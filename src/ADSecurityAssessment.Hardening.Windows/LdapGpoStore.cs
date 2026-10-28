using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using ADSecurityAssessment.Hardening.Execution;
using ADSecurityAssessment.Hardening.Gpo;
using ADSecurityAssessment.Hardening.Policy;

namespace ADSecurityAssessment.Hardening.Windows;

/// <summary>
/// Cria/lê/remove GPOs sem RSAT: o GPC (objetos groupPolicyContainer em CN=Policies,CN=System) por LDAP e o GPT (pasta no SYSVOL) por SMB.
/// Tudo no PDC emulator (como o GPMC faz) para que LDAP e SYSVOL fiquem no MESMO servidor até a replicação.
/// Usa a identidade Windows do processo (Kerberos/Negotiate, com assinatura e criptografia LDAP). Nenhuma senha é lida ou guardada.
/// Ordem de criação: SYSVOL primeiro, GPC depois — se algo falhar no meio, nada fica "apontando para o nada".
/// NÃO existe aqui nenhuma escrita em gPLink (vínculo) nem em GPO pré-existente.
/// </summary>
public sealed class LdapGpoStore : IGpoStore, IDisposable
{
    private static readonly Regex GpLinkRx = new(@"\[LDAP://(?<dn>[^;\]]+);(?<opt>\d+)\]", RegexOptions.Compiled | RegexOptions.IgnoreCase, TimeSpan.FromSeconds(5));
    private readonly LdapConnection _ldap;
    private readonly IHardeningLog _log;
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    public DomainContextInfo Domain { get; }

    /// <param name="domainDnsName">null = domínio do usuário atual.</param>
    /// <param name="server">null = PDC emulator do domínio.</param>
    public LdapGpoStore(string? domainDnsName, string? server, IHardeningLog log)
    {
        _log = log;
        var host = server;
        if (string.IsNullOrWhiteSpace(host))
        {
            try
            {
                using var d = string.IsNullOrWhiteSpace(domainDnsName)
                    ? System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain()
                    : System.DirectoryServices.ActiveDirectory.Domain.GetDomain(new DirectoryContext(DirectoryContextType.Domain, domainDnsName));
                host = d.PdcRoleOwner.Name;
                _log.Info($"PDC emulator localizado: {host}");
            }
            catch (Exception ex) when (ex is ActiveDirectoryObjectNotFoundException or ActiveDirectoryOperationException or InvalidOperationException)
            {
                throw new InvalidOperationException("Não foi possível localizar o domínio/PDC. Esta máquina precisa ser membro do domínio (ou informe o controlador de domínio). Detalhe: " + ex.Message, ex);
            }
        }

        _ldap = new LdapConnection(new LdapDirectoryIdentifier(host!, 389)) { AuthType = AuthType.Negotiate, Timeout = Timeout };
        _ldap.SessionOptions.ProtocolVersion = 3;
        _ldap.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
        _ldap.SessionOptions.Signing = true;
        _ldap.SessionOptions.Sealing = true;
        _ldap.AutoBind = false;
        try { _ldap.Bind(); }
        catch (Exception ex) { _ldap.Dispose(); throw new InvalidOperationException($"Falha ao autenticar em '{host}': {ex.Message}", ex); }

        var root = Search("", "(objectClass=*)", SearchScope.Base, "defaultNamingContext", "configurationNamingContext", "dnsHostName").FirstOrDefault()
                   ?? throw new InvalidOperationException("RootDSE vazio.");
        var domainDn = Str(root, "defaultNamingContext") ?? throw new InvalidOperationException("defaultNamingContext ausente.");
        var configDn = Str(root, "configurationNamingContext") ?? "";
        Domain = new DomainContextInfo(DnToDns(domainDn), domainDn, host!, configDn);
        _log.Info($"Conectado a {host} · domínio {Domain.DnsName}");
    }

    public void Dispose() => _ldap.Dispose();

    // ------------------------------------------------------------------ leitura
    public IReadOnlyList<GpoInfo> ListGpos()
    {
        var list = new List<GpoInfo>();
        foreach (var e in Search($"CN=Policies,CN=System,{Domain.DistinguishedName}", "(objectClass=groupPolicyContainer)", SearchScope.OneLevel, "displayName", "name"))
        {
            var name = Str(e, "name");
            if (name is null || !Guid.TryParse(name.Trim('{', '}'), out var id)) continue;
            list.Add(new GpoInfo(id, Str(e, "displayName") ?? name, e.DistinguishedName));
        }
        return list;
    }

    public IReadOnlyList<GpoLink> FindLinks(Guid id)
    {
        var token = id.ToString().ToUpperInvariant();
        var links = new List<GpoLink>();
        var bases = new List<string> { Domain.DistinguishedName };
        if (!string.IsNullOrEmpty(Domain.ConfigurationDn)) bases.Add($"CN=Sites,{Domain.ConfigurationDn}");
        foreach (var b in bases)
            foreach (var e in Search(b, $"(gPLink=*{token}*)", SearchScope.Subtree, "gPLink"))
            {
                var value = Str(e, "gPLink") ?? "";
                foreach (Match m in GpLinkRx.Matches(value))
                {
                    if (m.Groups["dn"].Value.IndexOf(token, StringComparison.OrdinalIgnoreCase) < 0) continue;
                    var opt = int.Parse(m.Groups["opt"].Value, CultureInfo.InvariantCulture);
                    links.Add(new GpoLink(e.DistinguishedName, (opt & 1) == 0, (opt & 2) != 0));
                }
            }
        return links;
    }

    public DomainPasswordPolicy ReadPasswordPolicy()
    {
        var e = Search(Domain.DistinguishedName, "(objectClass=domainDNS)", SearchScope.Base,
            "minPwdLength", "pwdProperties", "minPwdAge", "pwdHistoryLength", "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow").FirstOrDefault()
            ?? throw new InvalidOperationException("Não foi possível ler o objeto do domínio.");
        return new DomainPasswordPolicy(
            (int)Num(e, "minPwdLength"), (int)Num(e, "pwdProperties"), IntervalToDays(Num(e, "minPwdAge")), (int)Num(e, "pwdHistoryLength"),
            (int)Num(e, "lockoutThreshold"), IntervalToMinutes(Num(e, "lockoutDuration")), IntervalToMinutes(Num(e, "lockOutObservationWindow")));
    }

    public IReadOnlyList<PsoInfo> ListPsos()
    {
        try
        {
            return Search($"CN=Password Settings Container,CN=System,{Domain.DistinguishedName}", "(objectClass=msDS-PasswordSettings)", SearchScope.OneLevel,
                    "cn", "msDS-PasswordSettingsPrecedence", "msDS-MinimumPasswordLength", "msDS-LockoutThreshold")
                .Select(e => new PsoInfo(Str(e, "cn") ?? e.DistinguishedName, (int)Num(e, "msDS-PasswordSettingsPrecedence"), (int)Num(e, "msDS-MinimumPasswordLength"), (int)Num(e, "msDS-LockoutThreshold")))
                .ToList();
        }
        catch (DirectoryOperationException) { return Array.Empty<PsoInfo>(); }   // sem permissão para ler o container de PSOs
    }

    // ------------------------------------------------------------------ criação
    public CreatedGpo Create(GpoBundle bundle)
    {
        var id = Guid.NewGuid();
        var token = "{" + id.ToString().ToUpperInvariant() + "}";
        var gpcDn = $"CN={token},CN=Policies,CN=System,{Domain.DistinguishedName}";
        var dns = Domain.DnsName;
        var writePath = $@"\\{Domain.Server}\SYSVOL\{dns}\Policies\{token}";
        var attributePath = $@"\\{dns}\SysVol\{dns}\Policies\{token}";

        var gptWritten = false;
        var gpcWritten = false;
        try
        {
            WriteSysvol(writePath, bundle);
            gptWritten = true;

            Send(new AddRequest(gpcDn,
                new DirectoryAttribute("objectClass", "groupPolicyContainer"),
                new DirectoryAttribute("displayName", bundle.DisplayName),
                new DirectoryAttribute("gPCFileSysPath", attributePath),
                new DirectoryAttribute("flags", "0"),
                new DirectoryAttribute("versionNumber", bundle.VersionNumber.ToString(CultureInfo.InvariantCulture)),
                new DirectoryAttribute("gPCFunctionalityVersion", "2"),
                new DirectoryAttribute("gPCMachineExtensionNames", bundle.MachineExtensionNames)));
            gpcWritten = true;
            Send(new AddRequest($"CN=Machine,{gpcDn}", new DirectoryAttribute("objectClass", "container")));
            Send(new AddRequest($"CN=User,{gpcDn}", new DirectoryAttribute("objectClass", "container")));
        }
        catch
        {
            // Desfaz o que foi gravado desta GPO para não deixar lixo no domínio.
            try { if (gpcWritten) Send(TreeDelete(gpcDn)); } catch (Exception ex) { _log.Error($"Limpeza do GPC falhou: {ex.Message}"); }
            try { if (gptWritten || Directory.Exists(writePath)) Directory.Delete(writePath, true); } catch (Exception ex) { _log.Error($"Limpeza do SYSVOL falhou: {ex.Message}"); }
            throw;
        }
        return new CreatedGpo(id, bundle.DisplayName, gpcDn, writePath);
    }

    private static void WriteSysvol(string root, GpoBundle bundle)
    {
        if (Directory.Exists(root)) throw new IOException($"A pasta já existe no SYSVOL: {root}");
        Directory.CreateDirectory(root);
        foreach (var folder in bundle.Folders) Directory.CreateDirectory(Path.Combine(root, folder));
        foreach (var file in bundle.Files)
        {
            var path = Path.Combine(root, file.RelativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllBytes(path, file.Content);
        }
    }

    // ------------------------------------------------------------------ conferência
    public GpoVerification Verify(GpoBundle bundle, CreatedGpo created)
    {
        var issues = new List<string>();
        var notes = new List<string>();

        var gpc = Search(created.DistinguishedName, "(objectClass=*)", SearchScope.Base,
            new[] { "displayName", "versionNumber", "gPCMachineExtensionNames", "gPCFileSysPath", "nTSecurityDescriptor" }, new SecurityDescriptorFlagControl(SecurityMasks.Dacl)).FirstOrDefault();
        if (gpc is null) { issues.Add("O objeto GPC não foi encontrado após a criação."); return new GpoVerification(false, issues, notes); }

        if (!string.Equals(Str(gpc, "displayName"), bundle.DisplayName, StringComparison.Ordinal)) issues.Add("displayName divergente.");
        if (Str(gpc, "versionNumber") != bundle.VersionNumber.ToString(CultureInfo.InvariantCulture)) issues.Add("versionNumber do GPC diferente do planejado.");
        if (!string.Equals(Str(gpc, "gPCMachineExtensionNames"), bundle.MachineExtensionNames, StringComparison.Ordinal)) issues.Add("gPCMachineExtensionNames divergente.");

        foreach (var child in new[] { "Machine", "User" })
            if (!Search($"CN={child},{created.DistinguishedName}", "(objectClass=container)", SearchScope.Base, "cn").Any()) issues.Add($"Container CN={child} ausente no GPC.");

        foreach (var f in bundle.Files)
        {
            var path = Path.Combine(created.SysvolPath, f.RelativePath);
            if (!File.Exists(path)) { issues.Add($"Arquivo ausente no SYSVOL: {f.RelativePath}"); continue; }
            var actual = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
            if (!string.Equals(actual, f.Sha256, StringComparison.Ordinal)) issues.Add($"Conteúdo divergente no SYSVOL: {f.RelativePath}");
        }
        var ini = Path.Combine(created.SysvolPath, "GPT.INI");
        if (File.Exists(ini) && !File.ReadAllText(ini).Contains($"Version={bundle.VersionNumber}", StringComparison.Ordinal)) issues.Add("GPT.INI com versão diferente do GPC.");

        try
        {
            var sd = gpc.Attributes.Contains("nTSecurityDescriptor") ? gpc.Attributes["nTSecurityDescriptor"].GetValues(typeof(byte[])).Cast<byte[]>().FirstOrDefault() : null;
            if (sd is null) notes.Add("Não foi possível ler as permissões da GPO para conferir o direito 'Apply group policy' de Authenticated Users.");
            else if (!GpcSecurity.AuthenticatedUsersCanApply(sd))
                notes.Add("Authenticated Users NÃO tem o direito 'Apply group policy' nesta GPO: depois de vinculada ela não se aplicaria a ninguém. No GPMC, aba Delegação, adicione Authenticated Users com Read + Apply group policy.");
        }
        catch (InvalidDataException ex) { notes.Add("Permissões da GPO ilegíveis: " + ex.Message); }

        notes.Add($"Criada em {Domain.Server}; os demais controladores recebem a GPO pela replicação (AD e SYSVOL) antes de ela poder ser vinculada com efeito imediato em todos os sites.");
        return new GpoVerification(issues.Count == 0, issues, notes);
    }

    // ------------------------------------------------------------------ remoção
    public void Delete(CreatedGpo gpo)
    {
        Send(TreeDelete(gpo.DistinguishedName));
        if (!string.IsNullOrEmpty(gpo.SysvolPath) && Directory.Exists(gpo.SysvolPath)) Directory.Delete(gpo.SysvolPath, true);
    }

    private static DeleteRequest TreeDelete(string dn)
    {
        var req = new DeleteRequest(dn);
        req.Controls.Add(new TreeDeleteControl());
        return req;
    }

    // ------------------------------------------------------------------ utilidades LDAP
    private void Send(DirectoryRequest request)
    {
        try { _ldap.SendRequest(request, Timeout); }
        catch (DirectoryOperationException ex) { throw new InvalidOperationException($"O servidor recusou a operação ({ex.Response?.ResultCode}): {ex.Message}", ex); }
    }

    private IEnumerable<SearchResultEntry> Search(string baseDn, string filter, SearchScope scope, params string[] attributes) =>
        Search(baseDn, filter, scope, attributes, null);

    private IEnumerable<SearchResultEntry> Search(string baseDn, string filter, SearchScope scope, string[] attributes, DirectoryControl? extra)
    {
        byte[] cookie = Array.Empty<byte>();
        do
        {
            var req = new SearchRequest(baseDn, filter, scope, attributes) { TimeLimit = Timeout };
            var page = new PageResultRequestControl(500) { Cookie = cookie };
            req.Controls.Add(page);
            if (extra is not null) req.Controls.Add(extra);
            SearchResponse resp;
            try { resp = (SearchResponse)_ldap.SendRequest(req, Timeout); }
            catch (DirectoryOperationException ex) when (ex.Response?.ResultCode == ResultCode.NoSuchObject) { yield break; }
            foreach (SearchResultEntry e in resp.Entries) yield return e;
            cookie = resp.Controls.OfType<PageResultResponseControl>().FirstOrDefault()?.Cookie ?? Array.Empty<byte>();
        }
        while (cookie.Length > 0);
    }

    private static string? Str(SearchResultEntry e, string attribute) =>
        e.Attributes.Contains(attribute) && e.Attributes[attribute].Count > 0 ? e.Attributes[attribute][0]?.ToString() : null;

    private static long Num(SearchResultEntry e, string attribute) =>
        long.TryParse(Str(e, attribute), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : 0;

    /// <summary>Intervalos do AD são negativos em unidades de 100 ns; long.MinValue = "para sempre".</summary>
    private static int IntervalToMinutes(long v) => v == long.MinValue ? int.MaxValue : (int)Math.Min(int.MaxValue, Math.Abs(v) / 600_000_000L);
    private static int IntervalToDays(long v) => v == long.MinValue ? int.MaxValue : (int)Math.Min(int.MaxValue, Math.Abs(v) / 864_000_000_000L);

    private static string DnToDns(string dn) =>
        string.Join('.', dn.Split(',').Select(p => p.Trim()).Where(p => p.StartsWith("DC=", StringComparison.OrdinalIgnoreCase)).Select(p => p[3..]));
}
