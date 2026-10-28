using System.Security.Cryptography;
using System.Text;
using ADSecurityAssessment.Hardening.Model;

namespace ADSecurityAssessment.Hardening.Gpo;

public sealed record GpoFile(string RelativePath, byte[] Content)
{
    public string Sha256 => Convert.ToHexString(SHA256.HashData(Content));
}

/// <summary>Tudo o que compõe uma GPO nova: arquivos do SYSVOL (GPT) e atributos do GPC.</summary>
public sealed class GpoBundle
{
    public required string DisplayName { get; init; }
    /// <summary>Caminhos relativos à pasta da GPO no SYSVOL, separador '\'.</summary>
    public required IReadOnlyList<GpoFile> Files { get; init; }
    /// <summary>Pastas vazias exigidas (Machine, User).</summary>
    public required IReadOnlyList<string> Folders { get; init; }
    /// <summary>Valor de gPCMachineExtensionNames (pares de GUID CSE ordenados).</summary>
    public required string MachineExtensionNames { get; init; }
    /// <summary>versionNumber do GPC e Version do GPT.INI (16 bits altos = usuário; baixos = computador).</summary>
    public required int VersionNumber { get; init; }
    public required int RegistryValueCount { get; init; }
    public required int SecurityOptionCount { get; init; }
    public required int AuditSubcategoryCount { get; init; }

    public GpoFile? Find(string relativePath) => Files.FirstOrDefault(f => string.Equals(f.RelativePath, relativePath, StringComparison.OrdinalIgnoreCase));
}

public static class GpoBundleBuilder
{
    public const string RegistryPolPath = @"Machine\Registry.pol";
    public const string SecurityTemplatePath = @"Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf";
    public const string AuditCsvPath = @"Machine\Microsoft\Windows NT\Audit\audit.csv";
    public const string GptIniPath = "GPT.INI";

    // Pares {CSE}{ferramenta} documentados para Computer Configuration.
    public const string RegistryCse = "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]";
    public const string SecurityCse = "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]";
    public const string AuditCse = "[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]";

    public static GpoBundle Build(string displayName, IReadOnlyList<ResolvedEntry> entries)
    {
        var pol = entries.OfType<PolEntry>().ToList();
        var tmpl = entries.OfType<TemplateEntry>().ToList();
        var aud = entries.OfType<AuditEntry>().ToList();
        if (pol.Count + tmpl.Count + aud.Count == 0) throw new InvalidOperationException("A GPO não tem nenhuma configuração.");

        var files = new List<GpoFile>();
        var cses = new List<(string Guid, string Pair)>();
        if (pol.Count > 0) { files.Add(new GpoFile(RegistryPolPath, RegistryPol.Build(pol))); cses.Add(("{35378EAC-683F-11D2-A89A-00C04FBBCFA2}", RegistryCse)); }
        if (tmpl.Count > 0) { files.Add(new GpoFile(SecurityTemplatePath, SecurityTemplate.Build(tmpl))); cses.Add(("{827D319E-6EAC-11D2-A4EA-00C04F79F83A}", SecurityCse)); }
        if (aud.Count > 0) { files.Add(new GpoFile(AuditCsvPath, AuditPolicy.BuildCsv(aud))); cses.Add(("{F3CCC681-B74C-4060-9F26-CD84525DCA2A}", AuditCse)); }

        const int version = 1;
        files.Add(new GpoFile(GptIniPath, Encoding.ASCII.GetBytes($"[General]\r\nVersion={version}\r\n")));

        return new GpoBundle
        {
            DisplayName = displayName,
            Files = files,
            Folders = new[] { "Machine", "User" },
            MachineExtensionNames = string.Concat(cses.OrderBy(c => c.Guid, StringComparer.OrdinalIgnoreCase).Select(c => c.Pair)),
            VersionNumber = version,
            RegistryValueCount = pol.Count,
            SecurityOptionCount = tmpl.Count,
            AuditSubcategoryCount = aud.Select(a => a.SubcategoryKey).Distinct().Count()
        };
    }
}
