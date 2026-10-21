using System.Text.RegularExpressions;
using ADSecurityAssessment.Infrastructure.Ldap;

namespace ADSecurityAssessment.Tests;

/// <summary>
/// Guardas do princípio READ-ONLY / LOCAL-ONLY. Falham se alguém introduzir uma API de escrita no AD, de rede externa
/// ou a leitura de atributos secretos. São verificações estáticas sobre o código-fonte + o filtro de atributos do gateway.
/// </summary>
public class ReadOnlyGuardTests
{
    private static IEnumerable<(string Project, string File, string Text)> Sources(bool raw = false)
    {
        var src = Path.Combine(RepoLocator.Root(), "src");
        foreach (var file in Directory.EnumerateFiles(src, "*.cs", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(src, file);
            if (rel.Contains(Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar) || rel.Contains(Path.DirectorySeparatorChar + "bin" + Path.DirectorySeparatorChar)) continue;
            var text = File.ReadAllText(file);
            yield return (rel.Split(Path.DirectorySeparatorChar)[0], rel, raw ? text : StripComments(text));
        }
    }

    private static string StripComments(string code)
    {
        code = Regex.Replace(code, @"/\*.*?\*/", "", RegexOptions.Singleline);
        return Regex.Replace(code, @"//.*$", "", RegexOptions.Multiline);
    }

    private static void AssertNone(string pattern, Func<string, bool>? projectFilter = null, bool raw = false)
    {
        var rx = new Regex(pattern, RegexOptions.Compiled);
        var hits = Sources(raw).Where(s => projectFilter?.Invoke(s.Project) ?? true).Where(s => rx.IsMatch(s.Text)).Select(s => s.File).ToList();
        Assert.True(hits.Count == 0, $"Padrão proibido /{pattern}/ encontrado em: {string.Join(", ", hits)}");
    }

    [Fact]
    public void SourcesAreFound()
    {
        Assert.True(Sources().Count() > 50);
    }

    [Fact]
    public void NoLdapWriteOperations_AreEverCreated()
    {
        AssertNone(@"\b(ModifyRequest|AddRequest|DeleteRequest|ModifyDNRequest|ExtendedRequest|CompareRequest|DsmlAuthRequest)\b");
        AssertNone(@"\b(DirectoryAttributeModification|DirectoryAttributeOperation)\b");
    }

    [Fact]
    public void OnlySearchRequestIsUsedForLdap()
    {
        var uses = Sources().Where(s => Regex.IsMatch(s.Text, @"new\s+\w*Request\s*\(")).Select(s => (s.File, Matches: Regex.Matches(s.Text, @"new\s+(\w*Request)\s*\(").Select(m => m.Groups[1].Value).Distinct().ToList())).ToList();

        Assert.All(uses, u => Assert.True(u.Matches.All(m => m is "SearchRequest"), $"{u.File}: {string.Join(",", u.Matches)}"));
    }

    [Fact]
    public void NoSystemDirectoryServicesWriteApis()
    {
        AssertNone(@"\b(DirectoryEntry|DirectorySearcher|CommitChanges|SetPassword|ChangePassword|InvokeSet)\b");
        AssertNone(@"\b(SyncReplicaFromServer|SyncReplicaFromAllServers|TriggerSyncReplicaFromNeighbors|CreateLocalSideOfTrustRelationship|CreateTrustRelationship|DeleteLocalSideOfTrustRelationship|DeleteTrustRelationship|UpdateLocalSideOfTrustRelationship|UpdateTrustRelationship|RepairTrustRelationship|SetSidFilteringStatus|SetSelectiveAuthenticationStatus|TransferRoleOwnership|SeizeRoleOwnership|MoveToAnotherSite|DeleteDomainController)\b");
    }

    [Fact]
    public void NoGroupPolicyOrAccountWriteApis()
    {
        AssertNone(@"\b(SetGPLink|New-GPO|Set-GP[A-Za-z]+|Remove-GP[A-Za-z]+|Set-ADUser|Set-ADGroup|Add-ADGroupMember|Remove-ADGroupMember|Disable-ADAccount|Reset-ADAccountPassword|Set-ADAccountPassword)\b");
    }

    [Fact]
    public void NoNetworkEgress_ToExternalServices()
    {
        AssertNone(@"\b(HttpClient|WebClient|HttpWebRequest|WebRequest|SmtpClient|TcpClient|UdpClient|ClientWebSocket|FtpWebRequest)\b");
        AssertNone(@"https?://(?!learn\.microsoft\.com|schemas\.microsoft\.com|www\.w3\.org|schemas\.openxmlformats\.org|go\.microsoft\.com)[a-z0-9.-]+", raw: true);
    }

    [Fact]
    public void NoProcessOrShellExecution_OutsideTheUiLayer()
    {
        // A camada de coleta/regras/relatório nunca inicia processos nem PowerShell. Somente o App abre o Explorer/navegador a pedido do usuário.
        AssertNone(@"\b(Process\.Start|ProcessStartInfo|PowerShell\.Create|Runspace|Invoke-Expression|cmd\.exe|powershell\.exe)\b", p => p != "ADSecurityAssessment.App");
    }

    [Fact]
    public void NoAssemblyLoading_OrDynamicCodeExecution_AnywhereInTheProduct()
    {
        AssertNone(@"\b(Assembly\.Load(From|File)?|AssemblyLoadContext|CSharpScript|Microsoft\.CodeAnalysis\.CSharp\.Scripting|Expression\.Lambda|DynamicMethod|ILGenerator|Activator\.CreateInstance\s*\(\s*Type\.GetType)\b");
    }

    [Fact]
    public void PasswordIsNeverPersisted()
    {
        // Nada em src/ grava uma propriedade chamada Password em arquivo/log/config.
        AssertNone(@"\b(WriteAllText|AppendAllText|WriteAllLines|File\.Create|StreamWriter)\b[^;]*[Pp]assword");
        AssertNone(@"\blog\w*\.(Debug|Info|Warn|Error)\s*\([^;]*\.Password\b");
    }

    [Fact]
    public void CollectorsNeverRequestSecretAttributes()
    {
        foreach (var attribute in LdapGateway.ForbiddenAttributes)
        {
            var quoted = "\"" + attribute + "\"";
            var hits = Sources().Where(s => s.Project != "ADSecurityAssessment.Infrastructure" && s.Text.Contains(quoted, StringComparison.OrdinalIgnoreCase)).Select(s => s.File).ToList();
            Assert.True(hits.Count == 0, $"Atributo secreto {attribute} citado em: {string.Join(", ", hits)}");
        }
    }

    [Fact]
    public void Gateway_RefusesEveryForbiddenAttribute()
    {
        foreach (var attribute in LdapGateway.ForbiddenAttributes)
        {
            Assert.Throws<InvalidOperationException>(() => LdapGateway.EnsureAllowed(new[] { "sAMAccountName", attribute }));
            Assert.Throws<InvalidOperationException>(() => LdapGateway.EnsureAllowed(new[] { attribute + ";range=0-*" }));
        }
        Assert.Throws<InvalidOperationException>(() => LdapGateway.EnsureAllowed(new[] { "UNICODEPWD" }));   // case-insensitive
    }

    [Fact]
    public void Gateway_AllowsNormalAndLapsMetadataAttributes()
    {
        LdapGateway.EnsureAllowed(new[] { "sAMAccountName", "userAccountControl", "member;range=0-1499", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime", "pwdLastSet" });
    }

    [Fact]
    public void Manifest_NeverRequestsElevation()
    {
        var manifest = File.ReadAllText(Path.Combine(RepoLocator.Root(), "src", "ADSecurityAssessment.App", "app.manifest"));

        Assert.Contains("asInvoker", manifest);
        Assert.DoesNotContain("requireAdministrator", manifest);
        Assert.DoesNotContain("highestAvailable", manifest);
    }
}
