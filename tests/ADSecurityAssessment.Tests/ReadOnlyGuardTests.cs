using System.Text.RegularExpressions;
using ADSecurityAssessment.Infrastructure.Ldap;

namespace ADSecurityAssessment.Tests;

/// <summary>
/// Guardas do princípio READ-ONLY / LOCAL-ONLY. Falham se alguém introduzir uma API de escrita no AD, de rede externa
/// ou a leitura de atributos secretos. São verificações estáticas sobre o código-fonte + o filtro de atributos do gateway.
///
/// O módulo de HARDENING (projetos ADSecurityAssessment.Hardening*) é a ÚNICA exceção controlada à regra "somente leitura" e vive
/// em projetos separados: o app de avaliação nunca o referencia. Dentro dele, a escrita é restrita a criar/remover o objeto GPC e a pasta
/// da GPO (AddRequest/DeleteRequest, somente em Hardening.Windows); vínculo (gPLink), modificação de objetos e qualquer outra escrita
/// continuam proibidos em TODO o repositório. Os testes abaixo fixam esse limite.
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

    private static bool IsHardening(string project) => project.StartsWith("ADSecurityAssessment.Hardening", StringComparison.Ordinal);
    private static bool IsAssessment(string project) => !IsHardening(project);

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
    public void AssessmentProjects_NeverCreateLdapWriteOperations()
    {
        AssertNone(@"\b(ModifyRequest|AddRequest|DeleteRequest|ModifyDNRequest|ExtendedRequest|CompareRequest|DsmlAuthRequest)\b", IsAssessment);
        AssertNone(@"\b(DirectoryAttributeModification|DirectoryAttributeOperation)\b", IsAssessment);
    }

    [Fact]
    public void NoProject_EverModifiesRenamesOrExtendsDirectoryObjects()
    {
        // Mesmo o módulo de hardening não pode modificar objetos existentes (nem vincular GPO): só criar o GPC novo e apagar o que criou.
        AssertNone(@"\b(ModifyRequest|ModifyDNRequest|ExtendedRequest|CompareRequest|DsmlAuthRequest|DirectoryAttributeModification|DirectoryAttributeOperation)\b");
    }

    [Fact]
    public void LdapAddAndDelete_ExistOnlyInTheHardeningWindowsStore()
    {
        var hits = Sources().Where(s => Regex.IsMatch(s.Text, @"\b(AddRequest|DeleteRequest|TreeDeleteControl)\b")).Select(s => s.File).ToList();
        Assert.NotEmpty(hits);
        Assert.All(hits, f => Assert.True(f.Replace('\\', '/') == "ADSecurityAssessment.Hardening.Windows/LdapGpoStore.cs", $"AddRequest/DeleteRequest fora do repositório de GPO: {f}"));
    }

    [Fact]
    public void GpoLinks_AreNeverWritten()
    {
        // gPLink só pode aparecer como atributo de LEITURA (busca) em LdapGpoStore; nunca como atributo de um AddRequest.
        AssertNone(@"new\s+DirectoryAttribute\s*\(\s*""gPLink""");
        AssertNone(@"""gPLink""\s*,\s*(?:link|value|new)");
        var users = Sources().Where(s => s.Text.Contains("gPLink", StringComparison.OrdinalIgnoreCase)).Select(s => s.Project + "/" + Path.GetFileName(s.File)).Distinct().ToList();
        Assert.All(users, u => Assert.True(u.StartsWith("ADSecurityAssessment.Hardening.Windows/", StringComparison.Ordinal) || u.StartsWith("ADSecurityAssessment.Collectors/", StringComparison.Ordinal) || u.StartsWith("ADSecurityAssessment.Rules/", StringComparison.Ordinal) || u.StartsWith("ADSecurityAssessment.Core/", StringComparison.Ordinal), $"gPLink citado em {u}"));
    }

    [Fact]
    public void OnlySearchRequestIsUsedForLdap_InTheAssessment()
    {
        var uses = Sources().Where(s => IsAssessment(s.Project) && Regex.IsMatch(s.Text, @"new\s+\w*Request\s*\(")).Select(s => (s.File, Matches: Regex.Matches(s.Text, @"new\s+(\w*Request)\s*\(").Select(m => m.Groups[1].Value).Distinct().ToList())).ToList();

        Assert.All(uses, u => Assert.True(u.Matches.All(m => m is "SearchRequest"), $"{u.File}: {string.Join(",", u.Matches)}"));
    }

    [Fact]
    public void HardeningModule_OnlyUsesSearchAddAndDeleteRequests_AndOnlyInTheWindowsAdapter()
    {
        var uses = Sources().Where(s => IsHardening(s.Project) && Regex.IsMatch(s.Text, @"new\s+\w*Request\s*\(")).Select(s => (s.Project, s.File, Matches: Regex.Matches(s.Text, @"new\s+(\w*Request)\s*\(").Select(m => m.Groups[1].Value).Distinct().ToList())).ToList();

        Assert.NotEmpty(uses);
        Assert.All(uses, u => Assert.Equal("ADSecurityAssessment.Hardening.Windows", u.Project));
        Assert.All(uses, u => Assert.True(u.Matches.All(m => m is "SearchRequest" or "AddRequest" or "DeleteRequest"), $"{u.File}: {string.Join(",", u.Matches)}"));
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
        AssertNone(@"\b(Process\.Start|ProcessStartInfo|PowerShell\.Create|Runspace|Invoke-Expression|cmd\.exe|powershell\.exe)\b", p => p != "ADSecurityAssessment.App" && p != "ADSecurityAssessment.HardeningApp");
    }

    [Fact]
    public void HardeningApp_NeverRunsShellsOrScripts()
    {
        // A única chamada de processo permitida é abrir o relatório/pasta no shell e consultar "auditpol /list" (somente leitura).
        AssertNone(@"\b(PowerShell\.Create|Runspace|Invoke-Expression|cmd\.exe|powershell\.exe|pwsh(\.exe)?|wscript|cscript|mshta|rundll32)\b", p => p == "ADSecurityAssessment.HardeningApp");
        var app = Sources(raw: true).Where(s => s.Project == "ADSecurityAssessment.HardeningApp" && Regex.IsMatch(s.Text, @"ProcessStartInfo\s*\(")).ToList();
        foreach (var s in app)
            foreach (Match m in Regex.Matches(s.Text, @"ProcessStartInfo\s*\(\s*""([^""]+)"""))
                Assert.Equal("auditpol.exe", m.Groups[1].Value);
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

    [Fact]
    public void HardeningManifest_NeverRequestsElevation()
    {
        var manifest = File.ReadAllText(Path.Combine(RepoLocator.Root(), "src", "ADSecurityAssessment.HardeningApp", "app.manifest"));

        Assert.Contains("asInvoker", manifest);
        Assert.DoesNotContain("requireAdministrator", manifest);
        Assert.DoesNotContain("highestAvailable", manifest);
    }

    private static IEnumerable<(string Project, string Text)> ProjectFiles()
    {
        var src = Path.Combine(RepoLocator.Root(), "src");
        foreach (var file in Directory.EnumerateFiles(src, "*.csproj", SearchOption.AllDirectories))
            yield return (Path.GetFileNameWithoutExtension(file), File.ReadAllText(file));
    }

    [Fact]
    public void AssessmentProjects_NeverReferenceTheHardeningModule()
    {
        var assessment = ProjectFiles().Where(p => IsAssessment(p.Project)).ToList();
        Assert.True(assessment.Count >= 6);
        Assert.All(assessment, p => Assert.DoesNotContain("Hardening", p.Text));
    }

    [Fact]
    public void HardeningCore_HasNoDependencies_AndNeverReferencesDirectoryServices()
    {
        var core = ProjectFiles().Single(p => p.Project == "ADSecurityAssessment.Hardening");
        Assert.DoesNotContain("PackageReference", core.Text);
        Assert.DoesNotContain("ProjectReference", core.Text);
        AssertNone(@"System\.DirectoryServices|System\.Net\.|System\.Diagnostics\.Process", p => p == "ADSecurityAssessment.Hardening");
    }

    [Fact]
    public void HardeningApp_ReferencesOnlyTheHardeningProjects()
    {
        var app = ProjectFiles().Single(p => p.Project == "ADSecurityAssessment.HardeningApp");
        var refs = Regex.Matches(app.Text, @"ProjectReference\s+Include=""[^""]*?([\w.]+)\.csproj""").Select(m => m.Groups[1].Value).OrderBy(x => x).ToArray();
        Assert.Equal(new[] { "ADSecurityAssessment.Hardening", "ADSecurityAssessment.Hardening.Windows" }, refs);
    }
}
