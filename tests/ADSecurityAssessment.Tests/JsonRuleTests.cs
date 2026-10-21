using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;
using ADSecurityAssessment.Core.Pipeline;
using ADSecurityAssessment.Rules;
using ADSecurityAssessment.Rules.Json;

namespace ADSecurityAssessment.Tests;

/// <summary>Regras JSON: esquema fechado, validação, referências oficiais e ausência total de execução de código.</summary>
public class JsonRuleTests
{
    private static readonly ReferenceCatalog Refs = ReferenceCatalog.LoadEmbedded();

    private const string ValidRule = """
    {
      "schemaVersion": 1,
      "rules": [ {
        "ruleId": "AD-TST-901",
        "title": "Enabled user with PasswordNeverExpires",
        "description": "d", "category": "Identity Security", "module": "Users and Groups", "severity": "Medium",
        "condition": "c", "risk": "r", "recommendation": "rec",
        "references": [ "uac-flags" ],
        "dataset": "users",
        "scope": { "field": "Enabled", "op": "eq", "value": true },
        "where": { "field": "PasswordNeverExpires", "op": "eq", "value": true },
        "affected": { "name": "SamAccountName", "kind": "User", "domain": "Domain", "dn": "DistinguishedName" },
        "evidence": [ { "property": "UserAccountControl", "format": "hex", "expected": "bit not set" } ]
      } ]
    }
    """;

    private static RuleLoadResult Load(string json)
    {
        var result = new RuleLoadResult();
        JsonRuleLoader.LoadJson(json, "test.rules.json", Refs, result);
        return result;
    }

    [Fact]
    public void ValidRule_Loads()
    {
        var r = Load(ValidRule);

        Assert.Empty(r.Errors);
        var rule = Assert.Single(r.Rules);
        Assert.Equal("AD-TST-901", rule.Metadata.RuleId);
        Assert.Equal(Severity.Medium, rule.Metadata.Severity);
        Assert.NotEmpty(rule.Metadata.References);
    }

    [Fact]
    public void ValidRule_EvaluatesAgainstSnapshot_WithEvidence()
    {
        var rule = Load(ValidRule).Rules.Single();
        var snapshot = new SnapshotBuilder();
        snapshot.Users.Add(new UserRecord { Domain = "corp.test", SamAccountName = "svc-old", UserAccountControl = 0x10200 });   // NORMAL + DONT_EXPIRE
        snapshot.Users.Add(new UserRecord { Domain = "corp.test", SamAccountName = "alice", UserAccountControl = 0x200 });
        snapshot.Users.Add(new UserRecord { Domain = "corp.test", SamAccountName = "off", UserAccountControl = 0x10202 });         // desabilitado → fora do escopo
        snapshot.SetState(DatasetState.Complete("users", "UserCollector"));

        var ev = new RuleEngine().Run(new[] { rule }, T.Context(snapshot.Build(T.Now))).Single();

        Assert.Equal(RuleOutcome.Failed, ev.Outcome);
        Assert.Equal(2, ev.ObjectsEvaluated);
        var affected = Assert.Single(ev.Finding!.AffectedObjects);
        Assert.Equal("svc-old", affected.Name);
        var evidence = Assert.Single(ev.Finding.Evidence);
        Assert.Equal("svc-old", evidence.ObjectName);
        Assert.Contains("10200", evidence.Value, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidRule_WithoutCollectedData_IsNotEvaluated()
    {
        var rule = Load(ValidRule).Rules.Single();

        var ev = new RuleEngine().Run(new[] { rule }, T.Context(T.Snapshot())).Single();

        Assert.Equal(RuleOutcome.NotEvaluated, ev.Outcome);
    }

    [Theory]
    [InlineData("\"script\": \"Process.Start('calc')\",")]
    [InlineData("\"code\": \"System.IO.File.Delete(x)\",")]
    [InlineData("\"exec\": \"powershell -c whoami\",")]
    public void UnknownFields_ThatCouldCarryCode_RejectTheFile_AndNothingRuns(string injected)
    {
        var json = ValidRule.Replace("\"ruleId\": \"AD-TST-901\",", "\"ruleId\": \"AD-TST-901\", " + injected);

        var r = Load(json);

        Assert.Empty(r.Rules);
        Assert.NotEmpty(r.Errors);
    }

    [Fact]
    public void UnsupportedOperator_IsRejected()
    {
        var json = ValidRule.Replace("\"op\": \"eq\", \"value\": true }", "\"op\": \"exec\", \"value\": true }");

        var r = Load(json);

        Assert.Empty(r.Rules);
        Assert.Contains(r.Errors, e => e.Message.Contains("exec", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void UnknownField_InCondition_IsRejected()
    {
        var r = Load(ValidRule.Replace("\"PasswordNeverExpires\"", "\"NoSuchProperty\""));

        Assert.Empty(r.Rules);
        Assert.NotEmpty(r.Errors);
    }

    [Fact]
    public void UnknownDataset_IsRejected()
    {
        var r = Load(ValidRule.Replace("\"dataset\": \"users\"", "\"dataset\": \"secrets\""));

        Assert.Empty(r.Rules);
        Assert.Contains(r.Errors, e => e.Message.Contains("secrets"));
    }

    [Fact]
    public void ReferenceOutsideOfficialCatalog_IsRejected()
    {
        var r = Load(ValidRule.Replace("\"uac-flags\"", "\"https://evil.example/blog\""));

        Assert.Empty(r.Rules);
        Assert.NotEmpty(r.Errors);
    }

    [Fact]
    public void RuleWithoutReferences_IsRejected()
    {
        var r = Load(ValidRule.Replace("[ \"uac-flags\" ]", "[ ]"));

        Assert.Empty(r.Rules);
    }

    [Theory]
    [InlineData("\"severity\": \"Medium\"", "\"severity\": \"Catastrophic\"")]
    [InlineData("\"category\": \"Identity Security\"", "\"category\": \"Made Up\"")]
    [InlineData("\"ruleId\": \"AD-TST-901\"", "\"ruleId\": \"bad id\"")]
    [InlineData("\"recommendation\": \"rec\"", "\"recommendation\": \"\"")]
    public void InvalidMetadata_IsRejected(string from, string to)
    {
        var r = Load(ValidRule.Replace(from, to));

        Assert.Empty(r.Rules);
        Assert.NotEmpty(r.Errors);
    }

    [Fact]
    public void MalformedJson_IsReported_NotThrown()
    {
        var r = Load("{ this is not json");

        Assert.Empty(r.Rules);
        Assert.Single(r.Errors);
    }

    [Fact]
    public void PlaceholderRule_OnDatasetWithCollector_IsRejected()
    {
        var r = Load(ValidRule.Replace("\"dataset\": \"users\",", "\"dataset\": \"users\", \"placeholder\": true,"));

        Assert.Empty(r.Rules);
    }

    [Fact]
    public void DuplicateRuleId_IsRejected()
    {
        var result = new RuleLoadResult();
        JsonRuleLoader.LoadJson(ValidRule, "a.rules.json", Refs, result);
        JsonRuleLoader.LoadJson(ValidRule, "b.rules.json", Refs, result);

        Assert.Single(result.Rules);
        Assert.Single(result.Errors);
    }
}

/// <summary>O catálogo que acompanha o produto (7 regras C# + regras JSON embutidas).</summary>
public class ShippedRuleCatalogTests
{
    private static readonly ReferenceCatalog Refs = ReferenceCatalog.LoadEmbedded();
    private static readonly RuleLoadResult Loaded = RuleCatalog.Load(null, Refs);

    [Fact]
    public void AllShippedRules_Load_WithoutRejections()
    {
        Assert.Empty(Loaded.Errors);
        Assert.True(Loaded.Rules.Count >= 20, $"MVP exige 20–30+ regras; carregadas: {Loaded.Rules.Count}");
    }

    [Fact]
    public void RuleIds_AreUnique_AndWellFormed()
    {
        var ids = Loaded.Rules.Select(r => r.Metadata.RuleId).ToList();

        Assert.Equal(ids.Count, ids.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.All(ids, id => Assert.Matches(@"^AD-[A-Z]{2,8}-\d{3}$", id));
    }

    [Fact]
    public void EveryRule_HasAllRequiredFields()
    {
        foreach (var rule in Loaded.Rules)
        {
            var m = rule.Metadata;
            Assert.False(string.IsNullOrWhiteSpace(m.Title), m.RuleId + " title");
            Assert.False(string.IsNullOrWhiteSpace(m.Description), m.RuleId + " description");
            Assert.False(string.IsNullOrWhiteSpace(m.Condition), m.RuleId + " condition");
            Assert.False(string.IsNullOrWhiteSpace(m.Risk), m.RuleId + " risk");
            Assert.False(string.IsNullOrWhiteSpace(m.Recommendation), m.RuleId + " recommendation");
            Assert.Contains(m.Category, Categories.All);
            Assert.Contains(m.Module, Modules.All);
            Assert.True(Enum.IsDefined(m.Severity), m.RuleId + " severity");
            Assert.NotEmpty(m.RequiredDatasets);
        }
    }

    [Fact]
    public void EveryRule_ReferencesOnlyOfficialMicrosoftLearnUrls()
    {
        foreach (var rule in Loaded.Rules)
        {
            Assert.NotEmpty(rule.Metadata.References);
            foreach (var reference in rule.Metadata.References)
                Assert.True(ReferenceCatalog.IsOfficialUrl(reference.Url), $"{rule.Metadata.RuleId}: {reference.Url}");
        }
    }

    [Fact]
    public void ReferenceCatalog_ContainsOnlyOfficialHttpsLearnUrls_AndRejectsOthers()
    {
        Assert.Empty(Refs.Rejected);
        Assert.All(Refs.Keys, k => Assert.True(ReferenceCatalog.IsOfficialUrl(Refs.Resolve(k).Url), k));
        Assert.False(ReferenceCatalog.IsOfficialUrl("http://learn.microsoft.com/x"));
        Assert.False(ReferenceCatalog.IsOfficialUrl("https://learn.microsoft.com.evil.example/x"));
        Assert.False(ReferenceCatalog.IsOfficialUrl("https://example.com/learn.microsoft.com"));
    }

    [Fact]
    public void RulesWithoutCollector_AreNotEvaluated_OnAnEmptySnapshot()
    {
        // Sem nenhum dado coletado, nenhuma regra pode falhar nem passar: tudo é Not Evaluated.
        var results = new RuleEngine().Run(Loaded.Rules, T.Context(T.Snapshot()));

        Assert.Equal(Loaded.Rules.Count, results.Count);
        Assert.All(results, r => Assert.Equal(RuleOutcome.NotEvaluated, r.Outcome));
        Assert.All(results, r => Assert.Null(r.Finding));
    }

    [Fact]
    public void EveryShippedRule_AppearsInRulesFolderOrCSharp_AndShipsExternallyEditableJson()
    {
        // As regras JSON embutidas e as da pasta rules/ devem ser as mesmas (a pasta é o que o usuário edita).
        var root = RepoLocator.Root();
        var onDisk = RuleCatalog.Load(Path.Combine(root, "rules"), Refs);

        Assert.Empty(onDisk.Errors);
        Assert.Equal(
            Loaded.Rules.Select(r => r.Metadata.RuleId).OrderBy(x => x, StringComparer.Ordinal),
            onDisk.Rules.Select(r => r.Metadata.RuleId).OrderBy(x => x, StringComparer.Ordinal));
    }
}

internal static class RepoLocator
{
    public static string Root()
    {
        var fromEnvironment = Environment.GetEnvironmentVariable("ADS_REPO_ROOT");
        if (!string.IsNullOrWhiteSpace(fromEnvironment)) return fromEnvironment;
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "ADSecurityAssessment.sln"))) dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Raiz do repositório (ADSecurityAssessment.sln) não encontrada a partir de " + AppContext.BaseDirectory);
    }
}
