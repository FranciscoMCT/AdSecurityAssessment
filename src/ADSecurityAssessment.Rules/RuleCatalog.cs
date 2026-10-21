using System.Reflection;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Rules.Csharp;
using ADSecurityAssessment.Rules.Json;

namespace ADSecurityAssessment.Rules;

/// <summary>Reúne regras C# (lógica complexa) e regras JSON (declarativas). Regras inválidas são rejeitadas e relatadas.</summary>
public static class RuleCatalog
{
    public static IEnumerable<IAssessmentRule> CSharpRules(ReferenceCatalog refs) => new IAssessmentRule[]
    {
        new DomainControllerRedundancyRule(refs),
        new DomainControllerOsSupportRule(refs),
        new DomainControllerClockSkewRule(refs),
        new ReplicationTombstoneRule(refs),
        new ServerOsSupportRule(refs),
        new LapsCoverageRule(refs),
        new AdCsDetectionRule(refs),
    };

    public static RuleLoadResult Load(string? rulesDirectory, ReferenceCatalog refs, IAssessmentLog? log = null)
    {
        log ??= NullAssessmentLog.Instance;
        var result = new RuleLoadResult();
        foreach (var r in CSharpRules(refs)) result.Rules.Add(r);

        var files = !string.IsNullOrWhiteSpace(rulesDirectory) && Directory.Exists(rulesDirectory)
            ? Directory.GetFiles(rulesDirectory, "*.rules.json").OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToArray()
            : Array.Empty<string>();

        if (files.Length > 0)
        {
            result.Origin = $"disk: {rulesDirectory}";
            foreach (var f in files)
            {
                try { JsonRuleLoader.LoadJson(File.ReadAllText(f), Path.GetFileName(f), refs, result); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                { result.Errors.Add(new RuleLoadError(Path.GetFileName(f), "-", "Failed to read the file: " + ex.Message)); }
            }
        }
        else
        {
            result.Origin = "embedded";
            var asm = typeof(RuleCatalog).Assembly;
            foreach (var name in asm.GetManifestResourceNames().Where(n => n.StartsWith("rules/", StringComparison.Ordinal)).OrderBy(n => n))
            {
                using var s = asm.GetManifestResourceStream(name)!;
                using var rd = new StreamReader(s);
                JsonRuleLoader.LoadJson(rd.ReadToEnd(), name, refs, result);
            }
        }

        // RuleId único entre C# e JSON
        var dup = result.Rules.GroupBy(r => r.Metadata.RuleId, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
        foreach (var id in dup) { result.Errors.Add(new RuleLoadError("catalog", id, "Duplicate RuleId between C# and JSON rules; the first one was kept.")); }
        if (dup.Count > 0)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var unique = result.Rules.Where(r => seen.Add(r.Metadata.RuleId)).ToList();
            result.Rules.Clear(); result.Rules.AddRange(unique);
        }

        log.Info($"Rules loaded: {result.Rules.Count} ({result.Origin}); rejected: {result.Errors.Count}.");
        foreach (var e in result.Errors) log.Warn($"Rule rejected [{e.Source}/{e.RuleId}]: {e.Message}");
        return result;
    }
}
