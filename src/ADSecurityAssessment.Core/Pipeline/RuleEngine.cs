using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Core.Pipeline;

/// <summary>
/// Executa as regras de forma isolada e aplica as salvaguardas do projeto:
/// dataset ausente → Not Evaluated; dataset parcial sem achados → Not Evaluated (nunca "Passed");
/// finding sem evidência → descartado; exceção em regra → Not Evaluated.
/// </summary>
public sealed class RuleEngine
{
    private readonly IAssessmentLog _log;
    public RuleEngine(IAssessmentLog? log = null) { _log = log ?? NullAssessmentLog.Instance; }

    public IReadOnlyList<RuleEvaluation> Run(IEnumerable<IAssessmentRule> rules, RuleContext context)
    {
        var results = new List<RuleEvaluation>();
        foreach (var rule in rules)
        {
            RuleEvaluation ev;
            try { ev = RunOne(rule, context); }
            catch (Exception ex)
            {
                _log.Error($"Rule {rule.Metadata.RuleId} failed to execute.", ex);
                ev = RuleEvaluation.NotEvaluated(rule.Metadata, $"Internal error while evaluating the rule: {ex.GetType().Name}: {ex.Message}");
            }
            results.Add(ev);
        }
        return results;
    }

    private RuleEvaluation RunOne(IAssessmentRule rule, RuleContext ctx)
    {
        var meta = rule.Metadata;

        var missing = new List<string>();
        var partial = new List<DatasetState>();
        foreach (var ds in meta.RequiredDatasets)
        {
            var st = ctx.Snapshot.GetState(ds);
            if (st.Coverage == DatasetCoverage.None) missing.Add($"'{ds}': {st.Reason}");
            else if (st.Coverage == DatasetCoverage.Partial) partial.Add(st);
        }
        if (missing.Count > 0)
            return RuleEvaluation.NotEvaluated(meta, "Data not collected — " + string.Join(" | ", missing));

        var ev = rule.Evaluate(ctx);

        if (ev.Outcome == RuleOutcome.Failed)
        {
            var finding = ev.Finding;
            if (finding is null || !HasValidEvidence(finding))
            {
                _log.Error($"Rule {meta.RuleId} produced a finding without technical evidence; discarded.");
                return RuleEvaluation.NotEvaluated(meta, "Finding discarded: technical evidence was not collected for every affected object.");
            }
            finding = Cap(finding, ctx.Settings.MaxAffectedObjectsPerFinding, out var total);
            if (partial.Count > 0)
            {
                var scope = string.Join("; ", partial.Select(p => $"{p.Name}: ok=[{string.Join(", ", p.ScopesCollected)}] falhou=[{string.Join(", ", p.ScopesFailed)}]"));
                finding = finding with { Notes = Join(finding.Notes, "Dataset was only partially collected — the result may be incomplete. " + scope) };
            }
            if (ctx.Snapshot.IsDemo) finding = finding with { IsDemo = true };
            return ev with { Finding = finding, ObjectsAffected = Math.Max(ev.ObjectsAffected, total) };
        }

        if (ev.Outcome == RuleOutcome.Passed)
        {
            if (partial.Count > 0)
                return RuleEvaluation.NotEvaluated(meta, "Partial data coverage — no deviation was found in what was collected, but compliance cannot be asserted. " +
                    string.Join("; ", partial.Select(p => $"{p.Name}: {p.Reason}")));
            if (ev.ObjectsEvaluated == 0)
                return RuleEvaluation.NotApplicable(meta, "No object in the scope of the rule was found.");
        }
        return ev;
    }

    private static string Join(string? a, string b) => string.IsNullOrWhiteSpace(a) ? b : a + " " + b;

    private static bool HasValidEvidence(Finding f)
    {
        if (f.Evidence.Count == 0 || f.AffectedObjects.Count == 0) return false;
        var names = new HashSet<string>(f.Evidence.Select(e => e.ObjectName), StringComparer.OrdinalIgnoreCase);
        return f.AffectedObjects.All(a => names.Contains(a.Name));
    }

    private static Finding Cap(Finding f, int max, out int total)
    {
        total = f.AffectedObjects.Count;
        if (max <= 0 || total <= max) return f;
        var keep = f.AffectedObjects.Take(max).ToArray();
        var keepNames = new HashSet<string>(keep.Select(a => a.Name), StringComparer.OrdinalIgnoreCase);
        var ev = f.Evidence.Where(e => keepNames.Contains(e.ObjectName)).ToArray();
        return f with
        {
            AffectedObjects = keep, Evidence = ev,
            Notes = Join(f.Notes, $"{total} objects are affected in total; listing the first {max} (configurable limit: MaxAffectedObjectsPerFinding).")
        };
    }
}
