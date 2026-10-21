using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Reporting;

/// <summary>Consultas reutilizadas pelos exportadores (ordenação e agrupamentos determinísticos).</summary>
internal static class ReportQueries
{
    public static IEnumerable<Finding> OrderedFindings(AssessmentResult r) =>
        r.Findings.OrderByDescending(f => f.Severity).ThenBy(f => f.Category, StringComparer.OrdinalIgnoreCase).ThenBy(f => f.RuleId, StringComparer.OrdinalIgnoreCase);

    public static IEnumerable<RuleEvaluation> NotEvaluated(AssessmentResult r) =>
        r.Evaluations.Where(e => e.Outcome == RuleOutcome.NotEvaluated).OrderBy(e => e.Rule.RuleId, StringComparer.OrdinalIgnoreCase);

    public static IEnumerable<RuleEvaluation> NotApplicable(AssessmentResult r) =>
        r.Evaluations.Where(e => e.Outcome == RuleOutcome.NotApplicable).OrderBy(e => e.Rule.RuleId, StringComparer.OrdinalIgnoreCase);

    public static int CountBySeverity(AssessmentResult r, Severity s) => r.Findings.Count(f => f.Severity == s);

    public static string FileStem(AssessmentResult r) =>
        $"{(r.IsDemo ? "DEMO_" : "")}ADSecurityAssessment_{r.Metadata.FinishedAt.ToLocalTime():yyyyMMdd_HHmmss}_{r.Metadata.AssessmentId}";
}
