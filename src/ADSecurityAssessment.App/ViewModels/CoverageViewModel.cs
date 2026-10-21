using System.Globalization;
using ADSecurityAssessment.App.Infrastructure;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.App.ViewModels;

public sealed record CoverageRow(string Category, string Status, int Passed, int Failed, int NotEvaluated, int NotApplicable, string Coverage, double Fraction);
public sealed record CollectorRow(string Name, string Status, int Objects, string Seconds, string Notes);
public sealed record DatasetRow(string Name, string Coverage, string Collector, string Reason);
public sealed record RuleStatusRow(string RuleId, string Title, string Outcome, string Reason);

/// <summary>Assessment Coverage: o que foi (e o que NÃO foi) avaliado, e por quê.</summary>
public sealed class CoverageViewModel : ObservableObject
{
    public CoverageViewModel(AssessmentResult r)
    {
        Categories = r.Score.Categories.Select(c => new CoverageRow(c.Category, c.Status.ToString(), c.Passed, c.Failed, c.NotEvaluated, c.NotApplicable,
            c.CoveragePercent.ToString("0", CultureInfo.InvariantCulture) + "%", Math.Clamp(c.CoveragePercent / 100.0, 0, 1))).ToArray();
        Collectors = r.CollectorRuns.Select(c => new CollectorRow(c.DisplayName, c.Status.ToString(), c.ObjectCount,
            c.Duration.TotalSeconds.ToString("0.0", CultureInfo.InvariantCulture), string.Join(" | ", c.Errors.Concat(c.Warnings).Take(3)))).ToArray();
        Datasets = r.Datasets.Select(d => new DatasetRow(d.Name, d.Coverage.ToString(), d.Collector, d.Reason ?? "")).ToArray();
        NotEvaluated = r.Evaluations.Where(e => e.Outcome is RuleOutcome.NotEvaluated or RuleOutcome.NotApplicable)
            .OrderBy(e => e.Outcome).ThenBy(e => e.Rule.RuleId, StringComparer.OrdinalIgnoreCase)
            .Select(e => new RuleStatusRow(e.Rule.RuleId, e.Rule.Title, e.Outcome == RuleOutcome.NotEvaluated ? "Not evaluated" : "Not applicable", e.Reason ?? "")).ToArray();
        Explanation = "Coverage is reported separately from risk. Rules that could not be evaluated are never treated as compliant and never improve the score.";
    }

    public string Explanation { get; }
    public IReadOnlyList<CoverageRow> Categories { get; }
    public IReadOnlyList<CollectorRow> Collectors { get; }
    public IReadOnlyList<DatasetRow> Datasets { get; }
    public IReadOnlyList<RuleStatusRow> NotEvaluated { get; }
}
