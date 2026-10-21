using System.Globalization;
using ADSecurityAssessment.App.Infrastructure;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.App.ViewModels;

public sealed record SeverityCard(Severity Severity, string Name, int Count, RelayCommand Filter);

public sealed record CategoryCard(string Name, string ScoreText, string Rating, string StatusText, string CoverageText, double CoverageFraction,
    string Tone, string Counts, RelayCommand Filter);

public sealed record PriorityItem(string RuleId, string Title, string SeverityName, int Affected, RelayCommand Open);

/// <summary>Dashboard: Overall Security Score, contagem por severidade, score por categoria e principais prioridades.</summary>
public sealed class DashboardViewModel : ObservableObject
{
    public DashboardViewModel(AssessmentResult r, Action<Severity> filterSeverity, Action<string> filterCategory, Action<string> openFinding)
    {
        var o = r.Score.Overall;
        ScoreValue = o.SecurityScore ?? 0;
        ScoreText = o.SecurityScore is null ? "n/a" : o.SecurityScore.Value.ToString("0", CultureInfo.InvariantCulture);
        Rating = o.Rating ?? "Not scored";
        Tone = ToneFor(o.Rating);
        CoverageText = $"Assessment coverage {o.CoveragePercent.ToString("0", CultureInfo.InvariantCulture)}%";
        CoverageFraction = Math.Clamp(o.CoveragePercent / 100.0, 0, 1);
        RiskText = o.RiskScore is null ? "Risk n/a" : $"Risk {o.RiskScore.Value.ToString("0.0", CultureInfo.InvariantCulture)}%";
        IsProvisional = r.Score.IsProvisional;
        ProvisionalReason = r.Score.ProvisionalReason;
        CapNote = o.CapApplied ? "Score capped because Critical/High findings exist." : null;
        IsDemo = r.IsDemo;

        Severities = new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low }
            .Select(s => new SeverityCard(s, s.ToString(), r.Findings.Count(f => f.Severity == s), new RelayCommand(() => filterSeverity(s)))).ToArray();

        Categories = r.Score.Categories.Select(c => new CategoryCard(
            c.Category,
            c.Status == CategoryStatus.Scored ? c.SecurityScore!.Value.ToString("0", CultureInfo.InvariantCulture)
                : c.Status == CategoryStatus.NotApplicable ? "N/A" : "—",
            c.Rating ?? "",
            c.Status switch { CategoryStatus.Scored => "Scored", CategoryStatus.NotApplicable => "Not applicable", _ => "Not evaluated" },
            $"Coverage {c.CoveragePercent.ToString("0", CultureInfo.InvariantCulture)}%",
            Math.Clamp(c.CoveragePercent / 100.0, 0, 1),
            c.Status == CategoryStatus.Scored ? ToneFor(c.Rating) : "Neutral",
            $"{c.Critical} critical · {c.High} high · {c.Medium} medium · {c.Low} low",
            new RelayCommand(() => filterCategory(c.Category)))).ToArray();

        Priorities = r.Findings.OrderByDescending(f => f.Severity).ThenByDescending(f => f.AffectedObjects.Count).Take(8)
            .Select(f => new PriorityItem(f.RuleId, f.Title, f.Severity.ToString(), f.AffectedObjects.Count, new RelayCommand(() => openFinding(f.RuleId)))).ToArray();
        NoFindingsNote = r.Findings.Count == 0
            ? "No findings were raised by the rules that could be evaluated. See Coverage for what was not evaluated." : null;
    }

    public double ScoreValue { get; }
    public string ScoreText { get; }
    public string Rating { get; }
    public string Tone { get; }
    public string CoverageText { get; }
    public double CoverageFraction { get; }
    public string RiskText { get; }
    public bool IsProvisional { get; }
    public string? ProvisionalReason { get; }
    public string? CapNote { get; }
    public bool IsDemo { get; }
    public IReadOnlyList<SeverityCard> Severities { get; }
    public IReadOnlyList<CategoryCard> Categories { get; }
    public IReadOnlyList<PriorityItem> Priorities { get; }
    public string? NoFindingsNote { get; }

    /// <summary>Strong/Good → Ok; Fair → Warn; Weak/Poor → Bad (usado para escolher a cor).</summary>
    public static string ToneFor(string? rating) => rating switch
    {
        "Strong" or "Good" => "Ok",
        "Fair" => "Warn",
        "Weak" or "Poor" => "Bad",
        _ => "Neutral"
    };
}
