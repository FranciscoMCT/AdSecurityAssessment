using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Core.Pipeline;

/// <summary>
/// Risk Score (resultado das regras avaliadas) separado de Assessment Coverage (quanto foi possível avaliar).
/// Fórmula (docs/SCORING.md): Risk% = Σ peso(regras Failed) / Σ peso(regras Passed+Failed) × 100; Security = 100 − Risk%,
/// limitado pelos tetos configurados quando há findings Critical/High. Regras Not Evaluated NÃO entram no denominador do risco
/// (não podem "melhorar" nem "piorar" o resultado), mas reduzem a Coverage e podem tornar o score PROVISÓRIO.
/// </summary>
public static class ScoringEngine
{
    public static ScoreResult Calculate(IReadOnlyList<RuleEvaluation> evaluations, ScoringSettings cfg)
    {
        var overall = Compute("Overall", evaluations, cfg);
        var cats = Categories.All.Select(c => Compute(c, evaluations.Where(e => e.Rule.Category.Equals(c, StringComparison.OrdinalIgnoreCase)).ToList(), cfg)).ToList();

        var provisional = overall.Status == CategoryStatus.Scored && overall.CoveragePercent < cfg.MinimumCoveragePercent;
        string? reason = provisional
            ? $"Assessment Coverage of {overall.CoveragePercent:0}% is below the configured minimum ({cfg.MinimumCoveragePercent:0}%): part of the rules could not be evaluated, so the score is provisional."
            : null;

        return new ScoreResult
        {
            Overall = overall,
            Categories = cats,
            IsProvisional = provisional,
            ProvisionalReason = reason,
            Configuration = cfg,
            MethodSummary = "Risk% = Σ weight(Failed) / Σ weight(Passed+Failed). Security Score = 100 − Risk%, with per-severity caps. " +
                            "Coverage = Σ weight(evaluated) / Σ weight(applicable). Not Evaluated and Not Applicable rules do not enter Risk%."
        };
    }

    private static CategoryScore Compute(string name, IReadOnlyList<RuleEvaluation> evs, ScoringSettings cfg)
    {
        double W(RuleEvaluation e) => cfg.WeightFor(e.Rule.Severity);

        var applicable = evs.Where(e => e.Outcome != RuleOutcome.NotApplicable).ToList();
        var evaluated = applicable.Where(e => e.Outcome is RuleOutcome.Passed or RuleOutcome.Failed).ToList();
        var failed = evaluated.Where(e => e.Outcome == RuleOutcome.Failed).ToList();

        var applicableWeight = applicable.Sum(W);
        var evaluatedWeight = evaluated.Sum(W);
        var failedWeight = failed.Sum(W);

        double coverage = applicableWeight > 0
            ? evaluatedWeight / applicableWeight * 100
            : applicable.Count > 0 ? evaluated.Count * 100.0 / applicable.Count : 0;

        CategoryStatus status;
        double? risk = null, score = null;
        bool capApplied = false;
        string? rating = null;

        if (applicable.Count == 0) status = CategoryStatus.NotApplicable;
        else if (evaluated.Count == 0) status = CategoryStatus.NotEvaluated;
        else
        {
            status = CategoryStatus.Scored;
            risk = evaluatedWeight > 0 ? failedWeight / evaluatedWeight * 100 : 0;
            score = 100 - risk;
            foreach (var sev in new[] { Severity.Critical, Severity.High })
            {
                if (cfg.ScoreCaps.TryGetValue(sev.ToString(), out var cap) && failed.Any(f => f.Rule.Severity == sev) && score > cap)
                { score = cap; capApplied = true; }
            }
            score = Math.Round(score.Value, 1);
            risk = Math.Round(risk.Value, 1);
            rating = cfg.RatingBands.OrderByDescending(b => b.MinScore).FirstOrDefault(b => score >= b.MinScore)?.Label;
        }

        int Count(Severity s) => failed.Count(f => f.Rule.Severity == s);
        return new CategoryScore
        {
            Category = name, Status = status, SecurityScore = score, RiskScore = risk,
            CoveragePercent = Math.Round(coverage, 1), Rating = rating, CapApplied = capApplied,
            RulesTotal = evs.Count,
            Passed = evs.Count(e => e.Outcome == RuleOutcome.Passed),
            Failed = failed.Count,
            NotEvaluated = evs.Count(e => e.Outcome == RuleOutcome.NotEvaluated),
            NotApplicable = evs.Count(e => e.Outcome == RuleOutcome.NotApplicable),
            Critical = Count(Severity.Critical), High = Count(Severity.High), Medium = Count(Severity.Medium),
            Low = Count(Severity.Low), Informational = Count(Severity.Informational)
        };
    }
}
