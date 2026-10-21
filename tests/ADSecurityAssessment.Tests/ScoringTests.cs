using ADSecurityAssessment.Core.Model;
using ADSecurityAssessment.Core.Pipeline;

namespace ADSecurityAssessment.Tests;

/// <summary>Risk Score separado de Assessment Coverage; categorias não avaliadas não podem inflar o score.</summary>
public class ScoringTests
{
    private static ScoreResult Score(params RuleEvaluation[] evals) => ScoringEngine.Calculate(evals, new ScoringSettings());

    [Fact]
    public void AllPassed_GivesFullScore_AndFullCoverage()
    {
        var r = Score(T.Result("AD-T-001", Severity.High, RuleOutcome.Passed), T.Result("AD-T-002", Severity.Low, RuleOutcome.Passed));

        Assert.Equal(CategoryStatus.Scored, r.Overall.Status);
        Assert.Equal(100.0, r.Overall.SecurityScore);
        Assert.Equal(0.0, r.Overall.RiskScore);
        Assert.Equal(100.0, r.Overall.CoveragePercent);
        Assert.Equal("Strong", r.Overall.Rating);
        Assert.False(r.IsProvisional);
    }

    [Fact]
    public void RiskPercent_IsFailedWeightOverEvaluatedWeight()
    {
        // pesos padrão: High=7, Medium=4  →  falhou 7 de 11  →  risco 63,6  →  score 36,4 (teto High=79 não altera).
        var r = Score(T.Result("AD-T-001", Severity.High, RuleOutcome.Failed), T.Result("AD-T-002", Severity.Medium, RuleOutcome.Passed));

        Assert.Equal(63.6, r.Overall.RiskScore);
        Assert.Equal(36.4, r.Overall.SecurityScore);
        Assert.Equal("Poor", r.Overall.Rating);
    }

    [Fact]
    public void CriticalFinding_CapsScore_EvenWhenMostRulesPass()
    {
        // 1 Critical falho (10) + 10 Medium aprovadas (40) → risco 20 → score 80, limitado a 59 pelo teto Critical.
        var evals = new List<RuleEvaluation> { T.Result("AD-T-000", Severity.Critical, RuleOutcome.Failed) };
        evals.AddRange(Enumerable.Range(1, 10).Select(i => T.Result($"AD-T-{i:000}", Severity.Medium, RuleOutcome.Passed)));

        var r = Score(evals.ToArray());

        Assert.Equal(59.0, r.Overall.SecurityScore);
        Assert.True(r.Overall.CapApplied);
        Assert.Equal(20.0, r.Overall.RiskScore);
    }

    [Fact]
    public void NotEvaluatedRules_DoNotChangeRisk_ButReduceCoverage()
    {
        var r = Score(
            T.Result("AD-T-001", Severity.High, RuleOutcome.Passed),
            T.Result("AD-T-002", Severity.High, RuleOutcome.NotEvaluated));

        Assert.Equal(0.0, r.Overall.RiskScore);
        Assert.Equal(50.0, r.Overall.CoveragePercent);
    }

    [Fact]
    public void LowCoverage_MarksScoreAsProvisional()
    {
        var r = Score(
            T.Result("AD-T-001", Severity.High, RuleOutcome.Passed),
            T.Result("AD-T-002", Severity.High, RuleOutcome.NotEvaluated),
            T.Result("AD-T-003", Severity.High, RuleOutcome.NotEvaluated));

        Assert.True(r.Overall.CoveragePercent < 50);
        Assert.True(r.IsProvisional);
        Assert.False(string.IsNullOrWhiteSpace(r.ProvisionalReason));
    }

    [Fact]
    public void EverythingNotEvaluated_NeverProducesAScore()
    {
        var r = Score(T.Result("AD-T-001", Severity.High, RuleOutcome.NotEvaluated), T.Result("AD-T-002", Severity.Low, RuleOutcome.NotEvaluated));

        Assert.Equal(CategoryStatus.NotEvaluated, r.Overall.Status);
        Assert.Null(r.Overall.SecurityScore);
        Assert.Null(r.Overall.RiskScore);
        Assert.Equal(0.0, r.Overall.CoveragePercent);
    }

    [Fact]
    public void NotApplicableRules_AreExcludedFromCoverageAndRisk()
    {
        var r = Score(T.Result("AD-T-001", Severity.High, RuleOutcome.Passed), T.Result("AD-T-002", Severity.Critical, RuleOutcome.NotApplicable));

        Assert.Equal(100.0, r.Overall.CoveragePercent);
        Assert.Equal(100.0, r.Overall.SecurityScore);
        Assert.Equal(1, r.Overall.NotApplicable);
    }

    [Fact]
    public void CategoryWithoutRules_IsNotApplicable_AndNeverScoredAsPerfect()
    {
        var r = Score(T.Result("AD-T-001", Severity.High, RuleOutcome.Passed, Categories.Identity));

        var adcs = r.Categories.Single(c => c.Category == Categories.AdCs);
        Assert.Equal(CategoryStatus.NotApplicable, adcs.Status);
        Assert.Null(adcs.SecurityScore);
    }

    [Fact]
    public void UnevaluatedCategory_DoesNotInflateOverallScore()
    {
        // Identity: 1 falha High, 1 aprovada High → score 50. Privileged: tudo Not Evaluated (não pode "puxar" o geral para 100).
        var r = Score(
            T.Result("AD-T-001", Severity.High, RuleOutcome.Failed, Categories.Identity),
            T.Result("AD-T-002", Severity.High, RuleOutcome.Passed, Categories.Identity),
            T.Result("AD-T-003", Severity.High, RuleOutcome.NotEvaluated, Categories.Privileged),
            T.Result("AD-T-004", Severity.High, RuleOutcome.NotEvaluated, Categories.Privileged));

        Assert.Equal(50.0, r.Overall.SecurityScore);
        Assert.Equal(CategoryStatus.NotEvaluated, r.Categories.Single(c => c.Category == Categories.Privileged).Status);
        Assert.Equal(50.0, r.Categories.Single(c => c.Category == Categories.Identity).SecurityScore);
    }

    [Fact]
    public void Weights_AreConfigurable()
    {
        var evals = new[] { T.Result("AD-T-001", Severity.High, RuleOutcome.Failed), T.Result("AD-T-002", Severity.Medium, RuleOutcome.Passed) };
        var custom = new ScoringSettings();
        custom.SeverityWeights["High"] = 1;
        custom.SeverityWeights["Medium"] = 1;

        var r = ScoringEngine.Calculate(evals, custom);

        Assert.Equal(50.0, r.Overall.RiskScore);
    }

    [Fact]
    public void FindingCounts_PerSeverity_AreReported()
    {
        var r = Score(
            T.Result("AD-T-001", Severity.Critical, RuleOutcome.Failed), T.Result("AD-T-002", Severity.High, RuleOutcome.Failed),
            T.Result("AD-T-003", Severity.High, RuleOutcome.Failed), T.Result("AD-T-004", Severity.Low, RuleOutcome.Failed));

        Assert.Equal(1, r.Overall.Critical);
        Assert.Equal(2, r.Overall.High);
        Assert.Equal(0, r.Overall.Medium);
        Assert.Equal(1, r.Overall.Low);
    }
}
