using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;
using ADSecurityAssessment.Core.Pipeline;

namespace ADSecurityAssessment.Tests;

/// <summary>
/// Garantias do Rule Engine: nunca há finding sem evidência, "Not Evaluated" quando o dado não foi coletado e
/// "Compliant/Passed" jamais é assumido quando a coleta foi parcial ou ausente.
/// </summary>
public class RuleEngineTests
{
    private static RuleEvaluation RunOne(IAssessmentRule rule, AssessmentSnapshot snapshot, AssessmentSettings? settings = null) =>
        new RuleEngine().Run(new[] { rule }, T.Context(snapshot, settings)).Single();

    [Fact]
    public void MissingDataset_IsNotEvaluated_AndRuleIsNotExecuted()
    {
        var executed = false;
        var rule = new FakeRule("AD-TST-001", Severity.High, new[] { "users" }, (m, _) => { executed = true; return RuleEvaluation.Passed(m, 5); });

        var ev = RunOne(rule, T.Snapshot());

        Assert.Equal(RuleOutcome.NotEvaluated, ev.Outcome);
        Assert.False(executed);
        Assert.Null(ev.Finding);
        Assert.Contains("users", ev.Reason);
    }

    [Fact]
    public void DatasetWithoutCollector_IsNotEvaluated()
    {
        // smb-signing-config é um dataset "planejado": não há collector, logo nada pode ser afirmado.
        var rule = new FakeRule("AD-TST-002", Severity.High, new[] { DatasetNames.SmbSigningConfig }, (m, _) => RuleEvaluation.Passed(m, 3));

        var ev = RunOne(rule, T.Snapshot());

        Assert.Equal(RuleOutcome.NotEvaluated, ev.Outcome);
    }

    [Fact]
    public void CompleteDataset_AndNoDeviation_IsPassed()
    {
        var rule = new FakeRule("AD-TST-003", Severity.Medium, new[] { "users" }, (m, _) => RuleEvaluation.Passed(m, 12));

        var ev = RunOne(rule, T.Snapshot(false, DatasetState.Complete("users", "UserCollector")));

        Assert.Equal(RuleOutcome.Passed, ev.Outcome);
        Assert.Equal(12, ev.ObjectsEvaluated);
    }

    [Fact]
    public void PartialDataset_WithNoDeviation_IsNotEvaluated_NeverPassed()
    {
        var rule = new FakeRule("AD-TST-004", Severity.High, new[] { "users" }, (m, _) => RuleEvaluation.Passed(m, 40));
        var partial = DatasetState.Partial("users", "UserCollector", "domain b unreachable", new[] { "a.test" }, new[] { "b.test" });

        var ev = RunOne(rule, T.Snapshot(false, partial));

        Assert.Equal(RuleOutcome.NotEvaluated, ev.Outcome);
        Assert.Contains("users", ev.Reason);
    }

    [Fact]
    public void PartialDataset_WithDeviation_KeepsFinding_AndAddsIncompleteNote()
    {
        var rule = new FakeRule("AD-TST-005", Severity.High, new[] { "users" }, (m, _) => T.Fail(m, "alice"));
        var partial = DatasetState.Partial("users", "UserCollector", "domain b unreachable", new[] { "a.test" }, new[] { "b.test" });

        var ev = RunOne(rule, T.Snapshot(false, partial));

        Assert.Equal(RuleOutcome.Failed, ev.Outcome);
        Assert.NotNull(ev.Finding);
        Assert.False(string.IsNullOrWhiteSpace(ev.Finding!.Notes));
        Assert.Contains("b.test", ev.Finding.Notes);
    }

    [Fact]
    public void PassedWithZeroObjectsEvaluated_IsNotApplicable_NotCompliant()
    {
        var rule = new FakeRule("AD-TST-006", Severity.Low, new[] { "users" }, (m, _) => RuleEvaluation.Passed(m, 0));

        var ev = RunOne(rule, T.Snapshot(false, DatasetState.Complete("users", "UserCollector")));

        Assert.Equal(RuleOutcome.NotApplicable, ev.Outcome);
    }

    [Fact]
    public void FindingWithoutEvidence_IsDiscarded()
    {
        var rule = new FakeRule("AD-TST-007", Severity.Critical, new[] { "users" },
            (m, _) => RuleEvaluation.Failed(m, new[] { T.Affected("alice") }, Array.Empty<EvidenceItem>(), 1));

        var ev = RunOne(rule, T.Snapshot(false, DatasetState.Complete("users", "UserCollector")));

        Assert.Equal(RuleOutcome.NotEvaluated, ev.Outcome);
        Assert.Null(ev.Finding);
    }

    [Fact]
    public void FindingWithEvidenceMissingForOneObject_IsDiscarded()
    {
        var rule = new FakeRule("AD-TST-008", Severity.High, new[] { "users" }, (m, _) =>
            RuleEvaluation.Failed(m, new[] { T.Affected("alice"), T.Affected("bob") }, new[] { T.Evidence("alice") }, 2));

        var ev = RunOne(rule, T.Snapshot(false, DatasetState.Complete("users", "UserCollector")));

        Assert.Equal(RuleOutcome.NotEvaluated, ev.Outcome);
        Assert.Null(ev.Finding);
    }

    [Fact]
    public void FindingWithNoAffectedObjects_IsDiscarded()
    {
        var rule = new FakeRule("AD-TST-009", Severity.High, new[] { "users" },
            (m, _) => RuleEvaluation.Failed(m, Array.Empty<AffectedObject>(), new[] { T.Evidence("alice") }, 1));

        var ev = RunOne(rule, T.Snapshot(false, DatasetState.Complete("users", "UserCollector")));

        Assert.Equal(RuleOutcome.NotEvaluated, ev.Outcome);
    }

    [Fact]
    public void RuleThatThrows_IsNotEvaluated_AndOtherRulesStillRun()
    {
        var bad = new FakeRule("AD-TST-010", Severity.High, new[] { "users" }, (_, _) => throw new InvalidOperationException("boom"));
        var good = new FakeRule("AD-TST-011", Severity.High, new[] { "users" }, (m, _) => T.Fail(m, "alice"));
        var snapshot = T.Snapshot(false, DatasetState.Complete("users", "UserCollector"));

        var results = new RuleEngine().Run(new IAssessmentRule[] { bad, good }, T.Context(snapshot));

        Assert.Equal(2, results.Count);
        Assert.Equal(RuleOutcome.NotEvaluated, results[0].Outcome);
        Assert.Contains("boom", results[0].Reason);
        Assert.Equal(RuleOutcome.Failed, results[1].Outcome);
    }

    [Fact]
    public void AffectedObjects_AreCappedBySetting_WithNote_AndEvidenceStaysConsistent()
    {
        var names = Enumerable.Range(1, 50).Select(i => "user" + i).ToArray();
        var rule = new FakeRule("AD-TST-012", Severity.Medium, new[] { "users" }, (m, _) => T.Fail(m, names));
        var settings = new AssessmentSettings { MaxAffectedObjectsPerFinding = 10 };

        var ev = RunOne(rule, T.Snapshot(false, DatasetState.Complete("users", "UserCollector")), settings);

        Assert.Equal(RuleOutcome.Failed, ev.Outcome);
        Assert.Equal(10, ev.Finding!.AffectedObjects.Count);
        Assert.Equal(10, ev.Finding.Evidence.Count);
        Assert.Equal(50, ev.ObjectsAffected);
        Assert.Contains("50", ev.Finding.Notes);
    }

    [Fact]
    public void DemoSnapshot_MarksFindingsAsDemo_AndLiveSnapshotDoesNot()
    {
        var rule = new FakeRule("AD-TST-013", Severity.High, new[] { "users" }, (m, _) => T.Fail(m, "alice"));
        var complete = DatasetState.Complete("users", "UserCollector");

        Assert.True(RunOne(rule, T.Snapshot(true, complete)).Finding!.IsDemo);
        Assert.False(RunOne(rule, T.Snapshot(false, complete)).Finding!.IsDemo);
    }

    [Fact]
    public void Engine_IsDeterministic_SameInputSameOutput()
    {
        var rule = new FakeRule("AD-TST-014", Severity.High, new[] { "users" }, (m, _) => T.Fail(m, "alice", "bob"));
        var snapshot = T.Snapshot(false, DatasetState.Complete("users", "UserCollector"));

        var first = RunOne(rule, snapshot);
        var second = RunOne(rule, snapshot);

        Assert.Equal(first.Outcome, second.Outcome);
        Assert.Equal(first.Finding!.AffectedObjects.Select(a => a.Name), second.Finding!.AffectedObjects.Select(a => a.Name));
    }
}
