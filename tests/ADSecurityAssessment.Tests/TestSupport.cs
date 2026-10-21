using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Tests;

/// <summary>Regra de teste: o delegate decide o resultado. Permite exercitar o Rule Engine sem depender das regras reais.</summary>
internal sealed class FakeRule : IAssessmentRule
{
    private readonly Func<RuleMetadata, RuleContext, RuleEvaluation> _evaluate;

    public FakeRule(string id, Severity severity, string[] datasets, Func<RuleMetadata, RuleContext, RuleEvaluation> evaluate,
        string category = Categories.Identity)
    {
        Metadata = new RuleMetadata(id, "Title " + id, "Description", category, Modules.UsersGroups, severity, "Condition", "Risk", "Recommendation",
            new[] { new MicrosoftReference("Ref", "https://learn.microsoft.com/windows-server/") }, datasets);
        _evaluate = evaluate;
    }

    public RuleMetadata Metadata { get; }
    public RuleEvaluation Evaluate(RuleContext context) => _evaluate(Metadata, context);
}

internal static class T
{
    public static readonly DateTimeOffset Now = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

    public static AssessmentSnapshot Snapshot(bool demo = false, params DatasetState[] states)
    {
        var b = new SnapshotBuilder { IsDemo = demo };
        foreach (var s in states) b.SetState(s);
        return b.Build(Now);
    }

    public static RuleContext Context(AssessmentSnapshot snapshot, AssessmentSettings? settings = null) =>
        new() { Snapshot = snapshot, Settings = settings ?? new AssessmentSettings(), Now = Now };

    public static AffectedObject Affected(string name) => new(name, ObjectKind.User, "corp.test", null);

    public static EvidenceItem Evidence(string name) => new("test", name, "property", "value", "expected", Now);

    public static RuleEvaluation Fail(RuleMetadata meta, params string[] names) =>
        RuleEvaluation.Failed(meta, names.Select(Affected).ToArray(), names.Select(Evidence).ToArray(), evaluated: Math.Max(names.Length, 1));

    /// <summary>Resultado sintético (sem executar regra) para testar o Scoring.</summary>
    public static RuleEvaluation Result(string id, Severity severity, RuleOutcome outcome, string category = Categories.Identity)
    {
        var meta = new RuleMetadata(id, "T", "D", category, Modules.UsersGroups, severity, "C", "R", "Rec", Array.Empty<MicrosoftReference>(), Array.Empty<string>());
        return outcome switch
        {
            RuleOutcome.Failed => T.Fail(meta, "obj-" + id),
            RuleOutcome.Passed => RuleEvaluation.Passed(meta, 1),
            RuleOutcome.NotApplicable => RuleEvaluation.NotApplicable(meta, "n/a"),
            _ => RuleEvaluation.NotEvaluated(meta, "no data")
        };
    }
}
