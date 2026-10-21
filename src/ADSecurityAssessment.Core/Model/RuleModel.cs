namespace ADSecurityAssessment.Core.Model;

public sealed record RuleMetadata(
    string RuleId, string Title, string Description, string Category, string Module,
    Severity Severity, string Condition, string Risk, string Recommendation,
    IReadOnlyList<MicrosoftReference> References,
    IReadOnlyList<string> RequiredDatasets);

public sealed record RuleEvaluation(
    RuleMetadata Rule, RuleOutcome Outcome,
    Finding? Finding,
    string? Reason,
    int ObjectsEvaluated, int ObjectsAffected)
{
    public static RuleEvaluation Passed(RuleMetadata rule, int evaluated) =>
        new(rule, RuleOutcome.Passed, null, null, evaluated, 0);

    public static RuleEvaluation NotEvaluated(RuleMetadata rule, string reason) =>
        new(rule, RuleOutcome.NotEvaluated, null, reason, 0, 0);

    public static RuleEvaluation NotApplicable(RuleMetadata rule, string reason) =>
        new(rule, RuleOutcome.NotApplicable, null, reason, 0, 0);

    /// <summary>Cria o Finding a partir dos metadados da regra + objetos/evidências coletados.</summary>
    public static RuleEvaluation Failed(RuleMetadata rule, IReadOnlyList<AffectedObject> affected,
        IReadOnlyList<EvidenceItem> evidence, int evaluated, string? notes = null, bool isDemo = false)
    {
        var finding = new Finding
        {
            FindingId = rule.RuleId,
            RuleId = rule.RuleId,
            Title = rule.Title,
            Description = rule.Description,
            Category = rule.Category,
            Module = rule.Module,
            Severity = rule.Severity,
            Condition = rule.Condition,
            Risk = rule.Risk,
            Recommendation = rule.Recommendation,
            References = rule.References,
            AffectedObjects = affected,
            Evidence = evidence,
            Notes = notes,
            IsDemo = isDemo
        };
        return new RuleEvaluation(rule, RuleOutcome.Failed, finding, null, evaluated, affected.Count);
    }
}
