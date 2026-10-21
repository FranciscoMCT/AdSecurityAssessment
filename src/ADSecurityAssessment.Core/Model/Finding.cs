namespace ADSecurityAssessment.Core.Model;

public sealed record MicrosoftReference(string Title, string Url);

public sealed record AffectedObject(string Name, ObjectKind Kind, string? Domain, string? DistinguishedName);

/// <summary>Uma evidência técnica coletada: de onde veio, de qual objeto, qual propriedade e qual valor.</summary>
public sealed record EvidenceItem(string Source, string ObjectName, string Property,
                                  string? Value, string? Expected, DateTimeOffset CollectedAt);

/// <summary>Problema identificado por uma regra. Só é criado a partir de objetos coletados (com evidência).</summary>
public sealed record Finding
{
    public required string FindingId { get; init; }
    public required string RuleId { get; init; }
    public required string Title { get; init; }
    public required string Description { get; init; }
    public required string Category { get; init; }
    public required string Module { get; init; }
    public required Severity Severity { get; init; }
    public required string Condition { get; init; }
    public required string Risk { get; init; }
    /// <summary>Orientação de remediação. NUNCA é executada pela aplicação.</summary>
    public required string Recommendation { get; init; }
    public required IReadOnlyList<MicrosoftReference> References { get; init; }
    public required IReadOnlyList<AffectedObject> AffectedObjects { get; init; }
    public required IReadOnlyList<EvidenceItem> Evidence { get; init; }
    public string? Notes { get; init; }
    public bool IsDemo { get; init; }
}
