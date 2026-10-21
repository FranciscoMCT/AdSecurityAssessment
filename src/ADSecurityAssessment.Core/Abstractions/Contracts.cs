using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Core.Abstractions;

public sealed class CollectionContext
{
    public required ConnectionInfo Connection { get; init; }
    public required IDirectoryGatewayFactory Gateways { get; init; }
    public required SnapshotBuilder Builder { get; init; }
    public required AssessmentSettings Settings { get; init; }
    public required IAssessmentLog Log { get; init; }
    public required Func<DateTimeOffset> Clock { get; init; }
    public DateTimeOffset Now => Clock();
    /// <summary>Progresso textual (ex.: "Users: 12.000 objetos…"). Opcional.</summary>
    public Action<string>? Report { get; init; }
}

public sealed record CollectorResult(CollectorStatus Status, int ObjectCount,
                                     IReadOnlyList<string> Errors, IReadOnlyList<string> Warnings)
{
    public static CollectorResult Ok(int count, IEnumerable<string>? warnings = null) =>
        new(CollectorStatus.Succeeded, count, Array.Empty<string>(), (warnings ?? Array.Empty<string>()).ToArray());

    public static CollectorResult Partial(int count, IEnumerable<string> errors, IEnumerable<string>? warnings = null) =>
        new(CollectorStatus.Partial, count, errors.ToArray(), (warnings ?? Array.Empty<string>()).ToArray());

    public static CollectorResult Failed(params string[] errors) =>
        new(CollectorStatus.Failed, 0, errors, Array.Empty<string>());

    public static CollectorResult NotApplicable(string reason) =>
        new(CollectorStatus.NotApplicable, 0, Array.Empty<string>(), new[] { reason });

    public static CollectorResult Skipped(string reason) =>
        new(CollectorStatus.Skipped, 0, Array.Empty<string>(), new[] { reason });
}

/// <summary>Um collector independente: lê (somente leitura) uma fatia do AD e publica datasets no SnapshotBuilder.</summary>
public interface ICollector
{
    string Id { get; }
    string DisplayName { get; }
    IReadOnlyList<string> Datasets { get; }
    IReadOnlyList<string> DependsOn { get; }
    Task<CollectorResult> CollectAsync(CollectionContext context, CancellationToken cancellationToken);
}

public sealed class RuleContext
{
    public required AssessmentSnapshot Snapshot { get; init; }
    public required AssessmentSettings Settings { get; init; }
    public required DateTimeOffset Now { get; init; }
    public ReferenceCatalog References { get; init; } = ReferenceCatalog.Default;
    public OsLifecycleCatalog Lifecycle { get; init; } = OsLifecycleCatalog.Default;
}

/// <summary>Regra determinística. Deve ser pura: mesma entrada → mesma saída; sem I/O.</summary>
public interface IAssessmentRule
{
    RuleMetadata Metadata { get; }
    RuleEvaluation Evaluate(RuleContext context);
}

/// <summary>Exportador de relatório. PDF futuro = nova implementação desta interface.</summary>
public interface IReportExporter
{
    string Format { get; }
    string FileExtension { get; }
    Task ExportAsync(AssessmentResult result, string path, CancellationToken cancellationToken);
}
