namespace ADSecurityAssessment.Core.Model;

public sealed record AssessmentMetadata(
    string AssessmentId, string ToolName, string ToolVersion,
    DateTimeOffset StartedAt, DateTimeOffset FinishedAt,
    string Target, AssessmentMode Mode, string ExecutedBy);

public sealed record CollectorRun(
    string CollectorId, string DisplayName, CollectorStatus Status,
    DateTimeOffset StartedAt, TimeSpan Duration, int ObjectCount,
    IReadOnlyList<string> Errors, IReadOnlyList<string> Warnings);

public sealed record DomainSummary(string Name, string? NetBiosName, string FunctionalLevel, int DomainControllers,
                                   int Users, int EnabledUsers, int Computers, string? Pdc);

public sealed record EnvironmentSummary
{
    public string? ForestName { get; init; }
    public string? ForestFunctionalLevel { get; init; }
    public IReadOnlyList<DomainSummary> Domains { get; init; } = Array.Empty<DomainSummary>();
    public int DomainControllerCount { get; init; }
    public int ReadOnlyDomainControllerCount { get; init; }
    public int GlobalCatalogCount { get; init; }
    public int SiteCount { get; init; }
    public int TrustCount { get; init; }
    public int UserCount { get; init; }
    public int EnabledUserCount { get; init; }
    public int ComputerCount { get; init; }
    public int PrivilegedAccountCount { get; init; }
    public int GpoCount { get; init; }
    public bool AdCsDetected { get; init; }
    public bool HybridDetected { get; init; }
    public IReadOnlyList<string> FsmoRoles { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> DomainControllerOperatingSystems { get; init; } = Array.Empty<string>();
}

public enum CategoryStatus { Scored, NotEvaluated, NotApplicable }

public sealed record CategoryScore
{
    public required string Category { get; init; }
    public CategoryStatus Status { get; init; }
    /// <summary>0–100, maior = melhor. null quando Status != Scored.</summary>
    public double? SecurityScore { get; init; }
    /// <summary>0–100, maior = pior (parcela do peso avaliado que falhou, antes de tetos). null quando não pontuado.</summary>
    public double? RiskScore { get; init; }
    /// <summary>Assessment Coverage: peso das regras avaliadas / peso das regras aplicáveis (0–100).</summary>
    public double CoveragePercent { get; init; }
    public string? Rating { get; init; }
    public bool CapApplied { get; init; }
    public int RulesTotal { get; init; }
    public int Passed { get; init; }
    public int Failed { get; init; }
    public int NotEvaluated { get; init; }
    public int NotApplicable { get; init; }
    public int Critical { get; init; }
    public int High { get; init; }
    public int Medium { get; init; }
    public int Low { get; init; }
    public int Informational { get; init; }
}

public sealed record ScoreResult
{
    public required CategoryScore Overall { get; init; }
    public required IReadOnlyList<CategoryScore> Categories { get; init; }
    /// <summary>true quando a cobertura está abaixo do mínimo configurado: o score NÃO deve ser lido como definitivo.</summary>
    public bool IsProvisional { get; init; }
    public string? ProvisionalReason { get; init; }
    public required ScoringSettings Configuration { get; init; }
    public string MethodSummary { get; init; } = "";
}

public sealed record AssessmentResult
{
    public required AssessmentMetadata Metadata { get; init; }
    public required EnvironmentSummary Environment { get; init; }
    public required IReadOnlyList<CollectorRun> CollectorRuns { get; init; }
    public required IReadOnlyList<DatasetState> Datasets { get; init; }
    public required IReadOnlyList<RuleEvaluation> Evaluations { get; init; }
    public required IReadOnlyList<Finding> Findings { get; init; }
    public required ScoreResult Score { get; init; }
    public bool IsDemo { get; init; }
}
