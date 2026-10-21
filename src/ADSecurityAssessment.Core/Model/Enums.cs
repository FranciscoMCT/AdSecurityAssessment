namespace ADSecurityAssessment.Core.Model;

/// <summary>Severidade de uma regra/finding. A ordem numérica é usada para ordenação.</summary>
public enum Severity { Informational = 0, Low = 1, Medium = 2, High = 3, Critical = 4 }

/// <summary>Resultado tri-estado (+ N/A) de uma regra. "Compliant" nunca é assumido: só existe Passed com evidência de cobertura.</summary>
public enum RuleOutcome { Passed, Failed, NotEvaluated, NotApplicable }

public enum CollectorStatus { Succeeded, Partial, Failed, NotApplicable, Skipped }

public enum ObjectKind
{
    Forest, Domain, DomainController, User, Group, Computer, Trust, Gpo,
    ServiceAccount, Dns, Policy, CertificationAuthority, Site, Other
}

public enum DatasetCoverage { None, Partial, Complete }

public enum AssessmentMode { Live, Demo }
