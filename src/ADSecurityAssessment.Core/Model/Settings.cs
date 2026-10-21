namespace ADSecurityAssessment.Core.Model;

/// <summary>Parâmetros e limiares configuráveis (config/settings.json). Cada valor padrão tem origem documentada em docs/RULES.md.</summary>
public sealed class AssessmentSettings
{
    public int LdapPageSize { get; set; } = 500;
    public int QueryTimeoutSeconds { get; set; } = 60;
    public int CollectorTimeoutSeconds { get; set; } = 900;
    public int MaxObjectsPerQuery { get; set; } = 1_000_000;
    public int DnsResolutionTimeoutSeconds { get; set; } = 5;
    public bool ScanSysvolForGppPasswords { get; set; } = true;
    public int MaxGpoFilesToScan { get; set; } = 20_000;

    /// <summary>Inatividade (lastLogonTimestamp) acima da qual uma conta é "stale". Learn cita 90–180 dias; padrão 180.</summary>
    public int StaleAccountDays { get; set; } = 180;
    /// <summary>Idade máxima da senha do krbtgt antes de alertar (Defender for Identity sinaliza > 180 dias).</summary>
    public int KrbtgtMaxPasswordAgeDays { get; set; } = 180;
    /// <summary>Baseline de segurança Windows: comprimento mínimo de senha ≥ 14.</summary>
    public int MinPasswordLength { get; set; } = 14;
    /// <summary>Baseline de segurança Windows: duração do bloqueio ≥ 15 minutos.</summary>
    public int MinLockoutDurationMinutes { get; set; } = 15;
    /// <summary>Kerberos tolera 5 minutos de diferença de relógio por padrão.</summary>
    public int MaxClockSkewMinutes { get; set; } = 5;
    /// <summary>AZUREADSSOACC: a chave deve ser trocada a cada 30 dias.</summary>
    public int SeamlessSsoKeyRollDays { get; set; } = 30;

    public int MaxAffectedObjectsPerFinding { get; set; } = 2000;
    public ScoringSettings Scoring { get; set; } = new();
}

public sealed class RatingBand
{
    public double MinScore { get; set; }
    public string Label { get; set; } = "";
}

/// <summary>Configuração do cálculo de score (config/scoring.json). Documentado em docs/SCORING.md.</summary>
public sealed class ScoringSettings
{
    public Dictionary<string, double> SeverityWeights { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Critical"] = 10, ["High"] = 7, ["Medium"] = 4, ["Low"] = 1, ["Informational"] = 0
    };

    /// <summary>Teto do Security Score quando existe ao menos um finding da severidade indicada (evita "média" esconder um problema grave).</summary>
    public Dictionary<string, double> ScoreCaps { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Critical"] = 59, ["High"] = 79
    };

    /// <summary>Abaixo desta cobertura (peso avaliado / peso aplicável) o score é marcado como PROVISÓRIO.</summary>
    public double MinimumCoveragePercent { get; set; } = 50;

    public List<RatingBand> RatingBands { get; set; } = new()
    {
        new() { MinScore = 90, Label = "Strong" },
        new() { MinScore = 75, Label = "Good" },
        new() { MinScore = 60, Label = "Fair" },
        new() { MinScore = 40, Label = "Weak" },
        new() { MinScore = 0, Label = "Poor" }
    };

    public double WeightFor(Severity s) =>
        SeverityWeights.TryGetValue(s.ToString(), out var w) ? w : 0;
}

public static class Categories
{
    public const string Identity = "Identity Security";
    public const string Privileged = "Privileged Access";
    public const string Authentication = "Authentication";
    public const string Infrastructure = "Active Directory Infrastructure";
    public const string GroupPolicy = "Group Policy";
    public const string AdCs = "AD CS";
    public const string Hybrid = "Hybrid Identity";

    public static readonly IReadOnlyList<string> All = new[]
        { Identity, Privileged, Authentication, Infrastructure, GroupPolicy, AdCs, Hybrid };
}

public static class Modules
{
    public const string Infrastructure = "Active Directory Infrastructure";
    public const string DomainControllers = "Domain Controllers";
    public const string Replication = "Replication";
    public const string Dns = "DNS";
    public const string Privileged = "Privileged Accounts";
    public const string UsersGroups = "Users and Groups";
    public const string Passwords = "Password Security";
    public const string Kerberos = "Kerberos";
    public const string Ntlm = "NTLM";
    public const string Ldap = "LDAP Security";
    public const string Smb = "SMB Security";
    public const string GroupPolicy = "Group Policy";
    public const string Laps = "Windows LAPS";
    public const string ServiceAccounts = "Service Accounts / gMSA";
    public const string Trusts = "Trusts";
    public const string AdCs = "AD CS";
    public const string Hybrid = "Hybrid Identity / Microsoft Entra Connect";
    public const string Legacy = "Legacy Configurations";
    public const string Baseline = "Security Baseline";
    public const string AttackSurface = "Identity Attack Surface";

    public static readonly IReadOnlyList<string> All = new[]
    {
        Infrastructure, DomainControllers, Replication, Dns, Privileged, UsersGroups, Passwords, Kerberos, Ntlm, Ldap,
        Smb, GroupPolicy, Laps, ServiceAccounts, Trusts, AdCs, Hybrid, Legacy, Baseline, AttackSurface
    };
}
