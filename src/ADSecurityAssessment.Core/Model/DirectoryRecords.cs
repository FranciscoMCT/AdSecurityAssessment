namespace ADSecurityAssessment.Core.Model;

/// <summary>Bits de userAccountControl (valores conforme Microsoft Learn: "Use the UserAccountControl flags").</summary>
public static class UacFlags
{
    public const int AccountDisable = 0x2;
    public const int PasswordNotRequired = 0x20;
    public const int EncryptedTextPasswordAllowed = 0x80;
    public const int WorkstationTrustAccount = 0x1000;
    public const int ServerTrustAccount = 0x2000;
    public const int DontExpirePassword = 0x10000;
    public const int SmartcardRequired = 0x40000;
    public const int TrustedForDelegation = 0x80000;
    public const int NotDelegated = 0x100000;
    public const int UseDesKeyOnly = 0x200000;
    public const int DontRequirePreauth = 0x400000;
    public const int TrustedToAuthForDelegation = 0x1000000;
    public const int PartialSecretsAccount = 0x4000000;
}

/// <summary>RIDs conhecidos (Microsoft Learn: Appendix B / Active Directory security groups).</summary>
public static class WellKnownRids
{
    public const int Administrator = 500;
    public const int Krbtgt = 502;
    public const int DomainAdmins = 512;
    public const int DomainControllers = 516;
    public const int SchemaAdmins = 518;
    public const int EnterpriseAdmins = 519;
    public const int GroupPolicyCreatorOwners = 520;
    public const int ReadOnlyDomainControllers = 521;
    public const int ProtectedUsers = 525;
    public const int KeyAdmins = 526;
    public const int EnterpriseKeyAdmins = 527;

    // SIDs "builtin" completos (S-1-5-32-x)
    public const string BuiltinAdministrators = "S-1-5-32-544";
    public const string BuiltinAccountOperators = "S-1-5-32-548";
    public const string BuiltinServerOperators = "S-1-5-32-549";
    public const string BuiltinPrintOperators = "S-1-5-32-550";
    public const string BuiltinBackupOperators = "S-1-5-32-551";
    public const string BuiltinReplicator = "S-1-5-32-552";
}

public sealed record ForestInfo
{
    public required string Name { get; init; }
    public string? RootDomain { get; init; }
    public int? FunctionalLevel { get; init; }
    public int? SchemaVersion { get; init; }
    public int? TombstoneLifetimeDays { get; init; }
    public bool? RecycleBinEnabled { get; init; }
    public string? DsHeuristics { get; init; }
    public string? ConfigurationNamingContext { get; init; }
    public bool DsHeuristicsAttributePresent { get; init; }
    /// <summary>7º caractere do dSHeuristics igual a '2' = operações LDAP anônimas permitidas (Microsoft Learn KB 326690).</summary>
    public bool AnonymousLdapAllowed => DsHeuristics is { Length: >= 7 } s && s[6] == '2';
    public string FunctionalLevelName => FunctionalLevelNames.Name(FunctionalLevel);
}

public static class FunctionalLevelNames
{
    // Valores de msDS-Behavior-Version / domainFunctionality (Learn: Active Directory Domain Services functional levels).
    public static string Name(int? v) => v switch
    {
        0 => "Windows 2000",
        1 => "Windows Server 2003 interim",
        2 => "Windows Server 2003",
        3 => "Windows Server 2008",
        4 => "Windows Server 2008 R2",
        5 => "Windows Server 2012",
        6 => "Windows Server 2012 R2",
        7 => "Windows Server 2016",
        10 => "Windows Server 2025",
        null => "unknown",
        _ => $"level {v}"
    };
}

public sealed record DomainInfo
{
    public required string Name { get; init; }
    public string? NetBiosName { get; init; }
    public string? DistinguishedName { get; init; }
    public string? Sid { get; init; }
    public int? FunctionalLevel { get; init; }
    public int? MachineAccountQuota { get; init; }
    public bool IsForestRoot { get; init; }
    public string? PdcEmulator { get; init; }
    public bool ProtectedUsersGroupExists { get; init; }
    public string? ControllerUsed { get; init; }
    public string FunctionalLevelName => FunctionalLevelNames.Name(FunctionalLevel);
}

public sealed record FsmoRole
{
    public required string Role { get; init; }
    /// <summary>Domínio do papel; null para papéis de floresta (Schema Master, Domain Naming Master).</summary>
    public string? Domain { get; init; }
    public string? OwnerServerDn { get; init; }
    public string? OwnerHostName { get; init; }
    /// <summary>true quando o proprietário corresponde a um DC descoberto.</summary>
    public bool OwnerIsKnownDc { get; init; }
    public string DisplayName => Domain is null ? Role : $"{Role} ({Domain})";
}

public sealed record SiteInfo
{
    public required string Name { get; init; }
    public int SubnetCount { get; init; }
    public int DomainControllerCount { get; init; }
    public string? DistinguishedName { get; init; }
}

public sealed record DomainControllerInfo
{
    public required string Name { get; init; }
    public required string Domain { get; init; }
    public string? DnsHostName { get; init; }
    public string? Site { get; init; }
    public string? OperatingSystem { get; init; }
    public string? OperatingSystemVersion { get; init; }
    public bool IsGlobalCatalog { get; init; }
    public bool IsReadOnly { get; init; }
    public bool Reachable { get; init; }
    public string? ReachabilityNote { get; init; }
    public DateTimeOffset? CurrentTime { get; init; }
    /// <summary>"DFSR", "FRS" ou "Unknown" — decidido por evidência (objetos msDFSR-Subscription / nTFRSSubscriber).</summary>
    public string SysvolReplication { get; init; } = "Unknown";
    public string? SysvolEvidence { get; init; }
    public int? DomainControllerFunctionality { get; init; }
    public string? ComputerDn { get; init; }
    public string? ServerDn { get; init; }
    /// <summary>Preenchido pelo normalizador: diferença de relógio em relação ao PDC Emulator do domínio.</summary>
    public double? ClockSkewSecondsVsPdc { get; init; }
    /// <summary>Preenchido pelo normalizador: chave de ciclo de vida do produto (ex.: ws2016) ou null.</summary>
    public string? OsProductKey { get; init; }
}

public sealed record UserRecord
{
    public required string Domain { get; init; }
    public required string SamAccountName { get; init; }
    public string? DistinguishedName { get; init; }
    public string? Sid { get; init; }
    public string ObjectClass { get; init; } = "user";
    public int UserAccountControl { get; init; }
    public DateTimeOffset? PasswordLastSet { get; init; }
    public DateTimeOffset? LastLogonTimestamp { get; init; }
    public DateTimeOffset? WhenCreated { get; init; }
    public int? AdminCount { get; init; }
    public IReadOnlyList<string> ServicePrincipalNames { get; init; } = Array.Empty<string>();

    public bool Enabled => (UserAccountControl & UacFlags.AccountDisable) == 0;
    public bool PasswordNeverExpires => (UserAccountControl & UacFlags.DontExpirePassword) != 0;
    public bool PasswordNotRequired => (UserAccountControl & UacFlags.PasswordNotRequired) != 0;
    public bool ReversibleEncryption => (UserAccountControl & UacFlags.EncryptedTextPasswordAllowed) != 0;
    public bool DoesNotRequirePreAuth => (UserAccountControl & UacFlags.DontRequirePreauth) != 0;
    public bool UseDesKeyOnly => (UserAccountControl & UacFlags.UseDesKeyOnly) != 0;
    public bool TrustedForDelegation => (UserAccountControl & UacFlags.TrustedForDelegation) != 0;
    public bool TrustedToAuthForDelegation => (UserAccountControl & UacFlags.TrustedToAuthForDelegation) != 0;
    public bool NotDelegated => (UserAccountControl & UacFlags.NotDelegated) != 0;
    public bool SmartcardRequired => (UserAccountControl & UacFlags.SmartcardRequired) != 0;
    public bool HasSpn => ServicePrincipalNames.Count > 0;
    public bool IsKrbtgt => SamAccountName.Equals("krbtgt", StringComparison.OrdinalIgnoreCase);
    public bool IsRodcKrbtgt => SamAccountName.StartsWith("krbtgt_", StringComparison.OrdinalIgnoreCase);

    // ---- Enriquecimento (SnapshotNormalizer) ----
    public bool IsPrivileged { get; init; }
    public IReadOnlyList<string> PrivilegedGroups { get; init; } = Array.Empty<string>();
    public bool IsProtectedUsersMember { get; init; }
    public bool DomainHasProtectedUsersGroup { get; init; }
    public bool IsStale { get; init; }
    public int? PasswordAgeDays { get; init; }
    public int? DaysSinceLastLogon { get; init; }
}

public sealed record ComputerRecord
{
    public required string Domain { get; init; }
    public required string Name { get; init; }
    public string? DnsHostName { get; init; }
    public string? DistinguishedName { get; init; }
    public string? Sid { get; init; }
    public int UserAccountControl { get; init; }
    public string? OperatingSystem { get; init; }
    public string? OperatingSystemVersion { get; init; }
    public DateTimeOffset? LastLogonTimestamp { get; init; }
    public DateTimeOffset? PasswordLastSet { get; init; }
    public DateTimeOffset? WhenCreated { get; init; }
    public DateTimeOffset? WindowsLapsExpiration { get; init; }
    public DateTimeOffset? LegacyLapsExpiration { get; init; }
    public int? PrimaryGroupId { get; init; }

    public bool Enabled => (UserAccountControl & UacFlags.AccountDisable) == 0;
    public bool TrustedForDelegation => (UserAccountControl & UacFlags.TrustedForDelegation) != 0;
    public bool TrustedToAuthForDelegation => (UserAccountControl & UacFlags.TrustedToAuthForDelegation) != 0;
    public bool IsDomainController => (UserAccountControl & UacFlags.ServerTrustAccount) != 0
                                       || PrimaryGroupId is WellKnownRids.DomainControllers or WellKnownRids.ReadOnlyDomainControllers;
    public bool HasLapsExpiration => WindowsLapsExpiration is not null || LegacyLapsExpiration is not null;
    public bool IsServerOs => OperatingSystem?.Contains("Server", StringComparison.OrdinalIgnoreCase) == true;

    // ---- Enriquecimento ----
    public bool IsStale { get; init; }
    public int? DaysSinceLastLogon { get; init; }
    public string? OsProductKey { get; init; }
}

public sealed record PrivilegedMembership
{
    public required string Domain { get; init; }
    /// <summary>Nome estável do grupo (ex.: "Domain Admins", "Schema Admins", "Administrators").</summary>
    public required string GroupName { get; init; }
    /// <summary>Chave estável: DomainAdmins, EnterpriseAdmins, SchemaAdmins, Administrators, AccountOperators, ServerOperators, BackupOperators, PrintOperators, ProtectedUsers.</summary>
    public required string GroupKey { get; init; }
    public string? GroupDn { get; init; }
    public required string MemberName { get; init; }
    public string? MemberDn { get; init; }
    public string? MemberSid { get; init; }
    public string MemberClass { get; init; } = "user";
    /// <summary>true = membro direto do grupo; false = membro por aninhamento (expansão recursiva do atributo member).</summary>
    public bool IsDirect { get; init; }
    public string? ViaGroup { get; init; }
    public string Label => $"{MemberName} -> {GroupName}";
}

public sealed record PasswordPolicy
{
    public required string Domain { get; init; }
    public required string PolicyName { get; init; }
    public bool IsDefaultDomainPolicy { get; init; }
    public int? MinLength { get; init; }
    public int? HistoryLength { get; init; }
    public double? MaxAgeDays { get; init; }
    public double? MinAgeDays { get; init; }
    public int? LockoutThreshold { get; init; }
    public double? LockoutDurationMinutes { get; init; }
    /// <summary>lockoutDuration = -∞ (valor mínimo) significa bloqueio até desbloqueio manual.</summary>
    public bool LockoutUntilAdminUnlock { get; init; }
    public double? LockoutObservationMinutes { get; init; }
    public bool? ComplexityEnabled { get; init; }
    public bool? ReversibleEncryptionEnabled { get; init; }
    public int? PwdProperties { get; init; }
    public IReadOnlyList<string> AppliesTo { get; init; } = Array.Empty<string>();
}

public sealed record TrustRecord
{
    public required string Domain { get; init; }
    public required string Partner { get; init; }
    public int Direction { get; init; }
    public int TrustType { get; init; }
    public int TrustAttributes { get; init; }
    /// <summary>Classificação via System.DirectoryServices.ActiveDirectory.TrustType (ParentChild, TreeRoot, CrossLink, External, Forest, Kerberos, Unknown).</summary>
    public string? Classification { get; init; }
    public string DirectionName => Direction switch { 1 => "Inbound", 2 => "Outbound", 3 => "Bidirectional", _ => $"Unknown({Direction})" };
    public bool IsExternalOrForest => Classification is "External" or "Forest";
    /// <summary>Resultado de GetSidFilteringStatus (true = habilitado). null = não pôde ser determinado.</summary>
    public bool? SidFilteringEnabled { get; init; }
    public string? SidFilteringNote { get; init; }
    public DateTimeOffset? WhenCreated { get; init; }
}

public sealed record ReplicationLink
{
    public required string DestinationServer { get; init; }
    public required string SourceServer { get; init; }
    public required string NamingContext { get; init; }
    public string? Domain { get; init; }
    public DateTimeOffset? LastSuccessfulSync { get; init; }
    public DateTimeOffset? LastAttemptedSync { get; init; }
    public int ConsecutiveFailures { get; init; }
    public int LastSyncResult { get; init; }
    public string? LastSyncMessage { get; init; }
    public string? Transport { get; init; }
}

public sealed record DnsCheckRecord
{
    public required string Domain { get; init; }
    /// <summary>HostResolution | ZoneInventory</summary>
    public required string Kind { get; init; }
    public required string Subject { get; init; }
    public bool Success { get; init; }
    public string? Detail { get; init; }
}

public sealed record GpoRecord
{
    public required string Domain { get; init; }
    public required string DisplayName { get; init; }
    public required string Guid { get; init; }
    public string? DistinguishedName { get; init; }
    public int? Flags { get; init; }
    public DateTimeOffset? WhenChanged { get; init; }
    public string? FileSysPath { get; init; }
}

/// <summary>Arquivo de Group Policy Preferences com atributo cpassword (valor NUNCA é armazenado).</summary>
public sealed record GppPasswordRecord
{
    public required string Domain { get; init; }
    public required string GpoGuid { get; init; }
    public string? GpoName { get; init; }
    public required string RelativePath { get; init; }
    public required string Setting { get; init; }
}

public sealed record LapsInfo
{
    public required string Domain { get; init; }
    public bool WindowsLapsSchemaPresent { get; init; }
    public bool LegacyLapsSchemaPresent { get; init; }
    public bool SchemaExtended => WindowsLapsSchemaPresent || LegacyLapsSchemaPresent;
    public int ComputersWithExpirationValue { get; init; }
    public int EligibleComputers { get; init; }
}

public sealed record ManagedServiceAccount
{
    public required string Domain { get; init; }
    public required string Name { get; init; }
    public string? DistinguishedName { get; init; }
    public string Kind { get; init; } = "gMSA";
    public int? ManagedPasswordIntervalDays { get; init; }
}

public sealed record CertificationAuthorityRecord
{
    public required string Name { get; init; }
    public string? DnsHostName { get; init; }
    public string? DistinguishedName { get; init; }
    public int? PublishedTemplates { get; init; }
}

public sealed record HybridIndicator
{
    public required string Domain { get; init; }
    /// <summary>EntraConnectSyncAccount | SeamlessSsoAccount</summary>
    public required string Kind { get; init; }
    public required string ObjectName { get; init; }
    public string? DistinguishedName { get; init; }
    public int UserAccountControl { get; init; }
    public DateTimeOffset? PasswordLastSet { get; init; }
    public bool Enabled => (UserAccountControl & UacFlags.AccountDisable) == 0;
    public bool TrustedForDelegation => (UserAccountControl & UacFlags.TrustedForDelegation) != 0;
    public bool TrustedToAuthForDelegation => (UserAccountControl & UacFlags.TrustedToAuthForDelegation) != 0;
    public bool HasAllowedToActOnBehalf { get; init; }
    public int? PasswordAgeDays { get; init; }
}
