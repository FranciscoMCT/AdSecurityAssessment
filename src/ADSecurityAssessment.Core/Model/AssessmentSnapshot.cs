namespace ADSecurityAssessment.Core.Model;

public sealed record DatasetState(
    string Name, string Collector, DatasetCoverage Coverage, string? Reason,
    IReadOnlyList<string> ScopesCollected, IReadOnlyList<string> ScopesFailed)
{
    public static DatasetState Complete(string name, string collector, IEnumerable<string>? scopes = null) =>
        new(name, collector, DatasetCoverage.Complete, null, (scopes ?? Array.Empty<string>()).ToArray(), Array.Empty<string>());

    public static DatasetState Partial(string name, string collector, string reason,
        IEnumerable<string> ok, IEnumerable<string> failed) =>
        new(name, collector, DatasetCoverage.Partial, reason, ok.ToArray(), failed.ToArray());

    public static DatasetState None(string name, string collector, string reason, IEnumerable<string>? failed = null) =>
        new(name, collector, DatasetCoverage.None, reason, Array.Empty<string>(), (failed ?? Array.Empty<string>()).ToArray());
}

/// <summary>Nomes (fechados) dos datasets. Usados por collectors, regras C# e regras JSON.</summary>
public static class DatasetNames
{
    public const string Forest = "forest";
    public const string Domains = "domains";
    public const string DomainControllers = "domain-controllers";
    public const string FsmoRoles = "fsmo-roles";
    public const string Sites = "sites";
    public const string Trusts = "trusts";
    public const string Users = "users";
    public const string Computers = "computers";
    public const string PrivilegedMemberships = "privileged-memberships";
    public const string PasswordPolicies = "password-policies";
    public const string ReplicationLinks = "replication-links";
    public const string DnsChecks = "dns-checks";
    public const string Gpos = "gpos";
    public const string GppPasswords = "gpp-passwords";
    public const string LapsInfo = "laps-info";
    public const string ManagedServiceAccounts = "managed-service-accounts";
    public const string CertificationAuthorities = "certification-authorities";
    public const string HybridIndicators = "hybrid-indicators";

    // Datasets conhecidos mas SEM collector (configuração não legível por LDAP) → regras ficam Not Evaluated.
    public const string DnsZoneSecurity = "dns-zone-security";
    public const string LdapSigningConfig = "ldap-signing-config";
    public const string LdapChannelBindingConfig = "ldap-channel-binding-config";
    public const string SmbSigningConfig = "smb-signing-config";
    public const string Smb1Config = "smb1-config";
    public const string NtlmConfig = "ntlm-config";
    public const string CertificateTemplateSecurity = "certificate-template-security";
}

public sealed record DatasetDefinition(string Name, Type? ItemType, Func<AssessmentSnapshot, IEnumerable<object>>? Accessor,
                                       string? NotCollectedReason = null)
{
    public bool HasCollector => Accessor is not null;
}

/// <summary>Registro fechado de datasets: nome → tipo de item + acessor. Usado pelo interpretador de regras JSON.</summary>
public static class DatasetCatalog
{
    private static DatasetDefinition D<T>(string name, Func<AssessmentSnapshot, IEnumerable<T>> get) =>
        new(name, typeof(T), s => get(s).Cast<object>());

    private static DatasetDefinition Planned(string name, string reason) => new(name, null, null, reason);

    public static readonly IReadOnlyList<DatasetDefinition> All = new[]
    {
        D(DatasetNames.Forest, s => s.Forest is null ? Array.Empty<ForestInfo>() : new[] { s.Forest }),
        D(DatasetNames.Domains, s => s.Domains),
        D(DatasetNames.DomainControllers, s => s.DomainControllers),
        D(DatasetNames.FsmoRoles, s => s.FsmoRoles),
        D(DatasetNames.Sites, s => s.Sites),
        D(DatasetNames.Trusts, s => s.Trusts),
        D(DatasetNames.Users, s => s.Users),
        D(DatasetNames.Computers, s => s.Computers),
        D(DatasetNames.PrivilegedMemberships, s => s.PrivilegedMemberships),
        D(DatasetNames.PasswordPolicies, s => s.PasswordPolicies),
        D(DatasetNames.ReplicationLinks, s => s.ReplicationLinks),
        D(DatasetNames.DnsChecks, s => s.DnsChecks),
        D(DatasetNames.Gpos, s => s.Gpos),
        D(DatasetNames.GppPasswords, s => s.GppPasswords),
        D(DatasetNames.LapsInfo, s => s.LapsInfo),
        D(DatasetNames.ManagedServiceAccounts, s => s.ManagedServiceAccounts),
        D(DatasetNames.CertificationAuthorities, s => s.CertificationAuthorities),
        D(DatasetNames.HybridIndicators, s => s.HybridIndicators),

        Planned(DatasetNames.DnsZoneSecurity,
            "The dynamic-update setting of DNS zones is stored in the binary dnsProperty attribute (MS-DNSP), whose layout is not parsed in this version; check it in DNS Manager."),
        Planned(DatasetNames.LdapSigningConfig,
            "LDAP signing enforcement is a policy/registry setting of the DC and cannot be read over LDAP. It requires privileged remote reads or GPO resolution."),
        Planned(DatasetNames.LdapChannelBindingConfig,
            "LDAP channel binding is a registry setting of the DC and cannot be read over LDAP."),
        Planned(DatasetNames.SmbSigningConfig,
            "The SMB signing configuration (registry/policy) of the DCs cannot be read over LDAP."),
        Planned(DatasetNames.Smb1Config,
            "The SMBv1 state is a local server setting and cannot be read over LDAP."),
        Planned(DatasetNames.NtlmConfig,
            "LmCompatibilityLevel and NTLM restrictions are policy/registry settings and cannot be read over LDAP."),
        Planned(DatasetNames.CertificateTemplateSecurity,
            "Analysis of ACLs/EKUs of certificate templates (AD CS) is not implemented in this version; only CA detection is available."),
    };

    private static readonly Dictionary<string, DatasetDefinition> ByName =
        All.ToDictionary(d => d.Name, StringComparer.OrdinalIgnoreCase);

    public static bool TryGet(string name, out DatasetDefinition def) => ByName.TryGetValue(name, out def!);
    public static bool IsKnown(string name) => ByName.ContainsKey(name);
}

/// <summary>Dados coletados e normalizados. Contém apenas fatos — nunca conclusões.</summary>
public sealed record AssessmentSnapshot
{
    public ForestInfo? Forest { get; init; }
    public IReadOnlyList<DomainInfo> Domains { get; init; } = Array.Empty<DomainInfo>();
    public IReadOnlyList<DomainControllerInfo> DomainControllers { get; init; } = Array.Empty<DomainControllerInfo>();
    public IReadOnlyList<FsmoRole> FsmoRoles { get; init; } = Array.Empty<FsmoRole>();
    public IReadOnlyList<SiteInfo> Sites { get; init; } = Array.Empty<SiteInfo>();
    public IReadOnlyList<TrustRecord> Trusts { get; init; } = Array.Empty<TrustRecord>();
    public IReadOnlyList<UserRecord> Users { get; init; } = Array.Empty<UserRecord>();
    public IReadOnlyList<ComputerRecord> Computers { get; init; } = Array.Empty<ComputerRecord>();
    public IReadOnlyList<PrivilegedMembership> PrivilegedMemberships { get; init; } = Array.Empty<PrivilegedMembership>();
    public IReadOnlyList<PasswordPolicy> PasswordPolicies { get; init; } = Array.Empty<PasswordPolicy>();
    public IReadOnlyList<ReplicationLink> ReplicationLinks { get; init; } = Array.Empty<ReplicationLink>();
    public IReadOnlyList<DnsCheckRecord> DnsChecks { get; init; } = Array.Empty<DnsCheckRecord>();
    public IReadOnlyList<GpoRecord> Gpos { get; init; } = Array.Empty<GpoRecord>();
    public IReadOnlyList<GppPasswordRecord> GppPasswords { get; init; } = Array.Empty<GppPasswordRecord>();
    public IReadOnlyList<LapsInfo> LapsInfo { get; init; } = Array.Empty<LapsInfo>();
    public IReadOnlyList<ManagedServiceAccount> ManagedServiceAccounts { get; init; } = Array.Empty<ManagedServiceAccount>();
    public IReadOnlyList<CertificationAuthorityRecord> CertificationAuthorities { get; init; } = Array.Empty<CertificationAuthorityRecord>();
    public IReadOnlyList<HybridIndicator> HybridIndicators { get; init; } = Array.Empty<HybridIndicator>();

    public IReadOnlyDictionary<string, DatasetState> States { get; init; } =
        new Dictionary<string, DatasetState>(StringComparer.OrdinalIgnoreCase);

    public DateTimeOffset CollectedAt { get; init; } = DateTimeOffset.UtcNow;
    public bool IsDemo { get; init; }

    public DatasetState GetState(string dataset)
    {
        if (States.TryGetValue(dataset, out var st)) return st;
        if (DatasetCatalog.TryGet(dataset, out var def) && !def.HasCollector)
            return DatasetState.None(dataset, "(no collector)", def.NotCollectedReason ?? "This dataset has no collector in this version.");
        return DatasetState.None(dataset, "(none)", "No collector published this dataset (the collector did not run or was not applicable).");
    }
}

/// <summary>Acumula dados publicados pelos collectors. Os collectors só escrevem aqui; as regras só leem o <see cref="AssessmentSnapshot"/>.</summary>
public sealed class SnapshotBuilder
{
    private readonly object _gate = new();
    private readonly Dictionary<string, DatasetState> _states = new(StringComparer.OrdinalIgnoreCase);

    public ForestInfo? Forest { get; private set; }
    public List<DomainInfo> Domains { get; } = new();
    public List<DomainControllerInfo> DomainControllers { get; } = new();
    public List<FsmoRole> FsmoRoles { get; } = new();
    public List<SiteInfo> Sites { get; } = new();
    public List<TrustRecord> Trusts { get; } = new();
    public List<UserRecord> Users { get; } = new();
    public List<ComputerRecord> Computers { get; } = new();
    public List<PrivilegedMembership> PrivilegedMemberships { get; } = new();
    public List<PasswordPolicy> PasswordPolicies { get; } = new();
    public List<ReplicationLink> ReplicationLinks { get; } = new();
    public List<DnsCheckRecord> DnsChecks { get; } = new();
    public List<GpoRecord> Gpos { get; } = new();
    public List<GppPasswordRecord> GppPasswords { get; } = new();
    public List<LapsInfo> LapsInfo { get; } = new();
    public List<ManagedServiceAccount> ManagedServiceAccounts { get; } = new();
    public List<CertificationAuthorityRecord> CertificationAuthorities { get; } = new();
    public List<HybridIndicator> HybridIndicators { get; } = new();

    public bool IsDemo { get; init; }

    public void SetForest(ForestInfo forest) { lock (_gate) Forest = forest; }
    public void SetState(DatasetState state) { lock (_gate) _states[state.Name] = state; }
    public DatasetState? TryGetState(string name) { lock (_gate) return _states.TryGetValue(name, out var s) ? s : null; }

    public AssessmentSnapshot Build(DateTimeOffset collectedAt)
    {
        lock (_gate)
        {
            return new AssessmentSnapshot
            {
                Forest = Forest,
                Domains = Domains.ToArray(),
                DomainControllers = DomainControllers.ToArray(),
                FsmoRoles = FsmoRoles.ToArray(),
                Sites = Sites.ToArray(),
                Trusts = Trusts.ToArray(),
                Users = Users.ToArray(),
                Computers = Computers.ToArray(),
                PrivilegedMemberships = PrivilegedMemberships.ToArray(),
                PasswordPolicies = PasswordPolicies.ToArray(),
                ReplicationLinks = ReplicationLinks.ToArray(),
                DnsChecks = DnsChecks.ToArray(),
                Gpos = Gpos.ToArray(),
                GppPasswords = GppPasswords.ToArray(),
                LapsInfo = LapsInfo.ToArray(),
                ManagedServiceAccounts = ManagedServiceAccounts.ToArray(),
                CertificationAuthorities = CertificationAuthorities.ToArray(),
                HybridIndicators = HybridIndicators.ToArray(),
                States = new Dictionary<string, DatasetState>(_states, StringComparer.OrdinalIgnoreCase),
                CollectedAt = collectedAt,
                IsDemo = IsDemo
            };
        }
    }
}
