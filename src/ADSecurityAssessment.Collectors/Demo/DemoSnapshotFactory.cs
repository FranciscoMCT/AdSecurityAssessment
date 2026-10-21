using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Collectors.Demo;

/// <summary>
/// Dados FICTÍCIOS para o Demo Mode. Domínios sob o TLD reservado ".invalid" (RFC 2606): não correspondem a nenhum ambiente real.
/// Cada nome de objeto contém "DEMO". O snapshot é marcado IsDemo=true e só pode ser processado por AssessmentOrchestrator.RunDemo;
/// jamais é combinado com dados coletados de um AD real.
/// </summary>
public static class DemoSnapshotFactory
{
    public const string Banner = "DEMO DATA — fictitious data; it does not describe any real environment.";
    private const string Root = "demo-corp.invalid";
    private const string Child = "emea.demo-corp.invalid";
    private const string RootDn = "DC=demo-corp,DC=invalid";
    private const string ChildDn = "DC=emea,DC=demo-corp,DC=invalid";
    private const string RootSid = "S-1-5-21-1000000001-1000000002-1000000003";
    private const string ChildSid = "S-1-5-21-2000000001-2000000002-2000000003";

    public static AssessmentSnapshot Create(DateTimeOffset? now = null)
    {
        var t = now ?? DateTimeOffset.UtcNow;
        var b = new SnapshotBuilder { IsDemo = true };
        DateTimeOffset Ago(int days) => t.AddDays(-days);

        // ---------------------------------------------------------------- floresta / domínios
        b.SetForest(new ForestInfo
        {
            Name = Root, RootDomain = Root, FunctionalLevel = 6, SchemaVersion = 88, TombstoneLifetimeDays = 180,
            RecycleBinEnabled = false, DsHeuristics = "0000002", DsHeuristicsAttributePresent = true,
            ConfigurationNamingContext = "CN=Configuration," + RootDn
        });
        b.Domains.Add(new DomainInfo { Name = Root, NetBiosName = "DEMOCORP", DistinguishedName = RootDn, Sid = RootSid, FunctionalLevel = 6,
            MachineAccountQuota = 10, IsForestRoot = true, PdcEmulator = "DEMO-DC01.demo-corp.invalid", ProtectedUsersGroupExists = true, ControllerUsed = "DEMO-DC01.demo-corp.invalid" });
        b.Domains.Add(new DomainInfo { Name = Child, NetBiosName = "DEMOEMEA", DistinguishedName = ChildDn, Sid = ChildSid, FunctionalLevel = 5,
            MachineAccountQuota = 10, IsForestRoot = false, PdcEmulator = "DEMO-EMEA-DC01.emea.demo-corp.invalid", ProtectedUsersGroupExists = true, ControllerUsed = "DEMO-EMEA-DC01.emea.demo-corp.invalid" });

        // ---------------------------------------------------------------- DCs
        DomainControllerInfo Dc(string name, string domain, string site, string os, string ver, bool gc, string sysvol, double skewMinutes = 0, bool ro = false) =>
            new()
            {
                Name = name, Domain = domain, DnsHostName = $"{name.ToLowerInvariant()}.{domain}", Site = site, OperatingSystem = os, OperatingSystemVersion = ver,
                IsGlobalCatalog = gc, IsReadOnly = ro, Reachable = true, CurrentTime = t.AddMinutes(skewMinutes), SysvolReplication = sysvol,
                SysvolEvidence = $"DEMO DATA: {sysvol} subscription object", DomainControllerFunctionality = 6,
                ComputerDn = $"CN={name},OU=Domain Controllers,{(domain == Root ? RootDn : ChildDn)}",
                ServerDn = $"CN={name},CN=Servers,CN={site},CN=Sites,CN=Configuration,{RootDn}"
            };
        b.DomainControllers.Add(Dc("DEMO-DC01", Root, "HQ", "Windows Server 2012 R2 Standard", "6.3 (9600)", true, "FRS"));
        b.DomainControllers.Add(Dc("DEMO-DC02", Root, "HQ", "Windows Server 2019 Datacenter", "10.0 (17763)", true, "DFSR", skewMinutes: 9));
        b.DomainControllers.Add(Dc("DEMO-EMEA-DC01", Child, "EMEA", "Windows Server 2016 Standard", "10.0 (14393)", true, "DFSR"));
        b.FsmoRoles.Add(new FsmoRole { Role = "Schema Master", OwnerHostName = "demo-dc01.demo-corp.invalid", OwnerServerDn = "CN=DEMO-DC01,CN=Servers,CN=HQ,CN=Sites,CN=Configuration," + RootDn, OwnerIsKnownDc = true });
        b.FsmoRoles.Add(new FsmoRole { Role = "Domain Naming Master", OwnerHostName = "demo-dc01.demo-corp.invalid", OwnerServerDn = "CN=DEMO-DC01,CN=Servers,CN=HQ,CN=Sites,CN=Configuration," + RootDn, OwnerIsKnownDc = true });
        b.FsmoRoles.Add(new FsmoRole { Role = "PDC Emulator", Domain = Root, OwnerHostName = "demo-dc01.demo-corp.invalid", OwnerServerDn = "CN=DEMO-DC01,CN=Servers,CN=HQ,CN=Sites,CN=Configuration," + RootDn, OwnerIsKnownDc = true });
        b.FsmoRoles.Add(new FsmoRole { Role = "RID Master", Domain = Root, OwnerHostName = "demo-dc-retired.demo-corp.invalid", OwnerServerDn = "CN=DEMO-DC-RETIRED,CN=Servers,CN=HQ,CN=Sites,CN=Configuration," + RootDn, OwnerIsKnownDc = false });
        b.FsmoRoles.Add(new FsmoRole { Role = "Infrastructure Master", Domain = Root, OwnerHostName = "demo-dc02.demo-corp.invalid", OwnerServerDn = "CN=DEMO-DC02,CN=Servers,CN=HQ,CN=Sites,CN=Configuration," + RootDn, OwnerIsKnownDc = true });
        b.Sites.Add(new SiteInfo { Name = "HQ", SubnetCount = 3, DomainControllerCount = 2, DistinguishedName = "CN=HQ,CN=Sites,CN=Configuration," + RootDn });
        b.Sites.Add(new SiteInfo { Name = "EMEA", SubnetCount = 0, DomainControllerCount = 1, DistinguishedName = "CN=EMEA,CN=Sites,CN=Configuration," + RootDn });

        b.ReplicationLinks.Add(new ReplicationLink { DestinationServer = "demo-dc02.demo-corp.invalid", SourceServer = "DEMO-DC01", NamingContext = RootDn, Domain = Root,
            LastSuccessfulSync = Ago(1), LastAttemptedSync = Ago(0), ConsecutiveFailures = 0, LastSyncResult = 0, Transport = "RPC" });
        b.ReplicationLinks.Add(new ReplicationLink { DestinationServer = "demo-emea-dc01.emea.demo-corp.invalid", SourceServer = "DEMO-DC01", NamingContext = "CN=Configuration," + RootDn, Domain = Child,
            LastSuccessfulSync = Ago(200), LastAttemptedSync = Ago(0), ConsecutiveFailures = 42, LastSyncResult = 1722, LastSyncMessage = "The RPC server is unavailable (DEMO).", Transport = "RPC" });
        b.DnsChecks.Add(new DnsCheckRecord { Domain = Root, Kind = "HostResolution", Subject = "demo-dc01.demo-corp.invalid", Success = true, Detail = "192.0.2.10 (DEMO)" });
        b.DnsChecks.Add(new DnsCheckRecord { Domain = Root, Kind = "HostResolution", Subject = "demo-dc02.demo-corp.invalid", Success = true, Detail = "192.0.2.11 (DEMO)" });
        b.DnsChecks.Add(new DnsCheckRecord { Domain = Child, Kind = "HostResolution", Subject = "demo-emea-dc01.emea.demo-corp.invalid", Success = false, Detail = "Host not found (DEMO)." });

        // ---------------------------------------------------------------- políticas de senha
        b.PasswordPolicies.Add(new PasswordPolicy { Domain = Root, PolicyName = "Default domain password policy", IsDefaultDomainPolicy = true, MinLength = 8, HistoryLength = 24,
            MaxAgeDays = 90, MinAgeDays = 1, LockoutThreshold = 0, LockoutUntilAdminUnlock = false, LockoutDurationMinutes = 30, LockoutObservationMinutes = 30,
            ComplexityEnabled = true, ReversibleEncryptionEnabled = false, PwdProperties = 1, AppliesTo = new[] { "All users (DEMO)" } });
        b.PasswordPolicies.Add(new PasswordPolicy { Domain = Child, PolicyName = "Default domain password policy", IsDefaultDomainPolicy = true, MinLength = 14, HistoryLength = 24,
            MaxAgeDays = 60, MinAgeDays = 1, LockoutThreshold = 10, LockoutUntilAdminUnlock = false, LockoutDurationMinutes = 10, LockoutObservationMinutes = 10,
            ComplexityEnabled = false, ReversibleEncryptionEnabled = false, PwdProperties = 0, AppliesTo = new[] { "All users (DEMO)" } });

        // ---------------------------------------------------------------- usuários e grupos privilegiados
        const int Normal = 0x200;
        var users = new List<UserRecord>();
        UserRecord U(string sam, int uac, int pwdAge, int? lastLogonDays, string[]? spn = null, string domain = Root) => new()
        {
            Domain = domain, SamAccountName = sam, DistinguishedName = $"CN={sam},OU=DEMO,{(domain == Root ? RootDn : ChildDn)}",
            Sid = $"{(domain == Root ? RootSid : ChildSid)}-{1100 + users.Count}", UserAccountControl = uac, PasswordLastSet = Ago(pwdAge),
            LastLogonTimestamp = lastLogonDays is null ? null : Ago(lastLogonDays.Value), WhenCreated = Ago(Math.Max(pwdAge, 900)),
            ServicePrincipalNames = spn ?? Array.Empty<string>()
        };
        users.Add(U("demo.admin1", Normal, 40, 1));
        users.Add(U("demo.admin2-neverexpires", Normal | 0x10000, 700, 3));
        users.Add(U("demo.svc-sql-admin", Normal | 0x10000, 900, 2, new[] { "MSSQLSvc/demo-sql01.demo-corp.invalid:1433" }));
        users.Add(U("demo.admin-delegated", Normal | 0x80000, 100, 5));
        users.Add(U("demo.admin-old", Normal, 500, 400));
        users.Add(U("demo.admin-disabled", Normal | 0x2, 800, 600));
        users.Add(U("demo.schemaadmin", Normal, 60, 20));
        users.Add(U("demo.acctop1", Normal, 120, 10));
        users.Add(U("demo.nested-admin", Normal, 30, 2));
        users.Add(U("demo.emea-admin", Normal, 20, 1, domain: Child));
        users.Add(U("krbtgt", 0x202, 1500, null));
        users.Add(U("krbtgt", 0x202, 600, null, domain: Child));
        users.Add(U("demo.nopreauth", Normal | 0x400000, 200, 4));
        users.Add(U("demo.deskey", Normal | 0x200000, 150, 6));
        users.Add(U("demo.nopwd", Normal | 0x20, 300, 8));
        users.Add(U("demo.reversible", Normal | 0x80, 300, 8));
        users.Add(U("demo.svc-web", Normal | 0x10000, 1000, 1, new[] { "HTTP/demo-web01.demo-corp.invalid" }));
        users.Add(U("demo.svc-deleg", Normal | 0x80000, 800, 1, new[] { "HTTP/demo-app01.demo-corp.invalid" }));
        for (var i = 1; i <= 25; i++) users.Add(U($"demo.user{i:00}", Normal, 20 + i * 3, i % 6 == 0 ? 300 + i : 1 + i % 9));
        users.Add(U("demo.stale01", Normal, 700, 450));
        users.Add(U("demo.stale02", Normal, 800, 520));
        b.Users.AddRange(users);

        PrivilegedMembership M(string group, string key, string member, string domain, bool direct = true, string? via = null, string cls = "user") => new()
        {
            Domain = domain, GroupName = group, GroupKey = key, GroupDn = $"CN={group},CN=Users,{(domain == Root ? RootDn : ChildDn)}",
            MemberName = member, MemberDn = $"CN={member},OU=DEMO,{(domain == Root ? RootDn : ChildDn)}", MemberClass = cls, IsDirect = direct, ViaGroup = via
        };
        foreach (var m in new[] { "demo.admin1", "demo.admin2-neverexpires", "demo.svc-sql-admin", "demo.admin-delegated", "demo.admin-old", "demo.admin-disabled" })
            b.PrivilegedMemberships.Add(M("Domain Admins", "DomainAdmins", m, Root));
        b.PrivilegedMemberships.Add(M("Domain Admins", "DomainAdmins", "DEMO-Tier0-Admins", Root, cls: "group"));
        b.PrivilegedMemberships.Add(M("Domain Admins", "DomainAdmins", "demo.nested-admin", Root, direct: false, via: "DEMO-Tier0-Admins"));
        b.PrivilegedMemberships.Add(M("Enterprise Admins", "EnterpriseAdmins", "demo.admin1", Root));
        b.PrivilegedMemberships.Add(M("Schema Admins", "SchemaAdmins", "demo.schemaadmin", Root));
        b.PrivilegedMemberships.Add(M("Administrators", "Administrators", "demo.admin1", Root));
        b.PrivilegedMemberships.Add(M("Account Operators", "AccountOperators", "demo.acctop1", Root));
        b.PrivilegedMemberships.Add(M("Domain Admins", "DomainAdmins", "demo.emea-admin", Child));
        b.PrivilegedMemberships.Add(M("Protected Users", "ProtectedUsers", "demo.admin1", Root));

        // ---------------------------------------------------------------- computadores
        var comps = new List<ComputerRecord>();
        ComputerRecord C(string name, int uac, string os, string ver, int? lastLogon, bool laps, string domain = Root, int primary = 515) => new()
        {
            Domain = domain, Name = name, DnsHostName = $"{name.ToLowerInvariant()}.{domain}", DistinguishedName = $"CN={name},OU=DEMO,{(domain == Root ? RootDn : ChildDn)}",
            UserAccountControl = uac, OperatingSystem = os, OperatingSystemVersion = ver, LastLogonTimestamp = lastLogon is null ? null : Ago(lastLogon.Value),
            WhenCreated = Ago(1200), PasswordLastSet = Ago(20), PrimaryGroupId = primary, WindowsLapsExpiration = laps ? t.AddDays(10) : null
        };
        comps.Add(C("DEMO-DC01", 0x82000, "Windows Server 2012 R2 Standard", "6.3 (9600)", 0, false, primary: 516));
        comps.Add(C("DEMO-DC02", 0x82000, "Windows Server 2019 Datacenter", "10.0 (17763)", 0, false, primary: 516));
        comps.Add(C("DEMO-EMEA-DC01", 0x82000, "Windows Server 2016 Standard", "10.0 (14393)", 0, false, Child, 516));
        comps.Add(C("DEMO-APP01", 0x1000 | 0x80000, "Windows Server 2016 Standard", "10.0 (14393)", 2, false));
        comps.Add(C("DEMO-SQL01", 0x1000, "Windows Server 2008 R2 Enterprise", "6.1 (7601)", 5, false));
        comps.Add(C("DEMO-FILE01", 0x1000, "Windows Server 2019 Standard", "10.0 (17763)", 1, true));
        for (var i = 1; i <= 12; i++) comps.Add(C($"DEMO-WKS{i:00}", 0x1000, "Windows 11 Enterprise", "10.0 (22631)", 1 + i, i <= 8));
        comps.Add(C("DEMO-WKS-OLD01", 0x1000, "Windows 10 Pro", "10.0 (19045)", 380, false));
        comps.Add(C("DEMO-WKS-OLD02", 0x1000, "Windows 10 Pro", "10.0 (19045)", 410, false));
        b.Computers.AddRange(comps);

        // ---------------------------------------------------------------- GPO, LAPS, confianças, AD CS, híbrido, gMSA
        b.Gpos.Add(new GpoRecord { Domain = Root, DisplayName = "DEMO Default Domain Policy", Guid = "{31B2F340-016D-11D2-945F-00C04FB984F9}", Flags = 0, WhenChanged = Ago(90) });
        b.Gpos.Add(new GpoRecord { Domain = Root, DisplayName = "DEMO Local Admin Rollout (legacy)", Guid = "{AAAAAAAA-0000-0000-0000-DEMO00000001}", Flags = 0, WhenChanged = Ago(1500) });
        b.GppPasswords.Add(new GppPasswordRecord { Domain = Root, GpoGuid = "{AAAAAAAA-0000-0000-0000-DEMO00000001}", GpoName = "DEMO Local Admin Rollout (legacy)",
            RelativePath = "{AAAAAAAA-0000-0000-0000-DEMO00000001}\\Machine\\Preferences\\Groups\\Groups.xml", Setting = "Groups.xml" });
        b.LapsInfo.Add(new LapsInfo { Domain = Root, WindowsLapsSchemaPresent = true, LegacyLapsSchemaPresent = false, EligibleComputers = 20, ComputersWithExpirationValue = 9 });
        b.LapsInfo.Add(new LapsInfo { Domain = Child, WindowsLapsSchemaPresent = true, LegacyLapsSchemaPresent = false, EligibleComputers = 0, ComputersWithExpirationValue = 0 });
        b.Trusts.Add(new TrustRecord { Domain = Root, Partner = "partner-demo.invalid", Direction = 3, TrustType = 2, TrustAttributes = 0, Classification = "External",
            SidFilteringEnabled = false, WhenCreated = Ago(1000) });
        b.Trusts.Add(new TrustRecord { Domain = Root, Partner = Child, Direction = 3, TrustType = 2, TrustAttributes = 0, Classification = "ParentChild", SidFilteringEnabled = null, WhenCreated = Ago(2000) });
        b.CertificationAuthorities.Add(new CertificationAuthorityRecord { Name = "DEMO-Issuing-CA", DnsHostName = "demo-ca01.demo-corp.invalid", DistinguishedName = "CN=DEMO-Issuing-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration," + RootDn, PublishedTemplates = 12 });
        b.HybridIndicators.Add(new HybridIndicator { Domain = Root, Kind = "SeamlessSsoAccount", ObjectName = "AZUREADSSOACC$", UserAccountControl = 0x1000, PasswordLastSet = Ago(420), HasAllowedToActOnBehalf = false });
        b.HybridIndicators.Add(new HybridIndicator { Domain = Root, Kind = "EntraConnectSyncAccount", ObjectName = "MSOL_demo000001", UserAccountControl = Normal, PasswordLastSet = Ago(300) });
        b.ManagedServiceAccounts.Add(new ManagedServiceAccount { Domain = Root, Name = "DEMO-gmsa-web$", Kind = "gMSA", ManagedPasswordIntervalDays = 30 });

        // ---------------------------------------------------------------- estados dos datasets (todos os datasets com collector: completos)
        foreach (var def in DatasetCatalog.All.Where(d => d.HasCollector))
            b.SetState(DatasetState.Complete(def.Name, "DemoData", new[] { "DEMO DATA" }));

        return b.Build(t);
    }
}
