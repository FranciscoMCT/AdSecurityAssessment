using ADSecurityAssessment.Collectors.Support;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Collectors;

/// <summary>
/// Enumera os domínios da floresta (partições crossRef) e, para cada um: nível funcional, MachineAccountQuota, PDC Emulator,
/// existência de Protected Users e a política de senha (Default Domain Policy + PSOs legíveis). Falha de um domínio não cancela os demais.
/// </summary>
public sealed class DomainCollector : CollectorBase
{
    private static readonly string[] HeadAttributes =
    {
        "objectSid", "msDS-Behavior-Version", "ms-DS-MachineAccountQuota", "fSMORoleOwner", "minPwdLength", "pwdHistoryLength",
        "maxPwdAge", "minPwdAge", "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow", "pwdProperties"
    };

    private static readonly string[] PsoAttributes =
    {
        "cn", "msDS-MinimumPasswordLength", "msDS-PasswordHistoryLength", "msDS-MaximumPasswordAge", "msDS-MinimumPasswordAge",
        "msDS-LockoutThreshold", "msDS-LockoutDuration", "msDS-LockoutObservationWindow", "msDS-PasswordComplexityEnabled",
        "msDS-PasswordReversibleEncryptionEnabled", "msDS-PSOAppliesTo", "msDS-PasswordSettingsPrecedence"
    };

    public override string Id => "domain";
    public override string DisplayName => "Domain discovery + password policy";
    public override IReadOnlyList<string> Datasets { get; } = new[] { DatasetNames.Domains, DatasetNames.PasswordPolicies };
    public override IReadOnlyList<string> DependsOn { get; } = new[] { "forest" };

    public override Task<CollectorResult> CollectAsync(CollectionContext ctx, CancellationToken ct)
    {
        var domainsTracker = new ScopeTracker();
        var policyTracker = new ScopeTracker();

        IDirectoryGateway initial;
        try { initial = OpenInitial(ctx); }
        catch (DirectoryQueryException ex) { return Task.FromResult(CollectorResult.Failed(ex.Message)); }

        using (initial)
        {
            var config = initial.RootDse.ConfigurationNamingContext!;
            var rootNc = initial.RootDse.RootDomainNamingContext!;
            var initialNc = initial.RootDse.DefaultNamingContext;

            var partitions = new List<(string Nc, string Dns, string? NetBios)>();
            try
            {
                // systemFlags com FLAG_CR_NTDS_NC (1) e FLAG_CR_NTDS_DOMAIN (2) = partição de domínio.
                foreach (var cr in initial.Search(new SearchSpec($"CN=Partitions,{config}",
                    "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=3))", SearchScopeKind.OneLevel,
                    new[] { "nCName", "dnsRoot", "nETBIOSName" }, 1000), ct))
                {
                    var nc = cr.GetString("nCName");
                    var dns = cr.GetString("dnsRoot") ?? (nc is null ? null : LdapUtil.DnToDns(nc));
                    if (nc is not null && dns is not null) partitions.Add((nc, dns, cr.GetString("nETBIOSName")));
                }
            }
            catch (DirectoryQueryException ex)
            {
                return Task.FromResult(CollectorResult.Failed($"Could not enumerate the domains of the forest: {ex.Message}"));
            }
            if (partitions.Count == 0 && initialNc is not null)
            {
                domainsTracker.Warn("No domain partition was found under CN=Partitions; using only the connection domain.");
                partitions.Add((initialNc, LdapUtil.DnToDns(initialNc), null));
            }

            foreach (var (nc, dns, netbios) in partitions.OrderBy(p => p.Dns, StringComparer.OrdinalIgnoreCase))
            {
                ct.ThrowIfCancellationRequested();
                IDirectoryGateway? own = null;
                try
                {
                    var useInitial = string.Equals(nc, initialNc, StringComparison.OrdinalIgnoreCase);
                    IDirectoryGateway gw;
                    if (useInitial) gw = initial;
                    else gw = own = ctx.Gateways.Open(new GatewayTarget(null, dns));
                    CollectDomain(ctx, gw, nc, dns, netbios, string.Equals(nc, rootNc, StringComparison.OrdinalIgnoreCase),
                        config, domainsTracker, policyTracker, ct);
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) when (ex is DirectoryQueryException or InvalidOperationException)
                {
                    domainsTracker.Fail(dns, ex.Message);
                    policyTracker.Fail(dns, ex.Message);
                    ctx.Log.Warn($"domain/{dns}: {ex.Message}");
                }
                finally { own?.Dispose(); }
            }
        }

        Publish(ctx, domainsTracker, DatasetNames.Domains, Id);
        Publish(ctx, policyTracker, DatasetNames.PasswordPolicies, Id);
        return Task.FromResult(domainsTracker.ToResult(ctx.Builder.Domains.Count));
    }

    private void CollectDomain(CollectionContext ctx, IDirectoryGateway gw, string nc, string dns, string? netbios, bool isRoot,
        string config, ScopeTracker domains, ScopeTracker policies, CancellationToken ct)
    {
        var head = gw.ReadEntry(nc, HeadAttributes, ct) ?? throw new DirectoryQueryException($"Domain head '{nc}' was not found.");
        var sid = head.GetSid("objectSid");

        var protectedUsers = false;
        if (sid is not null)
        {
            try
            {
                protectedUsers = gw.Search(new SearchSpec(nc, $"(objectSid={LdapUtil.SidFilterValue(sid + "-" + WellKnownRids.ProtectedUsers)})",
                    SearchScopeKind.Subtree, new[] { "distinguishedName" }, 1), ct).Any();
            }
            catch (DirectoryQueryException ex) { domains.Warn($"{dns}: could not check the Protected Users group ({ex.Message})."); }
        }

        string? pdcHost = null;
        var pdcNtds = head.GetString("fSMORoleOwner");
        if (pdcNtds is not null && LdapUtil.ParentDn(pdcNtds) is { } serverDn)
        {
            try { pdcHost = gw.ReadEntry(serverDn, new[] { "dNSHostName" }, ct)?.GetString("dNSHostName"); }
            catch (DirectoryQueryException ex) { domains.Warn($"{dns}: PDC Emulator could not be resolved ({ex.Message})."); }
        }

        ctx.Builder.Domains.Add(new DomainInfo
        {
            Name = dns,
            NetBiosName = netbios,
            DistinguishedName = nc,
            Sid = sid,
            FunctionalLevel = head.GetInt("msDS-Behavior-Version") ?? gw.RootDse.DomainFunctionality,
            MachineAccountQuota = head.GetInt("ms-DS-MachineAccountQuota"),
            IsForestRoot = isRoot,
            PdcEmulator = pdcHost,
            ProtectedUsersGroupExists = protectedUsers,
            ControllerUsed = gw.Server
        });
        domains.Succeeded(dns);

        // ---- política de senha do domínio (Default Domain Policy)
        var pwdProps = head.GetInt("pwdProperties");
        var lockoutDuration = head.GetLong("lockoutDuration");
        ctx.Builder.PasswordPolicies.Add(new PasswordPolicy
        {
            Domain = dns,
            PolicyName = "Default domain password policy",
            IsDefaultDomainPolicy = true,
            MinLength = head.GetInt("minPwdLength"),
            HistoryLength = head.GetInt("pwdHistoryLength"),
            MaxAgeDays = LdapUtil.IntervalDays(head.GetLong("maxPwdAge")),
            MinAgeDays = LdapUtil.IntervalDays(head.GetLong("minPwdAge")),
            LockoutThreshold = head.GetInt("lockoutThreshold"),
            // lockoutDuration 0 ou -∞ = bloqueado até um administrador desbloquear.
            LockoutUntilAdminUnlock = lockoutDuration is 0 or long.MinValue,
            LockoutDurationMinutes = LdapUtil.IntervalMinutes(lockoutDuration),
            LockoutObservationMinutes = LdapUtil.IntervalMinutes(head.GetLong("lockOutObservationWindow")),
            PwdProperties = pwdProps,
            ComplexityEnabled = pwdProps is null ? null : (pwdProps & 1) != 0,
            ReversibleEncryptionEnabled = pwdProps is null ? null : (pwdProps & 16) != 0,
            AppliesTo = new[] { "All users of the domain (default domain policy)" }
        });

        // ---- PSOs (fine-grained). Por padrão só administradores leem o container; "nenhum retornado" não prova inexistência.
        var psoCount = 0;
        try
        {
            foreach (var pso in gw.Search(new SearchSpec($"CN=Password Settings Container,CN=System,{nc}",
                "(objectClass=msDS-PasswordSettings)", SearchScopeKind.OneLevel, PsoAttributes, 1000), ct))
            {
                var duration = pso.GetLong("msDS-LockoutDuration");
                ctx.Builder.PasswordPolicies.Add(new PasswordPolicy
                {
                    Domain = dns,
                    PolicyName = "PSO: " + (pso.GetString("cn") ?? pso.DistinguishedName),
                    IsDefaultDomainPolicy = false,
                    MinLength = pso.GetInt("msDS-MinimumPasswordLength"),
                    HistoryLength = pso.GetInt("msDS-PasswordHistoryLength"),
                    MaxAgeDays = LdapUtil.IntervalDays(pso.GetLong("msDS-MaximumPasswordAge")),
                    MinAgeDays = LdapUtil.IntervalDays(pso.GetLong("msDS-MinimumPasswordAge")),
                    LockoutThreshold = pso.GetInt("msDS-LockoutThreshold"),
                    LockoutUntilAdminUnlock = duration is 0 or long.MinValue,
                    LockoutDurationMinutes = LdapUtil.IntervalMinutes(duration),
                    LockoutObservationMinutes = LdapUtil.IntervalMinutes(pso.GetLong("msDS-LockoutObservationWindow")),
                    ComplexityEnabled = ParseBool(pso.GetString("msDS-PasswordComplexityEnabled")),
                    ReversibleEncryptionEnabled = ParseBool(pso.GetString("msDS-PasswordReversibleEncryptionEnabled")),
                    AppliesTo = pso.GetStrings("msDS-PSOAppliesTo")
                });
                psoCount++;
            }
        }
        catch (DirectoryQueryException ex) when (ex.IsPermissionDenied || LdapUtil.IsNoSuchObject(ex))
        {
            policies.Warn($"{dns}: Fine-Grained Password Policies were not enumerated ({(ex.IsPermissionDenied ? "insufficient permission" : "container does not exist")}).");
        }
        if (psoCount == 0)
            policies.Warn($"{dns}: no Fine-Grained Password Policy was returned (by default only privileged accounts can read them; absence is not proof that none exist).");
        policies.Succeeded(dns);
    }

    private static bool? ParseBool(string? s) =>
        s is null ? null : string.Equals(s, "TRUE", StringComparison.OrdinalIgnoreCase);
}
