using ADSecurityAssessment.Collectors.Support;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Collectors;

/// <summary>
/// Grupos privilegiados e seus membros (diretos e aninhados): Domain/Enterprise/Schema Admins, Administrators, Account/Server/Print/Backup
/// Operators e Protected Users. Os grupos são localizados pelo SID/RID (independe do idioma do SO). Membros de outros domínios
/// (foreignSecurityPrincipal) são resolvidos por SID nos domínios conhecidos da floresta.
/// </summary>
public sealed class PrivilegedAccountCollector : CollectorBase
{
    private const int MaxDepth = 10;
    private const int MaxMembersPerDomain = 100_000;

    public override string Id => "privileged-accounts";
    public override string DisplayName => "Privileged groups and members";
    public override IReadOnlyList<string> Datasets { get; } = new[] { DatasetNames.PrivilegedMemberships };
    public override IReadOnlyList<string> DependsOn { get; } = new[] { "domain" };

    private sealed record GroupDef(string Key, string Name, string Sid, bool ForestRootOnly = false);

    private sealed record Resolved(string Name, string? Dn, string? Sid, string Class, IReadOnlyList<string> Classes);

    public override Task<CollectorResult> CollectAsync(CollectionContext ctx, CancellationToken ct)
    {
        var domains = ctx.Builder.Domains.ToArray();
        if (domains.Length == 0) return Task.FromResult(NoDomains());

        var tracker = new ScopeTracker();
        var gateways = new Dictionary<string, IDirectoryGateway>(StringComparer.OrdinalIgnoreCase);
        var rows = 0;
        try
        {
            var rootSid = domains.FirstOrDefault(d => d.IsForestRoot)?.Sid;
            foreach (var domain in domains)
            {
                ct.ThrowIfCancellationRequested();
                if (domain.Sid is null) { tracker.Fail(domain.Name, "The domain SID is unknown."); continue; }
                var gw = Gateway(ctx, gateways, domain);
                if (gw is null) { tracker.Fail(domain.Name, "could not connect to the domain."); continue; }

                foreach (var group in GroupDefinitions(domain, rootSid))
                {
                    var scope = $"{group.Name}@{domain.Name}";
                    Try(ctx, tracker, scope, () => rows += CollectGroup(ctx, gateways, domains, domain, gw, group, ct));
                }
            }
        }
        finally { foreach (var g in gateways.Values) g.Dispose(); }

        Publish(ctx, tracker, DatasetNames.PrivilegedMemberships, Id);
        return Task.FromResult(tracker.ToResult(rows));
    }

    private static IEnumerable<GroupDef> GroupDefinitions(DomainInfo domain, string? rootSid)
    {
        yield return new("DomainAdmins", "Domain Admins", $"{domain.Sid}-{WellKnownRids.DomainAdmins}");
        if (domain.IsForestRoot && rootSid is not null)
        {
            yield return new("EnterpriseAdmins", "Enterprise Admins", $"{rootSid}-{WellKnownRids.EnterpriseAdmins}", true);
            yield return new("SchemaAdmins", "Schema Admins", $"{rootSid}-{WellKnownRids.SchemaAdmins}", true);
        }
        yield return new("Administrators", "Administrators", WellKnownRids.BuiltinAdministrators);
        yield return new("AccountOperators", "Account Operators", WellKnownRids.BuiltinAccountOperators);
        yield return new("ServerOperators", "Server Operators", WellKnownRids.BuiltinServerOperators);
        yield return new("PrintOperators", "Print Operators", WellKnownRids.BuiltinPrintOperators);
        yield return new("BackupOperators", "Backup Operators", WellKnownRids.BuiltinBackupOperators);
        yield return new("ProtectedUsers", "Protected Users", $"{domain.Sid}-{WellKnownRids.ProtectedUsers}");
    }

    private IDirectoryGateway? Gateway(CollectionContext ctx, Dictionary<string, IDirectoryGateway> cache, DomainInfo domain)
    {
        if (cache.TryGetValue(domain.Name, out var existing)) return existing;
        try { return cache[domain.Name] = OpenDomain(ctx, domain); }
        catch (DirectoryQueryException ex) { ctx.Log.Warn($"{Id}: connection to {domain.Name} failed: {ex.Message}"); return null; }
    }

    private int CollectGroup(CollectionContext ctx, Dictionary<string, IDirectoryGateway> gateways, DomainInfo[] domains,
        DomainInfo domain, IDirectoryGateway gw, GroupDef group, CancellationToken ct)
    {
        var groupEntry = gw.Search(new SearchSpec(domain.DistinguishedName!, $"(objectSid={LdapUtil.SidFilterValue(group.Sid)})",
            SearchScopeKind.Subtree, new[] { "sAMAccountName" }, 1), ct).FirstOrDefault();
        if (groupEntry is null) return 0; // grupo inexistente neste domínio (ex.: Protected Users em domínio antigo) — não é erro.

        var count = 0;
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { groupEntry.DistinguishedName };
        var queue = new Queue<(string GroupDn, string GroupName, int Depth, bool Direct)>();
        queue.Enqueue((groupEntry.DistinguishedName, group.Name, 0, true));
        var knownUsers = ctx.Builder.Users.Where(u => u.DistinguishedName is not null)
            .GroupBy(u => u.DistinguishedName!, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        while (queue.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (groupDn, groupName, depth, direct) = queue.Dequeue();
            var owner = groupDn.Equals(groupEntry.DistinguishedName, StringComparison.OrdinalIgnoreCase) ? null : groupName;
            var groupGateway = GatewayForDn(ctx, gateways, domains, groupDn) ?? gw; // grupo aninhado pode estar em outro domínio
            foreach (var memberDn in LdapUtil.ReadRanged(groupGateway, groupDn, "member", ct))
            {
                if (count >= MaxMembersPerDomain) throw new DirectoryQueryException($"Member limit ({MaxMembersPerDomain:N0}) reached in {group.Name}.");
                var m = ResolveMember(ctx, gateways, domains, domain, gw, memberDn, knownUsers, ct);
                ctx.Builder.PrivilegedMemberships.Add(new PrivilegedMembership
                {
                    Domain = domain.Name,
                    GroupName = group.Name,
                    GroupKey = group.Key,
                    GroupDn = groupEntry.DistinguishedName,
                    MemberName = m.Name,
                    MemberDn = m.Dn ?? memberDn,
                    MemberSid = m.Sid,
                    MemberClass = m.Class,
                    IsDirect = direct,
                    ViaGroup = owner
                });
                count++;
                // Aninhamento: grupos dentro do grupo (mesmo domínio ou outro domínio conhecido).
                if (m.Classes.Contains("group", StringComparer.OrdinalIgnoreCase) && m.Dn is not null && depth < MaxDepth && visited.Add(m.Dn))
                    queue.Enqueue((m.Dn, m.Name, depth + 1, false));
            }
        }
        return count;
    }

    private IDirectoryGateway? GatewayForDn(CollectionContext ctx, Dictionary<string, IDirectoryGateway> gateways, DomainInfo[] domains, string dn)
    {
        var name = LdapUtil.DnToDns(dn);
        var d = domains.FirstOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        return d is null ? null : Gateway(ctx, gateways, d);
    }

    private Resolved ResolveMember(CollectionContext ctx, Dictionary<string, IDirectoryGateway> gateways, DomainInfo[] domains,
        DomainInfo groupDomain, IDirectoryGateway groupGateway, string memberDn, Dictionary<string, UserRecord> knownUsers, CancellationToken ct)
    {
        if (knownUsers.TryGetValue(memberDn, out var u))
            return new Resolved(u.SamAccountName, u.DistinguishedName, u.Sid, "user", new[] { "user" });

        var memberDomainName = LdapUtil.DnToDns(memberDn);
        var memberDomain = domains.FirstOrDefault(d => d.Name.Equals(memberDomainName, StringComparison.OrdinalIgnoreCase));
        var gw = memberDomain is null ? groupGateway : Gateway(ctx, gateways, memberDomain) ?? groupGateway;

        try
        {
            var e = gw.ReadEntry(memberDn, new[] { "objectClass", "sAMAccountName", "objectSid", "cn" }, ct);
            if (e is not null)
            {
                var classes = e.GetStrings("objectClass");
                if (classes.Contains("foreignSecurityPrincipal", StringComparer.OrdinalIgnoreCase))
                    return ResolveForeign(ctx, gateways, domains, e, memberDn, ct);
                return new Resolved(e.GetString("sAMAccountName") ?? e.GetString("cn") ?? memberDn, e.DistinguishedName, e.GetSid("objectSid"),
                    classes.LastOrDefault() ?? "unknown", classes);
            }
        }
        catch (DirectoryQueryException ex)
        {
            ctx.Log.Warn($"{Id}: member '{memberDn}' could not be resolved: {ex.Message}");
        }
        return new Resolved(LdapUtil.RdnValue(memberDn, 0) ?? memberDn, memberDn, null, "unresolved", Array.Empty<string>());
    }

    /// <summary>Procura, nos domínios conhecidos, o objeto cujo SID é o nome do foreignSecurityPrincipal.</summary>
    private Resolved ResolveForeign(CollectionContext ctx, Dictionary<string, IDirectoryGateway> gateways, DomainInfo[] domains,
        LdapEntry fsp, string fspDn, CancellationToken ct)
    {
        var sid = fsp.GetSid("objectSid") ?? fsp.GetString("cn");
        if (sid is not null && sid.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var d in domains)
            {
                var gw = Gateway(ctx, gateways, d);
                if (gw is null) continue;
                try
                {
                    var hit = gw.Search(new SearchSpec(d.DistinguishedName!, $"(objectSid={LdapUtil.SidFilterValue(sid)})",
                        SearchScopeKind.Subtree, new[] { "objectClass", "sAMAccountName" }, 1), ct).FirstOrDefault();
                    if (hit is not null)
                    {
                        var classes = hit.GetStrings("objectClass");
                        return new Resolved(hit.GetString("sAMAccountName") ?? sid, hit.DistinguishedName, sid, classes.LastOrDefault() ?? "unknown", classes);
                    }
                }
                catch (DirectoryQueryException) { /* tenta o próximo domínio */ }
            }
        }
        return new Resolved(sid ?? fspDn, fspDn, sid, "foreignSecurityPrincipal", new[] { "foreignSecurityPrincipal" });
    }
}
