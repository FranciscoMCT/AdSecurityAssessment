using System.Collections.Concurrent;
using ADSecurityAssessment.Collectors.Support;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Collectors;

/// <summary>
/// Domain Controllers (identificação, SO, GC, RODC, site, alcançabilidade, relógio, SYSVOL DFSR/FRS), papéis FSMO e sites/subnets.
/// Falha ao sondar um DC não cancela a coleta: o DC aparece como Reachable=false com o motivo.
/// </summary>
public sealed class DomainControllerCollector : CollectorBase
{
    private const int MaxParallelProbes = 4;

    public override string Id => "domain-controllers";
    public override string DisplayName => "Domain Controllers, FSMO and Sites";
    public override IReadOnlyList<string> Datasets { get; } = new[] { DatasetNames.DomainControllers, DatasetNames.FsmoRoles, DatasetNames.Sites };
    public override IReadOnlyList<string> DependsOn { get; } = new[] { "domain" };

    public override async Task<CollectorResult> CollectAsync(CollectionContext ctx, CancellationToken ct)
    {
        var domains = ctx.Builder.Domains.ToArray();
        if (domains.Length == 0) return NoDomains();

        var dcTracker = new ScopeTracker();
        var fsmoTracker = new ScopeTracker();
        var siteTracker = new ScopeTracker();
        var found = new List<DomainControllerInfo>();
        var pendingRoles = new List<(string Role, string? Domain, string OwnerNtdsDn)>();
        string? configNc = null;

        foreach (var domain in domains)
        {
            ct.ThrowIfCancellationRequested();
            IDirectoryGateway gw;
            try { gw = OpenDomain(ctx, domain); }
            catch (DirectoryQueryException ex)
            {
                dcTracker.Fail(domain.Name, ex.Message);
                fsmoTracker.Fail(domain.Name, ex.Message);
                continue;
            }
            using (gw)
            {
                configNc ??= gw.RootDse.ConfigurationNamingContext;
                var config = gw.RootDse.ConfigurationNamingContext;

                Try(ctx, dcTracker, domain.Name, () => found.AddRange(DiscoverDomainControllers(gw, domain, config, ct)));
                Try(ctx, fsmoTracker, domain.Name, () => pendingRoles.AddRange(DiscoverDomainRoles(gw, domain, ct)));

                // Papéis de floresta: lidos uma vez (do primeiro domínio acessível).
                if (config is not null && !pendingRoles.Any(r => r.Domain is null))
                    Try(ctx, fsmoTracker, "forest roles", () => pendingRoles.AddRange(DiscoverForestRoles(gw, config, ct)));
            }
        }

        // ---- sondagem de cada DC (conexão própria, em paralelo limitado)
        var probed = new ConcurrentBag<DomainControllerInfo>();
        await Parallel.ForEachAsync(found, new ParallelOptions { MaxDegreeOfParallelism = MaxParallelProbes, CancellationToken = ct },
            (dc, token) =>
            {
                probed.Add(Probe(ctx, dc));
                return ValueTask.CompletedTask;
            }).ConfigureAwait(false);

        var finalList = probed.OrderBy(d => d.Domain, StringComparer.OrdinalIgnoreCase).ThenBy(d => d.Name, StringComparer.OrdinalIgnoreCase).ToList();
        foreach (var dc in finalList) ctx.Builder.DomainControllers.Add(dc);
        foreach (var dc in finalList.Where(d => !d.Reachable))
            dcTracker.Warn($"DC '{dc.Name}' is not reachable over LDAP: {dc.ReachabilityNote}");

        // ---- FSMO: resolver host do dono e verificar se é um DC descoberto
        var knownServers = new HashSet<string>(finalList.Select(d => d.ServerDn).Where(s => s is not null)!, StringComparer.OrdinalIgnoreCase);
        using (var lookup = TryOpen(ctx, domains.First()))
        {
            foreach (var (role, domainName, ntds) in pendingRoles)
            {
                var serverDn = LdapUtil.ParentDn(ntds);
                string? host = null;
                if (serverDn is not null && lookup is not null)
                {
                    try { host = lookup.ReadEntry(serverDn, new[] { "dNSHostName" }, ct)?.GetString("dNSHostName"); }
                    catch (DirectoryQueryException) { /* host é informativo */ }
                }
                host ??= serverDn is null ? null : LdapUtil.RdnValue(serverDn, 0);
                ctx.Builder.FsmoRoles.Add(new FsmoRole
                {
                    Role = role,
                    Domain = domainName,
                    OwnerServerDn = serverDn,
                    OwnerHostName = host,
                    OwnerIsKnownDc = serverDn is not null && knownServers.Contains(serverDn)
                });
            }
        }

        // ---- sites e subnets (partição Configuration, uma vez)
        if (configNc is not null)
        {
            Try(ctx, siteTracker, "sites", () =>
            {
                using var gw = OpenDomain(ctx, domains.First());
                CollectSites(ctx, gw, configNc, finalList, ct);
            });
        }
        else siteTracker.Fail("sites", "Configuration NC desconhecido.");

        // Se algum domínio falhou, NÃO sabemos se existem DCs adicionais → não é "completo".
        Publish(ctx, dcTracker, DatasetNames.DomainControllers, Id);
        Publish(ctx, fsmoTracker, DatasetNames.FsmoRoles, Id);
        Publish(ctx, siteTracker, DatasetNames.Sites, Id);

        var result = dcTracker.ToResult(finalList.Count);
        if (fsmoTracker.Failed.Count > 0 || siteTracker.Failed.Count > 0)
            result = CollectorResult.Partial(finalList.Count, dcTracker.Errors.Concat(fsmoTracker.Errors).Concat(siteTracker.Errors), dcTracker.Warnings);
        return result;
    }

    private static IDirectoryGateway? TryOpen(CollectionContext ctx, DomainInfo d)
    {
        try { return OpenDomain(ctx, d); } catch (DirectoryQueryException) { return null; }
    }

    // ------------------------------------------------------------------ descoberta
    private static IEnumerable<DomainControllerInfo> DiscoverDomainControllers(IDirectoryGateway gw, DomainInfo domain, string? config, CancellationToken ct)
    {
        var list = new List<DomainControllerInfo>();
        // primaryGroupID 516 = Domain Controllers; 521 = Read-only Domain Controllers.
        var entries = gw.Search(new SearchSpec(domain.DistinguishedName!,
            "(&(objectCategory=computer)(|(primaryGroupID=516)(primaryGroupID=521)))", SearchScopeKind.Subtree,
            new[] { "name", "dNSHostName", "operatingSystem", "operatingSystemVersion", "serverReferenceBL", "primaryGroupID" }), ct);
        foreach (var e in entries)
        {
            var serverDn = e.GetString("serverReferenceBL");
            string? site = null;
            var isGc = false;
            if (serverDn is not null)
            {
                // CN=<DC>,CN=Servers,CN=<Site>,CN=Sites,CN=Configuration,...
                site = LdapUtil.RdnValue(serverDn, 2);
                try
                {
                    var ntds = gw.ReadEntry($"CN=NTDS Settings,{serverDn}", new[] { "options" }, ct);
                    isGc = ((ntds?.GetInt("options") ?? 0) & 1) != 0; // NTDSDSA_OPT_IS_GC
                }
                catch (DirectoryQueryException) { /* GC desconhecido → false; informativo */ }
            }
            list.Add(new DomainControllerInfo
            {
                Name = e.GetString("name") ?? LdapUtil.RdnValue(e.DistinguishedName, 0) ?? e.DistinguishedName,
                Domain = domain.Name,
                DnsHostName = e.GetString("dNSHostName"),
                Site = site,
                OperatingSystem = e.GetString("operatingSystem"),
                OperatingSystemVersion = e.GetString("operatingSystemVersion"),
                IsReadOnly = e.GetInt("primaryGroupID") == WellKnownRids.ReadOnlyDomainControllers,
                IsGlobalCatalog = isGc,
                ComputerDn = e.DistinguishedName,
                ServerDn = serverDn
            });
        }
        return list;
    }

    private static IEnumerable<(string Role, string? Domain, string OwnerNtdsDn)> DiscoverDomainRoles(IDirectoryGateway gw, DomainInfo domain, CancellationToken ct)
    {
        var roles = new List<(string, string?, string)>();
        var head = gw.ReadEntry(domain.DistinguishedName!, new[] { "fSMORoleOwner", "rIDManagerReference" }, ct);
        if (head?.GetString("fSMORoleOwner") is { } pdc) roles.Add(("PDC Emulator", domain.Name, pdc));

        if (head?.GetString("rIDManagerReference") is { } ridManager &&
            gw.ReadEntry(ridManager, new[] { "fSMORoleOwner" }, ct)?.GetString("fSMORoleOwner") is { } rid)
            roles.Add(("RID Master", domain.Name, rid));

        if (gw.ReadEntry($"CN=Infrastructure,{domain.DistinguishedName}", new[] { "fSMORoleOwner" }, ct)?.GetString("fSMORoleOwner") is { } infra)
            roles.Add(("Infrastructure Master", domain.Name, infra));

        if (roles.Count == 0) throw new DirectoryQueryException($"No FSMO role could be read in {domain.Name}.");
        return roles;
    }

    private static IEnumerable<(string Role, string? Domain, string OwnerNtdsDn)> DiscoverForestRoles(IDirectoryGateway gw, string config, CancellationToken ct)
    {
        var roles = new List<(string, string?, string)>();
        if (gw.RootDse.SchemaNamingContext is { } schema &&
            gw.ReadEntry(schema, new[] { "fSMORoleOwner" }, ct)?.GetString("fSMORoleOwner") is { } sm)
            roles.Add(("Schema Master", null, sm));
        if (gw.ReadEntry($"CN=Partitions,{config}", new[] { "fSMORoleOwner" }, ct)?.GetString("fSMORoleOwner") is { } dnm)
            roles.Add(("Domain Naming Master", null, dnm));
        if (roles.Count == 0) throw new DirectoryQueryException("Forest-wide roles (Schema/Domain Naming Master) could not be read.");
        return roles;
    }

    private static void CollectSites(CollectionContext ctx, IDirectoryGateway gw, string config, IReadOnlyList<DomainControllerInfo> dcs, CancellationToken ct)
    {
        var sites = gw.Search(new SearchSpec($"CN=Sites,{config}", "(objectClass=site)", SearchScopeKind.OneLevel, new[] { "cn" }), ct).ToList();
        var subnetsBySite = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var subnet in gw.Search(new SearchSpec($"CN=Subnets,CN=Sites,{config}", "(objectClass=subnet)", SearchScopeKind.OneLevel, new[] { "siteObject" }), ct))
        {
            var site = subnet.GetString("siteObject");
            if (site is null) continue;
            subnetsBySite[site] = subnetsBySite.GetValueOrDefault(site) + 1;
        }
        foreach (var s in sites)
        {
            var name = s.GetString("cn") ?? s.DistinguishedName;
            ctx.Builder.Sites.Add(new SiteInfo
            {
                Name = name,
                DistinguishedName = s.DistinguishedName,
                SubnetCount = subnetsBySite.GetValueOrDefault(s.DistinguishedName),
                DomainControllerCount = dcs.Count(d => string.Equals(d.Site, name, StringComparison.OrdinalIgnoreCase))
            });
        }
    }

    // ------------------------------------------------------------------ sondagem por DC
    private static DomainControllerInfo Probe(CollectionContext ctx, DomainControllerInfo dc)
    {
        var host = dc.DnsHostName ?? dc.Name;
        try
        {
            using var gw = ctx.Gateways.Open(new GatewayTarget(host, dc.Domain));
            var domainDn = gw.RootDse.DefaultNamingContext;
            var (sysvol, evidence) = DetectSysvol(gw, dc);
            return dc with
            {
                Reachable = true,
                CurrentTime = gw.RootDse.CurrentTime,
                DomainControllerFunctionality = gw.RootDse.DomainControllerFunctionality,
                IsGlobalCatalog = dc.IsGlobalCatalog || gw.RootDse.IsGlobalCatalogReady,
                SysvolReplication = sysvol,
                SysvolEvidence = evidence
            };
        }
        catch (Exception ex) when (ex is DirectoryQueryException or InvalidOperationException)
        {
            ctx.Log.Warn($"DC {host}: sondagem falhou: {ex.Message}");
            return dc with { Reachable = false, ReachabilityNote = ex.Message };
        }
    }

    /// <summary>DFSR se existir o msDFSR-Subscription "SYSVOL Subscription"; FRS se só existir nTFRSSubscriber; senão Unknown.</summary>
    private static (string Engine, string Evidence) DetectSysvol(IDirectoryGateway gw, DomainControllerInfo dc)
    {
        if (dc.ComputerDn is null) return ("Unknown", "DN do computador desconhecido.");
        try
        {
            var dfsr = gw.Search(new SearchSpec(dc.ComputerDn,
                "(&(objectClass=msDFSR-Subscription)(cn=SYSVOL Subscription))", SearchScopeKind.Subtree, new[] { "cn" }, 1), CancellationToken.None).FirstOrDefault();
            if (dfsr is not null) return ("DFSR", $"msDFSR-Subscription: {dfsr.DistinguishedName}");
            var frs = gw.Search(new SearchSpec(dc.ComputerDn,
                "(objectClass=nTFRSSubscriber)", SearchScopeKind.Subtree, new[] { "cn" }, 1), CancellationToken.None).FirstOrDefault();
            if (frs is not null) return ("FRS", $"nTFRSSubscriber: {frs.DistinguishedName} (no msDFSR-Subscription 'SYSVOL Subscription' found)");
            return ("Unknown", "No DFSR/FRS subscription object was found under the computer object (this may be a read-permission limit).");
        }
        catch (DirectoryQueryException ex) { return ("Unknown", ex.Message); }
    }
}
