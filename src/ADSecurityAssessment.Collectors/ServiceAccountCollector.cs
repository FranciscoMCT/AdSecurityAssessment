using ADSecurityAssessment.Collectors.Support;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Collectors;

/// <summary>Contas de serviço gerenciadas (gMSA/sMSA). O atributo msDS-ManagedPassword NUNCA é lido (bloqueado no gateway).</summary>
public sealed class ServiceAccountCollector : CollectorBase
{
    public override string Id => "service-accounts";
    public override string DisplayName => "Managed service accounts (gMSA/sMSA)";
    public override IReadOnlyList<string> Datasets { get; } = new[] { DatasetNames.ManagedServiceAccounts };
    public override IReadOnlyList<string> DependsOn { get; } = new[] { "domain" };

    public override Task<CollectorResult> CollectAsync(CollectionContext ctx, CancellationToken ct)
    {
        var domains = ctx.Builder.Domains.ToArray();
        if (domains.Length == 0) return Task.FromResult(NoDomains());

        var tracker = new ScopeTracker();
        var total = 0;
        foreach (var domain in domains)
        {
            ct.ThrowIfCancellationRequested();
            Try(ctx, tracker, domain.Name, () =>
            {
                using var gw = OpenDomain(ctx, domain);
                foreach (var e in gw.Search(new SearchSpec(domain.DistinguishedName!, "(objectClass=msDS-ManagedServiceAccount)", SearchScopeKind.Subtree,
                    new[] { "sAMAccountName", "objectClass", "msDS-ManagedPasswordInterval" }), ct))
                {
                    var isGmsa = e.GetStrings("objectClass").Contains("msDS-GroupManagedServiceAccount", StringComparer.OrdinalIgnoreCase);
                    ctx.Builder.ManagedServiceAccounts.Add(new ManagedServiceAccount
                    {
                        Domain = domain.Name,
                        Name = e.GetString("sAMAccountName") ?? e.DistinguishedName,
                        DistinguishedName = e.DistinguishedName,
                        Kind = isGmsa ? "gMSA" : "sMSA",
                        ManagedPasswordIntervalDays = e.GetInt("msDS-ManagedPasswordInterval")
                    });
                    total++;
                }
            });
        }
        Publish(ctx, tracker, DatasetNames.ManagedServiceAccounts, Id);
        return Task.FromResult(tracker.ToResult(total));
    }
}
