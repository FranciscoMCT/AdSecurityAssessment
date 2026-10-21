using ADSecurityAssessment.Collectors.Support;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Collectors;

/// <summary>
/// Confianças de cada domínio (objetos trustedDomain via LDAP) + tipo e SID filtering via System.DirectoryServices.ActiveDirectory.
/// Se o tipo/SID filtering de uma confiança não puder ser determinado, o escopo é marcado como falho (regra → Not Evaluated).
/// </summary>
public sealed class TrustCollector : CollectorBase
{
    public override string Id => "trusts";
    public override string DisplayName => "Trusts";
    public override IReadOnlyList<string> Datasets { get; } = new[] { DatasetNames.Trusts };
    public override IReadOnlyList<string> DependsOn { get; } = new[] { "domain" };

    public override Task<CollectorResult> CollectAsync(CollectionContext ctx, CancellationToken ct)
    {
        var domains = ctx.Builder.Domains.ToArray();
        if (domains.Length == 0) return Task.FromResult(NoDomains());

        var tracker = new ScopeTracker();
        var total = 0;
        var forestName = ctx.Builder.Forest?.Name ?? domains.FirstOrDefault(d => d.IsForestRoot)?.Name ?? domains[0].Name;

        foreach (var domain in domains)
        {
            ct.ThrowIfCancellationRequested();
            Try(ctx, tracker, domain.Name, () =>
            {
                List<LdapEntry> entries;
                using (var gw = OpenDomain(ctx, domain))
                    entries = gw.Search(new SearchSpec($"CN=System,{domain.DistinguishedName}", "(objectClass=trustedDomain)", SearchScopeKind.OneLevel,
                        new[] { "name", "trustPartner", "flatName", "trustDirection", "trustType", "trustAttributes", "whenCreated" }), ct).ToList();
                if (entries.Count == 0) return;

                IReadOnlyDictionary<string, string>? types = null;
                string? typeError = null;
                try { types = DirectoryServicesApi.GetTrustTypes(domain.Name, ctx.Connection); }
                catch (Exception ex) when (ex is not OperationCanceledException and not OutOfMemoryException) { typeError = $"{ex.GetType().Name}: {ex.Message}"; }

                var unresolved = new List<string>();
                foreach (var e in entries)
                {
                    var partner = e.GetString("trustPartner") ?? e.GetString("name") ?? e.DistinguishedName;
                    string? classification = null;
                    if (types is not null && types.TryGetValue(partner, out var t)) classification = t;

                    bool? sid = null;
                    string? note = null;
                    if (classification is "External" or "Forest")
                    {
                        try { sid = DirectoryServicesApi.GetSidFiltering(domain.Name, forestName, partner, classification, ctx.Connection); }
                        catch (Exception ex) when (ex is not OperationCanceledException and not OutOfMemoryException)
                        {
                            note = $"SID filtering could not be determined: {ex.GetType().Name}: {ex.Message}";
                            unresolved.Add($"{partner}: {note}");
                        }
                    }
                    else if (classification is null) unresolved.Add($"{partner}: trust type could not be determined{(typeError is null ? "" : " (" + typeError + ")")}");

                    ctx.Builder.Trusts.Add(new TrustRecord
                    {
                        Domain = domain.Name,
                        Partner = partner,
                        Direction = e.GetInt("trustDirection") ?? 0,
                        TrustType = e.GetInt("trustType") ?? 0,
                        TrustAttributes = e.GetInt("trustAttributes") ?? 0,
                        Classification = classification,
                        SidFilteringEnabled = sid,
                        SidFilteringNote = note,
                        WhenCreated = e.GetGeneralizedTime("whenCreated")
                    });
                    total++;
                }
                if (unresolved.Count > 0) throw new DirectoryQueryException(string.Join("; ", unresolved));
            });
        }
        Publish(ctx, tracker, DatasetNames.Trusts, Id);
        return Task.FromResult(tracker.ToResult(total));
    }
}
