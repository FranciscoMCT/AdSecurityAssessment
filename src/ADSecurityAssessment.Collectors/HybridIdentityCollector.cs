using ADSecurityAssessment.Collectors.Support;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Collectors;

/// <summary>
/// Procura EVIDÊNCIAS de identidade híbrida: o computador AZUREADSSOACC (Seamless SSO) e contas de sincronização MSOL_*/AAD_* (Microsoft Entra Connect).
/// Sem evidências, nenhum indicador é publicado e as regras híbridas ficam Not Applicable.
/// </summary>
public sealed class HybridIdentityCollector : CollectorBase
{
    public override string Id => "hybrid";
    public override string DisplayName => "Hybrid identity (Entra Connect / Seamless SSO indicators)";
    public override IReadOnlyList<string> Datasets { get; } = new[] { DatasetNames.HybridIndicators };
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
                foreach (var e in gw.Search(new SearchSpec(domain.DistinguishedName!,
                    "(&(objectCategory=computer)(sAMAccountName=AZUREADSSOACC$))", SearchScopeKind.Subtree,
                    new[] { "sAMAccountName", "userAccountControl", "pwdLastSet", "msDS-AllowedToActOnBehalfOfOtherIdentity" }, 5), ct))
                {
                    ctx.Builder.HybridIndicators.Add(new HybridIndicator
                    {
                        Domain = domain.Name, Kind = "SeamlessSsoAccount", ObjectName = e.GetString("sAMAccountName") ?? "AZUREADSSOACC$",
                        DistinguishedName = e.DistinguishedName, UserAccountControl = e.GetInt("userAccountControl") ?? 0,
                        PasswordLastSet = e.GetFileTime("pwdLastSet"),
                        HasAllowedToActOnBehalf = e.GetBytes("msDS-AllowedToActOnBehalfOfOtherIdentity") is { Length: > 0 }
                    });
                    total++;
                }
                // Contas de sincronização criadas pelo Microsoft Entra Connect (padrões de nome MSOL_* e AAD_*).
                foreach (var e in gw.Search(new SearchSpec(domain.DistinguishedName!,
                    "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=MSOL_*)(sAMAccountName=AAD_*)))", SearchScopeKind.Subtree,
                    new[] { "sAMAccountName", "userAccountControl", "pwdLastSet" }, 50), ct))
                {
                    ctx.Builder.HybridIndicators.Add(new HybridIndicator
                    {
                        Domain = domain.Name, Kind = "EntraConnectSyncAccount", ObjectName = e.GetString("sAMAccountName") ?? e.DistinguishedName,
                        DistinguishedName = e.DistinguishedName, UserAccountControl = e.GetInt("userAccountControl") ?? 0,
                        PasswordLastSet = e.GetFileTime("pwdLastSet")
                    });
                    total++;
                }
            });
        }
        Publish(ctx, tracker, DatasetNames.HybridIndicators, Id);
        return Task.FromResult(tracker.ToResult(total));
    }
}
