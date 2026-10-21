using ADSecurityAssessment.Collectors.Support;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Collectors;

/// <summary>
/// Detecta Autoridades Certificadoras Enterprise (objetos pKIEnrollmentService em Public Key Services). Não assume que o AD CS existe:
/// container ausente ou vazio = nenhuma CA. Análise de modelos/ACLs não faz parte desta versão.
/// </summary>
public sealed class AdcsCollector : CollectorBase
{
    public override string Id => "adcs";
    public override string DisplayName => "AD CS detection";
    public override IReadOnlyList<string> Datasets { get; } = new[] { DatasetNames.CertificationAuthorities };
    public override IReadOnlyList<string> DependsOn { get; } = new[] { "forest" };

    public override Task<CollectorResult> CollectAsync(CollectionContext ctx, CancellationToken ct)
    {
        var tracker = new ScopeTracker();
        var count = 0;
        try
        {
            using var gw = OpenInitial(ctx);
            var config = gw.RootDse.ConfigurationNamingContext ?? throw new DirectoryQueryException("Configuration NC desconhecido.");
            try
            {
                foreach (var e in gw.Search(new SearchSpec($"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config}",
                    "(objectClass=pKIEnrollmentService)", SearchScopeKind.OneLevel, new[] { "cn", "dNSHostName", "certificateTemplates" }), ct))
                {
                    ctx.Builder.CertificationAuthorities.Add(new CertificationAuthorityRecord
                    {
                        Name = e.GetString("cn") ?? e.DistinguishedName,
                        DnsHostName = e.GetString("dNSHostName"),
                        DistinguishedName = e.DistinguishedName,
                        PublishedTemplates = e.GetStrings("certificateTemplates").Count
                    });
                    count++;
                }
            }
            catch (DirectoryQueryException ex) when (LdapUtil.IsNoSuchObject(ex))
            {
                ctx.Log.Info("adcs: container 'Enrollment Services' does not exist — no Enterprise CA is registered in AD.");
            }
            tracker.Succeeded("Enrollment Services");
        }
        catch (DirectoryQueryException ex) { tracker.Fail("Enrollment Services", ex.Message); }

        Publish(ctx, tracker, DatasetNames.CertificationAuthorities, Id);
        return Task.FromResult(tracker.ToResult(count));
    }
}
