using ADSecurityAssessment.Collectors.Support;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Collectors;

/// <summary>Contas de usuário de cada domínio (consulta paginada). Atinge o limite configurado → coleta PARCIAL (nunca finge completude).</summary>
public sealed class UserCollector : CollectorBase
{
    private static readonly string[] Attributes =
    {
        "sAMAccountName", "objectSid", "objectClass", "userAccountControl", "pwdLastSet", "lastLogonTimestamp",
        "whenCreated", "adminCount", "servicePrincipalName"
    };

    public override string Id => "users";
    public override string DisplayName => "Users";
    public override IReadOnlyList<string> Datasets { get; } = new[] { DatasetNames.Users };
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
            var remaining = ctx.Settings.MaxObjectsPerQuery;
            Try(ctx, tracker, domain.Name, () =>
            {
                using var gw = OpenDomain(ctx, domain);
                var count = 0;
                // objectCategory=person + objectClass=user: contas de usuário (computadores e gMSA têm outra categoria).
                foreach (var e in gw.Search(new SearchSpec(domain.DistinguishedName!, "(&(objectCategory=person)(objectClass=user))",
                    SearchScopeKind.Subtree, Attributes), ct))
                {
                    if (count >= remaining)
                        throw new DirectoryQueryException($"Limit of {remaining:N0} objects reached; user collection truncated (increase MaxObjectsPerQuery in config/settings.json).");
                    var sam = e.GetString("sAMAccountName");
                    if (sam is null) continue;
                    ctx.Builder.Users.Add(new UserRecord
                    {
                        Domain = domain.Name,
                        SamAccountName = sam,
                        DistinguishedName = e.DistinguishedName,
                        Sid = e.GetSid("objectSid"),
                        ObjectClass = LdapUtil.LastClass(e) ?? "user",
                        UserAccountControl = e.GetInt("userAccountControl") ?? 0,
                        PasswordLastSet = e.GetFileTime("pwdLastSet"),
                        LastLogonTimestamp = e.GetFileTime("lastLogonTimestamp"),
                        WhenCreated = e.GetGeneralizedTime("whenCreated"),
                        AdminCount = e.GetInt("adminCount"),
                        ServicePrincipalNames = e.GetStrings("servicePrincipalName")
                    });
                    count++;
                    if (count % 5000 == 0) ctx.Report?.Invoke($"Users ({domain.Name}): {count:N0}…");
                }
                total += count;
                ctx.Log.Info($"users/{domain.Name}: {count:N0} accounts.");
            });
        }
        Publish(ctx, tracker, DatasetNames.Users, Id);
        return Task.FromResult(tracker.ToResult(total));
    }
}
