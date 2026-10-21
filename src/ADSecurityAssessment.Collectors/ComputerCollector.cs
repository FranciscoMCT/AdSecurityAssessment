using ADSecurityAssessment.Collectors.Support;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Collectors;

/// <summary>
/// Contas de computador (SO, atividade, delegação, expiração de senha LAPS). Lê apenas a DATA de expiração do LAPS
/// (msLAPS-PasswordExpirationTime / ms-Mcs-AdmPwdExpirationTime) — NUNCA os atributos de senha (bloqueados no gateway).
/// </summary>
public sealed class ComputerCollector : CollectorBase
{
    private static readonly string[] Attributes =
    {
        "name", "dNSHostName", "objectSid", "userAccountControl", "operatingSystem", "operatingSystemVersion", "lastLogonTimestamp",
        "pwdLastSet", "whenCreated", "primaryGroupID", "msLAPS-PasswordExpirationTime", "ms-Mcs-AdmPwdExpirationTime"
    };

    public override string Id => "computers";
    public override string DisplayName => "Computers";
    public override IReadOnlyList<string> Datasets { get; } = new[] { DatasetNames.Computers };
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
            var limit = ctx.Settings.MaxObjectsPerQuery;
            Try(ctx, tracker, domain.Name, () =>
            {
                using var gw = OpenDomain(ctx, domain);
                var count = 0;
                foreach (var e in gw.Search(new SearchSpec(domain.DistinguishedName!, "(objectCategory=computer)", SearchScopeKind.Subtree, Attributes), ct))
                {
                    if (count >= limit)
                        throw new DirectoryQueryException($"Limit of {limit:N0} objects reached; computer collection truncated (increase MaxObjectsPerQuery).");
                    ctx.Builder.Computers.Add(new ComputerRecord
                    {
                        Domain = domain.Name,
                        Name = e.GetString("name") ?? LdapUtil.RdnValue(e.DistinguishedName, 0) ?? e.DistinguishedName,
                        DnsHostName = e.GetString("dNSHostName"),
                        DistinguishedName = e.DistinguishedName,
                        Sid = e.GetSid("objectSid"),
                        UserAccountControl = e.GetInt("userAccountControl") ?? 0,
                        OperatingSystem = e.GetString("operatingSystem"),
                        OperatingSystemVersion = e.GetString("operatingSystemVersion"),
                        LastLogonTimestamp = e.GetFileTime("lastLogonTimestamp"),
                        PasswordLastSet = e.GetFileTime("pwdLastSet"),
                        WhenCreated = e.GetGeneralizedTime("whenCreated"),
                        WindowsLapsExpiration = e.GetFileTime("msLAPS-PasswordExpirationTime"),
                        LegacyLapsExpiration = e.GetFileTime("ms-Mcs-AdmPwdExpirationTime"),
                        PrimaryGroupId = e.GetInt("primaryGroupID")
                    });
                    count++;
                    if (count % 5000 == 0) ctx.Report?.Invoke($"Computers ({domain.Name}): {count:N0}…");
                }
                total += count;
                ctx.Log.Info($"computers/{domain.Name}: {count:N0} accounts.");
            });
        }
        Publish(ctx, tracker, DatasetNames.Computers, Id);
        return Task.FromResult(tracker.ToResult(total));
    }
}
