using ADSecurityAssessment.Collectors.Support;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Collectors;

/// <summary>Detecta se o schema possui os atributos de Windows LAPS / LAPS legado e resume a cobertura por domínio (sem ler senhas).</summary>
public sealed class LapsCollector : CollectorBase
{
    public override string Id => "laps";
    public override string DisplayName => "Windows LAPS (schema + coverage)";
    public override IReadOnlyList<string> Datasets { get; } = new[] { DatasetNames.LapsInfo };
    public override IReadOnlyList<string> DependsOn { get; } = new[] { "domain" };

    public override Task<CollectorResult> CollectAsync(CollectionContext ctx, CancellationToken ct)
    {
        var domains = ctx.Builder.Domains.ToArray();
        if (domains.Length == 0) return Task.FromResult(NoDomains());

        var tracker = new ScopeTracker();
        bool windowsLaps = false, legacyLaps = false;
        var schemaOk = Try(ctx, tracker, "schema", () =>
        {
            using var gw = OpenDomain(ctx, domains[0]);
            var schema = gw.RootDse.SchemaNamingContext ?? throw new DirectoryQueryException("Schema NC desconhecido.");
            foreach (var e in gw.Search(new SearchSpec(schema,
                "(&(objectClass=attributeSchema)(|(lDAPDisplayName=msLAPS-PasswordExpirationTime)(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)))",
                SearchScopeKind.OneLevel, new[] { "lDAPDisplayName" }, 5), ct))
            {
                var name = e.GetString("lDAPDisplayName");
                if (string.Equals(name, "msLAPS-PasswordExpirationTime", StringComparison.OrdinalIgnoreCase)) windowsLaps = true;
                if (string.Equals(name, "ms-Mcs-AdmPwdExpirationTime", StringComparison.OrdinalIgnoreCase)) legacyLaps = true;
            }
        });
        if (!schemaOk) { Publish(ctx, tracker, DatasetNames.LapsInfo, Id); return Task.FromResult(tracker.ToResult(0)); }

        var computersState = ctx.Builder.TryGetState(DatasetNames.Computers);
        if (computersState is null || computersState.Coverage != DatasetCoverage.Complete)
            tracker.Warn("LAPS coverage counts may be incomplete: the 'computers' dataset is not complete.");

        foreach (var d in domains)
        {
            var eligible = ctx.Builder.Computers.Where(c => c.Domain.Equals(d.Name, StringComparison.OrdinalIgnoreCase) && c.Enabled && !c.IsDomainController).ToList();
            ctx.Builder.LapsInfo.Add(new LapsInfo
            {
                Domain = d.Name,
                WindowsLapsSchemaPresent = windowsLaps,
                LegacyLapsSchemaPresent = legacyLaps,
                EligibleComputers = eligible.Count,
                ComputersWithExpirationValue = eligible.Count(c => c.HasLapsExpiration)
            });
        }
        Publish(ctx, tracker, DatasetNames.LapsInfo, Id);
        return Task.FromResult(tracker.ToResult(domains.Length));
    }
}
