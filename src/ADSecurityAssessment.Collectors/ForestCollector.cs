using ADSecurityAssessment.Collectors.Support;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Collectors;

/// <summary>Descobre a floresta: nome, nível funcional, schema, tombstoneLifetime, dSHeuristics e Lixeira do AD. Somente leitura.</summary>
public sealed class ForestCollector : CollectorBase
{
    public override string Id => "forest";
    public override string DisplayName => "Forest discovery";
    public override IReadOnlyList<string> Datasets { get; } = new[] { DatasetNames.Forest };

    public override Task<CollectorResult> CollectAsync(CollectionContext ctx, CancellationToken ct)
    {
        var tracker = new ScopeTracker();
        IDirectoryGateway gw;
        try { gw = OpenInitial(ctx); }
        catch (DirectoryQueryException ex)
        {
            ctx.Log.Error($"forest: could not connect: {ex.Message}");
            return Task.FromResult(CollectorResult.Failed(ex.Message));
        }

        using (gw)
        {
            var rd = gw.RootDse;
            var config = rd.ConfigurationNamingContext;
            var root = rd.RootDomainNamingContext;
            if (config is null || root is null)
                return Task.FromResult(CollectorResult.Failed("The RootDSE did not return configurationNamingContext/rootDomainNamingContext."));

            var forestName = LdapUtil.DnToDns(root);
            tracker.Succeeded("rootDSE");

            int? tombstone = null;
            string? dsHeuristics = null;
            var dsHeuristicsPresent = false;
            Try(ctx, tracker, "Directory Service object", () =>
            {
                var ds = gw.ReadEntry($"CN=Directory Service,CN=Windows NT,CN=Services,{config}",
                    new[] { "tombstoneLifetime", "dSHeuristics" }, ct);
                if (ds is null) throw new DirectoryQueryException("Object 'Directory Service' was not found.");
                tombstone = ds.GetInt("tombstoneLifetime");
                dsHeuristicsPresent = ds.Has("dSHeuristics");
                dsHeuristics = ds.GetString("dSHeuristics");
            });

            // A Lixeira está habilitada quando o objeto "Recycle Bin Feature" possui msDS-EnabledFeatureBL (escopos em que está habilitada).
            bool? recycleBin = null;
            Try(ctx, tracker, "Recycle Bin feature", () =>
            {
                var feature = gw.Search(new SearchSpec(
                    $"CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,{config}",
                    "(&(objectClass=msDS-OptionalFeature)(cn=Recycle Bin Feature))",
                    SearchScopeKind.OneLevel, new[] { "cn", "msDS-EnabledFeatureBL" }, 2), ct).FirstOrDefault();
                if (feature is null) throw new DirectoryQueryException("Optional feature 'Recycle Bin Feature' was not found.");
                recycleBin = feature.Has("msDS-EnabledFeatureBL");
            });

            int? schemaVersion = null;
            Try(ctx, tracker, "Schema version", () =>
            {
                schemaVersion = rd.SchemaNamingContext is null ? null
                    : gw.ReadEntry(rd.SchemaNamingContext, new[] { "objectVersion" }, ct)?.GetInt("objectVersion");
            });

            ctx.Builder.SetForest(new ForestInfo
            {
                Name = forestName,
                RootDomain = forestName,
                FunctionalLevel = rd.ForestFunctionality,
                SchemaVersion = schemaVersion,
                TombstoneLifetimeDays = tombstone,
                RecycleBinEnabled = recycleBin,
                DsHeuristics = dsHeuristics,
                DsHeuristicsAttributePresent = dsHeuristicsPresent,
                ConfigurationNamingContext = config
            });
            Publish(ctx, tracker, DatasetNames.Forest, Id);
            ctx.Log.Info($"forest: {forestName}, functional level {FunctionalLevelNames.Name(rd.ForestFunctionality)}, via {gw.Server}.");
            return Task.FromResult(tracker.ToResult(1));
        }
    }
}
