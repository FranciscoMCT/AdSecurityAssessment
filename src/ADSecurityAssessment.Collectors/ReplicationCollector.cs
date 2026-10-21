using System.Collections.Concurrent;
using ADSecurityAssessment.Collectors.Support;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Collectors;

/// <summary>Vizinhos de replicação de entrada de cada DC (System.DirectoryServices.ActiveDirectory), com timeout por DC.</summary>
public sealed class ReplicationCollector : CollectorBase
{
    public override string Id => "replication";
    public override string DisplayName => "Replication health";
    public override IReadOnlyList<string> Datasets { get; } = new[] { DatasetNames.ReplicationLinks };
    public override IReadOnlyList<string> DependsOn { get; } = new[] { "domain-controllers" };

    public override async Task<CollectorResult> CollectAsync(CollectionContext ctx, CancellationToken ct)
    {
        var tracker = new ScopeTracker();
        var dcs = ctx.Builder.DomainControllers.ToArray();
        if (dcs.Length == 0) return CollectorResult.Failed("No domain controller was discovered.");

        var links = new ConcurrentBag<ReplicationLink>();
        var gate = new object();
        var timeout = TimeSpan.FromSeconds(Math.Max(10, ctx.Settings.QueryTimeoutSeconds));

        await Parallel.ForEachAsync(dcs, new ParallelOptions { MaxDegreeOfParallelism = 4, CancellationToken = ct }, async (dc, token) =>
        {
            var name = dc.DnsHostName ?? dc.Name;
            if (!dc.Reachable)
            {
                lock (gate) tracker.Fail(name, "DC is not reachable; replication topology was not read.");
                return;
            }
            try
            {
                // As APIs de replicação não aceitam timeout: executa em thread própria e abandona se exceder.
                var result = await Task.Run(() => DirectoryServicesApi.GetInboundReplication(dc, ctx.Connection), token)
                    .WaitAsync(timeout, token).ConfigureAwait(false);
                foreach (var l in result) links.Add(l);
                lock (gate) tracker.Succeeded(name);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
            catch (TimeoutException) { lock (gate) tracker.Fail(name, $"timed out ({timeout.TotalSeconds:0}s) while reading replication neighbors."); }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                lock (gate) tracker.Fail(name, $"{ex.GetType().Name}: {ex.Message}");
                ctx.Log.Warn($"replication/{name}: {ex.GetType().Name}: {ex.Message}");
            }
        }).ConfigureAwait(false);

        foreach (var l in links.OrderBy(l => l.DestinationServer, StringComparer.OrdinalIgnoreCase).ThenBy(l => l.NamingContext, StringComparer.OrdinalIgnoreCase))
            ctx.Builder.ReplicationLinks.Add(l);
        Publish(ctx, tracker, DatasetNames.ReplicationLinks, Id);
        return tracker.ToResult(links.Count);
    }
}
