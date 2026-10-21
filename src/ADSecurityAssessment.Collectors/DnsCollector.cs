using System.Collections.Concurrent;
using System.Net;
using ADSecurityAssessment.Collectors.Support;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Collectors;

/// <summary>
/// DNS básico: resolve o nome DNS de cada DC a partir do host de assessment. (Registros SRV do localizador e a segurança das zonas
/// não são avaliados nesta versão: veja o dataset 'dns-zone-security', reportado como Not Evaluated.)
/// </summary>
public sealed class DnsCollector : CollectorBase
{
    public override string Id => "dns";
    public override string DisplayName => "DNS (DC host resolution)";
    public override IReadOnlyList<string> Datasets { get; } = new[] { DatasetNames.DnsChecks };
    public override IReadOnlyList<string> DependsOn { get; } = new[] { "domain-controllers" };

    public override async Task<CollectorResult> CollectAsync(CollectionContext ctx, CancellationToken ct)
    {
        var tracker = new ScopeTracker();
        var dcs = ctx.Builder.DomainControllers.ToArray();
        if (dcs.Length == 0) return CollectorResult.Failed("No domain controller was discovered.");

        var timeout = TimeSpan.FromSeconds(Math.Max(1, ctx.Settings.DnsResolutionTimeoutSeconds));
        var results = new ConcurrentBag<DnsCheckRecord>();

        await Parallel.ForEachAsync(dcs, new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct }, async (dc, token) =>
        {
            if (string.IsNullOrWhiteSpace(dc.DnsHostName))
            {
                results.Add(new DnsCheckRecord { Domain = dc.Domain, Kind = "HostResolution", Subject = dc.Name, Success = false, Detail = "The computer object has an empty dNSHostName attribute." });
                return;
            }
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                cts.CancelAfter(timeout);
                var addresses = await Dns.GetHostAddressesAsync(dc.DnsHostName, cts.Token).ConfigureAwait(false);
                results.Add(new DnsCheckRecord
                {
                    Domain = dc.Domain, Kind = "HostResolution", Subject = dc.DnsHostName,
                    Success = addresses.Length > 0,
                    Detail = addresses.Length > 0 ? string.Join(", ", addresses.Select(a => a.ToString())) : "No address was returned."
                });
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
            catch (OperationCanceledException)
            {
                results.Add(new DnsCheckRecord { Domain = dc.Domain, Kind = "HostResolution", Subject = dc.DnsHostName, Success = false, Detail = $"Name resolution timed out ({timeout.TotalSeconds:0}s)." });
            }
            catch (Exception ex) when (ex is System.Net.Sockets.SocketException or ArgumentException)
            {
                results.Add(new DnsCheckRecord { Domain = dc.Domain, Kind = "HostResolution", Subject = dc.DnsHostName, Success = false, Detail = ex.Message });
            }
        }).ConfigureAwait(false);

        foreach (var r in results.OrderBy(r => r.Domain, StringComparer.OrdinalIgnoreCase).ThenBy(r => r.Subject, StringComparer.OrdinalIgnoreCase))
            ctx.Builder.DnsChecks.Add(r);
        tracker.Succeeded("host resolution");
        Publish(ctx, tracker, DatasetNames.DnsChecks, Id);
        return tracker.ToResult(results.Count);
    }
}
