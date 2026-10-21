using System.DirectoryServices.ActiveDirectory;
using System.Net;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Collectors.Support;

/// <summary>
/// Chamadas SOMENTE LEITURA às APIs System.DirectoryServices.ActiveDirectory (vizinhos de replicação, tipo de confiança,
/// status de SID filtering). Nenhum método Set*/Create*/Delete*/Update*/Sync*/Trigger* é usado (garantido por teste).
/// </summary>
internal static class DirectoryServicesApi
{
    private static DirectoryContext Context(DirectoryContextType type, string name, ConnectionInfo connection)
    {
        var cred = connection.CreateCredential();
        return cred is null
            ? new DirectoryContext(type, name)
            : new DirectoryContext(type, name, Qualified(cred), cred.Password);
    }

    private static string Qualified(NetworkCredential c) => string.IsNullOrEmpty(c.Domain) ? c.UserName : $"{c.Domain}\\{c.UserName}";

    public static IReadOnlyList<ReplicationLink> GetInboundReplication(DomainControllerInfo dc, ConnectionInfo connection)
    {
        var host = dc.DnsHostName ?? dc.Name;
        using var server = DomainController.GetDomainController(Context(DirectoryContextType.DirectoryServer, host, connection));
        var links = new List<ReplicationLink>();
        foreach (ReplicationNeighbor n in server.GetAllReplicationNeighbors())
        {
            links.Add(new ReplicationLink
            {
                DestinationServer = host,
                SourceServer = n.SourceServer ?? "(unknown source)",
                NamingContext = n.PartitionName ?? "(unknown partition)",
                Domain = dc.Domain,
                LastSuccessfulSync = ToUtc(n.LastSuccessfulSync),
                LastAttemptedSync = ToUtc(n.LastAttemptedSync),
                ConsecutiveFailures = n.ConsecutiveFailureCount,
                LastSyncResult = n.LastSyncResult,
                LastSyncMessage = string.IsNullOrWhiteSpace(n.LastSyncMessage) ? null : n.LastSyncMessage,
                Transport = n.TransportType.ToString()
            });
        }
        return links;
    }

    private static DateTimeOffset? ToUtc(DateTime value) =>
        value.Year <= 1601 ? null : new DateTimeOffset(value.ToUniversalTime(), TimeSpan.Zero);

    /// <summary>Tipo de cada confiança do domínio (ParentChild, TreeRoot, CrossLink, External, Forest, Kerberos, Unknown).</summary>
    public static IReadOnlyDictionary<string, string> GetTrustTypes(string domainName, ConnectionInfo connection)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using var domain = Domain.GetDomain(Context(DirectoryContextType.Domain, domainName, connection));
        foreach (TrustRelationshipInformation t in domain.GetAllTrustRelationships())
            if (t.TargetName is { Length: > 0 } target) map[target] = t.TrustType.ToString();
        return map;
    }

    /// <summary>true = SID filtering habilitado. Confiança de floresta: Forest.GetSidFilteringStatus; externa: Domain.GetSidFilteringStatus.</summary>
    public static bool GetSidFiltering(string domainName, string forestName, string partner, string classification, ConnectionInfo connection)
    {
        if (classification == "Forest")
        {
            using var forest = Forest.GetForest(Context(DirectoryContextType.Forest, forestName, connection));
            return forest.GetSidFilteringStatus(partner);
        }
        using var domain = Domain.GetDomain(Context(DirectoryContextType.Domain, domainName, connection));
        return domain.GetSidFilteringStatus(partner);
    }
}
