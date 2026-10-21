using ADSecurityAssessment.Core.Abstractions;

namespace ADSecurityAssessment.Collectors;

/// <summary>Registro dos collectors. A ordem de registro é a ordem de execução (respeitando DependsOn).</summary>
public static class CollectorCatalog
{
    public static IReadOnlyList<ICollector> CreateAll() => new ICollector[]
    {
        new ForestCollector(),
        new DomainCollector(),
        new DomainControllerCollector(),
        new ReplicationCollector(),
        new DnsCollector(),
        new UserCollector(),
        new ComputerCollector(),
        new PrivilegedAccountCollector(),
        new GpoCollector(),
        new TrustCollector(),
        new LapsCollector(),
        new AdcsCollector(),
        new ServiceAccountCollector(),
        new HybridIdentityCollector(),
        new NtlmCollector(),
        new LdapSecurityCollector(),
        new SmbSecurityCollector(),
    };
}
