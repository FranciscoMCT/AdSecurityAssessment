using System.DirectoryServices.ActiveDirectory;
using System.Net;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Infrastructure.Ldap;

/// <summary>
/// Abre conexões LDAP para o assessment. A senha nunca é guardada: é lida do <see cref="ConnectionInfo"/> (SecureString,
/// apenas em memória) no momento de criar a credencial e descartada junto com a conexão.
/// </summary>
public sealed class LdapGatewayFactory : IDirectoryGatewayFactory
{
    private readonly ConnectionInfo _connection;
    private readonly AssessmentSettings _settings;
    private readonly IAssessmentLog _log;

    public LdapGatewayFactory(ConnectionInfo connection, AssessmentSettings settings, IAssessmentLog? log = null)
    {
        _connection = connection;
        _settings = settings;
        _log = log ?? NullAssessmentLog.Instance;
    }

    public IDirectoryGateway Open(GatewayTarget target)
    {
        var server = target.Server;
        var domain = target.DomainDns ?? _connection.Domain;

        // O DC informado pelo usuário vale somente para o domínio informado (ou quando nenhum domínio foi dado).
        if (string.IsNullOrWhiteSpace(server) && !string.IsNullOrWhiteSpace(_connection.DomainController)
            && (string.IsNullOrWhiteSpace(target.DomainDns) || SameDomain(target.DomainDns, _connection.Domain)))
            server = _connection.DomainController;

        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(server)) candidates.Add(server!);
        else
        {
            var located = LocateDomainController(domain);
            if (located is not null) candidates.Add(located);
            // Fallback: o nome DNS do domínio resolve para registros A dos DCs.
            if (!string.IsNullOrWhiteSpace(domain)) candidates.Add(domain!);
            else if (Environment.GetEnvironmentVariable("USERDNSDOMAIN") is { Length: > 0 } dns) candidates.Add(dns);
        }
        if (candidates.Count == 0)
            throw new DirectoryQueryException("Could not determine a domain or DC. Enter the domain or the domain controller.");

        var timeout = TimeSpan.FromSeconds(Math.Max(5, _settings.QueryTimeoutSeconds));
        DirectoryQueryException? last = null;
        foreach (var candidate in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                return new LdapGateway(candidate, _connection.CreateCredential(), timeout, _settings.LdapPageSize, _log);
            }
            catch (DirectoryQueryException ex)
            {
                _log.Warn($"Failed to open LDAP on '{candidate}': {ex.Message}");
                last = ex;
            }
        }
        throw last ?? new DirectoryQueryException("Failed to open the LDAP connection.");
    }

    private static bool SameDomain(string? a, string? b) =>
        !string.IsNullOrWhiteSpace(a) && !string.IsNullOrWhiteSpace(b) && a.Trim().TrimEnd('.').Equals(b.Trim().TrimEnd('.'), StringComparison.OrdinalIgnoreCase);

    /// <summary>Usa o localizador de DC do Windows (DsGetDcName) via System.DirectoryServices.ActiveDirectory.</summary>
    private string? LocateDomainController(string? domain)
    {
        try
        {
            Domain d;
            if (string.IsNullOrWhiteSpace(domain)) d = Domain.GetCurrentDomain();
            else
            {
                var cred = _connection.CreateCredential();
                var ctx = cred is null
                    ? new DirectoryContext(DirectoryContextType.Domain, domain)
                    : new DirectoryContext(DirectoryContextType.Domain, domain, QualifiedUser(cred), cred.Password);
                d = Domain.GetDomain(ctx);
            }
            using (d)
            {
                using var dc = d.FindDomainController();
                return dc.Name;
            }
        }
        catch (Exception ex) when (ex is ActiveDirectoryObjectNotFoundException or ActiveDirectoryOperationException
                                    or ActiveDirectoryServerDownException or InvalidOperationException or PlatformNotSupportedException)
        {
            _log.Warn($"DC locator failed for '{domain ?? "(current domain)"}': {ex.Message}");
            return null;
        }
    }

    internal static string QualifiedUser(NetworkCredential c) =>
        string.IsNullOrEmpty(c.Domain) ? c.UserName : $"{c.Domain}\\{c.UserName}";
}
