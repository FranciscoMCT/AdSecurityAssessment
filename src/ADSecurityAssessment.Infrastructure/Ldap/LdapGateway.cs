using System.DirectoryServices.Protocols;
using System.Net;
using ADSecurityAssessment.Core.Abstractions;

namespace ADSecurityAssessment.Infrastructure.Ldap;

/// <summary>
/// Acesso LDAP SOMENTE LEITURA (System.DirectoryServices.Protocols). Esta classe só cria <see cref="SearchRequest"/>:
/// não existe nenhum caminho de código que construa Add/Modify/Delete/ModifyDN/Extended. Há teste automatizado que garante isso.
/// Autenticação Negotiate (Kerberos/NTLM) com assinatura e criptografia (sealing) habilitadas.
/// </summary>
public sealed class LdapGateway : IDirectoryGateway
{
    /// <summary>Atributos cujo valor é binário (retornados como byte[]); os demais são texto.</summary>
    private static readonly HashSet<string> BinaryAttributes = new(StringComparer.OrdinalIgnoreCase)
    {
        "objectSid", "objectGUID", "msDS-AllowedToActOnBehalfOfOtherIdentity", "nTSecurityDescriptor", "sIDHistory"
    };

    /// <summary>
    /// Atributos que contêm segredos. NUNCA são solicitados: a ferramenta não precisa deles, e solicitá-los violaria
    /// o requisito de não manipular senhas. Uma tentativa lança exceção (defesa em profundidade, coberta por teste).
    /// </summary>
    public static readonly IReadOnlySet<string> ForbiddenAttributes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "unicodePwd", "userPassword", "dBCSPwd", "lmPwdHistory", "ntPwdHistory", "supplementalCredentials", "pekList",
        "ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword", "msLAPS-EncryptedPasswordHistory",
        "msLAPS-PasswordHistory", "msDS-ManagedPassword", "trustAuthIncoming", "trustAuthOutgoing",
        "currentValue", "priorValue", "initialAuthIncoming", "initialAuthOutgoing"
    };

    private static readonly string[] RootDseAttributes =
    {
        "defaultNamingContext", "configurationNamingContext", "schemaNamingContext", "rootDomainNamingContext", "dnsHostName",
        "serverName", "currentTime", "domainFunctionality", "forestFunctionality", "domainControllerFunctionality",
        "isGlobalCatalogReady", "namingContexts"
    };

    private readonly LdapConnection _connection;
    private readonly TimeSpan _timeout;
    private readonly int _pageSize;
    private readonly IAssessmentLog _log;

    public LdapGateway(string server, NetworkCredential? credential, TimeSpan timeout, int pageSize, IAssessmentLog? log = null, int port = 389)
    {
        Server = server;
        _timeout = timeout;
        _pageSize = Math.Clamp(pageSize, 50, 5000);
        _log = log ?? NullAssessmentLog.Instance;

        var id = new LdapDirectoryIdentifier(server, port, fullyQualifiedDnsHostName: false, connectionless: false);
        if (credential is null)
        {
            // Autenticação Windows integrada: usa o contexto de segurança do usuário atual.
            _connection = new LdapConnection(id) { AuthType = AuthType.Negotiate };
        }
        else
        {
            _connection = new LdapConnection(id, credential, AuthType.Negotiate);
        }
        _connection.Timeout = timeout;
        _connection.SessionOptions.ProtocolVersion = 3;
        _connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
        _connection.SessionOptions.Signing = true;
        _connection.SessionOptions.Sealing = true;
        _connection.AutoBind = false;

        try
        {
            _connection.Bind();
            RootDse = ReadRootDse();
        }
        catch (Exception ex)
        {
            _connection.Dispose();
            throw Wrap($"Failed to connect or authenticate to '{server}'", ex);
        }
        _log.Debug($"LDAP connected: {server} (default naming context: {RootDse.DefaultNamingContext}).");
    }

    public string Server { get; }
    public RootDse RootDse { get; }

    public IEnumerable<LdapEntry> Search(SearchSpec spec, CancellationToken cancellationToken)
    {
        EnsureAllowed(spec.Attributes);
        byte[]? cookie = null;
        var returned = 0;
        do
        {
            cancellationToken.ThrowIfCancellationRequested();
            var request = new SearchRequest(spec.BaseDn, spec.Filter, Map(spec.Scope), spec.Attributes) { TimeLimit = _timeout };
            var page = new PageResultRequestControl(_pageSize) { Cookie = cookie ?? Array.Empty<byte>() };
            request.Controls.Add(page);

            var response = SendSearch(request, spec);
            foreach (SearchResultEntry entry in response.Entries)
            {
                yield return Convert(entry);
                returned++;
                if (spec.MaxEntries is { } max && returned >= max) yield break;
            }
            cookie = null;
            foreach (var control in response.Controls)
                if (control is PageResultResponseControl prc) cookie = prc.Cookie;
        }
        while (cookie is { Length: > 0 });
    }

    public LdapEntry? ReadEntry(string distinguishedName, string[] attributes, CancellationToken cancellationToken)
    {
        EnsureAllowed(attributes);
        cancellationToken.ThrowIfCancellationRequested();
        var request = new SearchRequest(distinguishedName, "(objectClass=*)", SearchScope.Base, attributes) { TimeLimit = _timeout };
        try
        {
            var response = (SearchResponse)_connection.SendRequest(request, _timeout);
            return response.Entries.Count > 0 ? Convert(response.Entries[0]) : null;
        }
        catch (DirectoryOperationException ex) when (ex.Response?.ResultCode == ResultCode.NoSuchObject)
        {
            return null;
        }
        catch (Exception ex)
        {
            throw Wrap($"Read of '{distinguishedName}' on {Server}", ex);
        }
    }

    public void Dispose() => _connection.Dispose();

    // ---------------------------------------------------------------- internos
    private SearchResponse SendSearch(SearchRequest request, SearchSpec spec)
    {
        try
        {
            return (SearchResponse)_connection.SendRequest(request, _timeout);
        }
        catch (Exception ex)
        {
            throw Wrap($"LDAP query on {Server} (base '{spec.BaseDn}', filter '{spec.Filter}')", ex);
        }
    }

    private RootDse ReadRootDse()
    {
        var request = new SearchRequest(string.Empty, "(objectClass=*)", SearchScope.Base, RootDseAttributes) { TimeLimit = _timeout };
        var response = (SearchResponse)_connection.SendRequest(request, _timeout);
        if (response.Entries.Count == 0) throw new DirectoryQueryException("The RootDSE returned no data.");
        var e = Convert(response.Entries[0]);
        return new RootDse(
            e.GetString("defaultNamingContext"), e.GetString("configurationNamingContext"), e.GetString("schemaNamingContext"),
            e.GetString("rootDomainNamingContext"), e.GetString("dnsHostName"), e.GetString("serverName"),
            e.GetGeneralizedTime("currentTime"), e.GetInt("domainFunctionality"), e.GetInt("forestFunctionality"),
            e.GetInt("domainControllerFunctionality"),
            string.Equals(e.GetString("isGlobalCatalogReady"), "TRUE", StringComparison.OrdinalIgnoreCase),
            e.GetStrings("namingContexts"));
    }

    internal static void EnsureAllowed(IEnumerable<string> attributes)
    {
        foreach (var a in attributes)
        {
            var name = a.Split(';')[0].Trim();
            if (ForbiddenAttributes.Contains(name))
                throw new InvalidOperationException($"Attribute '{name}' is forbidden: this tool never reads secrets or passwords.");
        }
    }

    private static SearchScope Map(SearchScopeKind k) => k switch
    {
        SearchScopeKind.Base => SearchScope.Base,
        SearchScopeKind.OneLevel => SearchScope.OneLevel,
        _ => SearchScope.Subtree
    };

    private static LdapEntry Convert(SearchResultEntry source)
    {
        var entry = new LdapEntry(source.DistinguishedName);
        foreach (string name in source.Attributes.AttributeNames)
        {
            var attribute = source.Attributes[name];
            var baseName = name.Split(';')[0];
            var type = BinaryAttributes.Contains(baseName) ? typeof(byte[]) : typeof(string);
            foreach (var value in attribute.GetValues(type)) entry.Add(name, value);
        }
        return entry;
    }

    /// <summary>Converte exceções do LDAP em <see cref="DirectoryQueryException"/> com classificação (permissão, timeout, objeto inexistente).</summary>
    internal static DirectoryQueryException Wrap(string context, Exception ex)
    {
        switch (ex)
        {
            case DirectoryQueryException dq: return dq;
            case LdapException le:
                return new DirectoryQueryException($"{context}: {le.Message} (LDAP {le.ErrorCode})", le, le.ErrorCode,
                    permissionDenied: le.ErrorCode is 50 or 49 or 8 or 13, timeout: le.ErrorCode is 85 or 3);
            case DirectoryOperationException oe:
                var rc = oe.Response?.ResultCode;
                return new DirectoryQueryException($"{context}: {oe.Message} ({rc})", oe, rc is null ? null : (int)rc.Value,
                    permissionDenied: rc == ResultCode.InsufficientAccessRights,
                    timeout: rc == ResultCode.TimeLimitExceeded);
            case TimeoutException:
                return new DirectoryQueryException($"{context}: timed out.", ex, timeout: true);
            default:
                return new DirectoryQueryException($"{context}: {ex.GetType().Name}: {ex.Message}", ex);
        }
    }
}
