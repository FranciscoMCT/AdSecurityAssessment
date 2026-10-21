using System.Globalization;
using System.Security.Principal;

namespace ADSecurityAssessment.Core.Abstractions;

public enum SearchScopeKind { Base, OneLevel, Subtree }

/// <summary>Especificação de uma consulta LDAP. Só existe "Search": o contrato não possui operações de escrita.</summary>
public sealed record SearchSpec(string BaseDn, string Filter, SearchScopeKind Scope, string[] Attributes, int? MaxEntries = null);

/// <summary>Entrada LDAP já desacoplada de System.DirectoryServices. Valores: string ou byte[].</summary>
public sealed class LdapEntry
{
    private readonly Dictionary<string, List<object>> _attrs = new(StringComparer.OrdinalIgnoreCase);

    public LdapEntry(string distinguishedName) { DistinguishedName = distinguishedName; }

    public string DistinguishedName { get; }
    public IReadOnlyDictionary<string, List<object>> Attributes => _attrs;

    public LdapEntry Add(string name, object value)
    {
        if (!_attrs.TryGetValue(name, out var list)) _attrs[name] = list = new List<object>();
        list.Add(value);
        return this;
    }

    public LdapEntry AddRange(string name, IEnumerable<object> values)
    {
        foreach (var v in values) Add(name, v);
        return this;
    }

    public bool Has(string name) => _attrs.TryGetValue(name, out var l) && l.Count > 0;

    public string? GetString(string name) =>
        _attrs.TryGetValue(name, out var l) && l.Count > 0 ? l[0] as string ?? (l[0] is byte[] b ? System.Text.Encoding.UTF8.GetString(b) : l[0].ToString()) : null;

    public IReadOnlyList<string> GetStrings(string name) =>
        _attrs.TryGetValue(name, out var l)
            ? l.Select(o => o as string ?? (o is byte[] b ? System.Text.Encoding.UTF8.GetString(b) : o.ToString() ?? "")).ToArray()
            : Array.Empty<string>();

    public int? GetInt(string name) =>
        int.TryParse(GetString(name), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;

    public long? GetLong(string name) =>
        long.TryParse(GetString(name), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;

    public byte[]? GetBytes(string name) =>
        _attrs.TryGetValue(name, out var l) && l.Count > 0 ? l[0] as byte[] : null;

    /// <summary>FILETIME (100ns desde 1601). 0 e Int64.MaxValue significam "nunca/sem valor" → null.</summary>
    public DateTimeOffset? GetFileTime(string name)
    {
        var v = GetLong(name);
        return FileTimeToDate(v);
    }

    public static DateTimeOffset? FileTimeToDate(long? v)
    {
        if (v is null or <= 0 or long.MaxValue) return null;
        try { return DateTimeOffset.FromFileTime(v.Value).ToUniversalTime(); } catch (ArgumentOutOfRangeException) { return null; }
    }

    /// <summary>Generalized time (yyyyMMddHHmmss.0Z), usada por whenCreated/whenChanged/currentTime.</summary>
    public DateTimeOffset? GetGeneralizedTime(string name) => ParseGeneralizedTime(GetString(name));

    public static DateTimeOffset? ParseGeneralizedTime(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        var core = s.Trim();
        // yyyyMMddHHmmss.fZ  ou yyyyMMddHHmmssZ
        var formats = new[] { "yyyyMMddHHmmss'.0Z'", "yyyyMMddHHmmss'.'fZ", "yyyyMMddHHmmss'Z'", "yyyyMMddHHmmss'.0'zzz" };
        return DateTimeOffset.TryParseExact(core, formats, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt) ? dt : null;
    }

    public string? GetSid(string name)
    {
        var b = GetBytes(name);
        if (b is null || b.Length < 8) return null;
        try { return new SecurityIdentifier(b, 0).Value; } catch (ArgumentException) { return null; }
    }
}

public sealed record RootDse(
    string? DefaultNamingContext, string? ConfigurationNamingContext, string? SchemaNamingContext,
    string? RootDomainNamingContext, string? DnsHostName, string? ServerName,
    DateTimeOffset? CurrentTime, int? DomainFunctionality, int? ForestFunctionality, int? DomainControllerFunctionality,
    bool IsGlobalCatalogReady, IReadOnlyList<string> NamingContexts);

/// <summary>Acesso LDAP somente leitura a um servidor.</summary>
public interface IDirectoryGateway : IDisposable
{
    string Server { get; }
    RootDse RootDse { get; }
    /// <summary>Consulta paginada (lazy). Lança <see cref="DirectoryQueryException"/> em falhas.</summary>
    IEnumerable<LdapEntry> Search(SearchSpec spec, CancellationToken cancellationToken);
    /// <summary>Lê um objeto (escopo Base). Retorna null se não existir.</summary>
    LdapEntry? ReadEntry(string distinguishedName, string[] attributes, CancellationToken cancellationToken);
}

public sealed record GatewayTarget(string? Server, string? DomainDns);

public interface IDirectoryGatewayFactory
{
    /// <summary>Abre uma conexão. Sem Server: o localizador de DC do Windows escolhe um DC do domínio (ou do domínio atual).</summary>
    IDirectoryGateway Open(GatewayTarget target);
}

public class DirectoryQueryException : Exception
{
    public int? ResultCode { get; }
    public bool IsPermissionDenied { get; }
    public bool IsTimeout { get; }
    public DirectoryQueryException(string message, Exception? inner = null, int? resultCode = null, bool permissionDenied = false, bool timeout = false)
        : base(message, inner) { ResultCode = resultCode; IsPermissionDenied = permissionDenied; IsTimeout = timeout; }
}
