using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using ADSecurityAssessment.Core.Abstractions;

namespace ADSecurityAssessment.Collectors.Support;

internal static class LdapUtil
{
    public const int NoSuchObjectCode = 32;

    public static bool IsNoSuchObject(Exception ex) => ex is DirectoryQueryException { ResultCode: NoSuchObjectCode };

    /// <summary>Divide um DN nas vírgulas NÃO escapadas.</summary>
    public static List<string> SplitDn(string dn)
    {
        var parts = new List<string>();
        var sb = new StringBuilder();
        for (var i = 0; i < dn.Length; i++)
        {
            var c = dn[i];
            if (c == '\\' && i + 1 < dn.Length) { sb.Append(c).Append(dn[++i]); continue; }
            if (c == ',') { parts.Add(sb.ToString().Trim()); sb.Clear(); continue; }
            sb.Append(c);
        }
        if (sb.Length > 0) parts.Add(sb.ToString().Trim());
        return parts;
    }

    public static string? ParentDn(string dn)
    {
        var parts = SplitDn(dn);
        return parts.Count < 2 ? null : string.Join(",", parts.Skip(1));
    }

    /// <summary>Valor do RDN na posição indicada (0 = primeiro).</summary>
    public static string? RdnValue(string dn, int index)
    {
        var parts = SplitDn(dn);
        if (index >= parts.Count) return null;
        var eq = parts[index].IndexOf('=');
        return eq < 0 ? null : parts[index][(eq + 1)..];
    }

    /// <summary>DC=contoso,DC=local → contoso.local</summary>
    public static string DnToDns(string dn) =>
        string.Join('.', SplitDn(dn).Where(p => p.StartsWith("DC=", StringComparison.OrdinalIgnoreCase)).Select(p => p[3..]));

    /// <summary>Filtro LDAP para objectSid a partir de um SID textual (bytes escapados como \xx).</summary>
    public static string SidFilterValue(string sid)
    {
        var s = new SecurityIdentifier(sid);
        var bytes = new byte[s.BinaryLength];
        s.GetBinaryForm(bytes, 0);
        var sb = new StringBuilder(bytes.Length * 3);
        foreach (var b in bytes) sb.Append('\\').Append(b.ToString("x2"));
        return sb.ToString();
    }

    public static string EscapeFilter(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (var c in value)
            switch (c)
            {
                case '\\': sb.Append("\\5c"); break;
                case '*': sb.Append("\\2a"); break;
                case '(': sb.Append("\\28"); break;
                case ')': sb.Append("\\29"); break;
                case '\0': sb.Append("\\00"); break;
                default: sb.Append(c); break;
            }
        return sb.ToString();
    }

    public static int? Rid(string? sid)
    {
        if (sid is null) return null;
        var i = sid.LastIndexOf('-');
        return i > 0 && int.TryParse(sid.AsSpan(i + 1), out var rid) ? rid : null;
    }

    /// <summary>Intervalos AD (100 ns, negativos) → dias. Int64.MinValue/0 = sem valor ("nunca").</summary>
    public static double? IntervalDays(long? ticks) =>
        ticks is null or 0 or long.MinValue ? null : Math.Abs((double)ticks.Value) / TimeSpan.TicksPerDay;

    public static double? IntervalMinutes(long? ticks) =>
        ticks is null or 0 or long.MinValue ? null : Math.Abs((double)ticks.Value) / TimeSpan.TicksPerMinute;

    /// <summary>Lê todos os valores de um atributo multivalorado grande (ranged retrieval: member;range=0-*).</summary>
    public static List<string> ReadRanged(IDirectoryGateway gateway, string dn, string attribute, CancellationToken ct)
    {
        var all = new List<string>();
        var start = 0;
        var rx = new Regex(@";range=(\d+)-(\*|\d+)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var entry = gateway.ReadEntry(dn, new[] { $"{attribute};range={start}-*" }, ct);
            var key = entry?.Attributes.Keys.FirstOrDefault(k => k.StartsWith(attribute, StringComparison.OrdinalIgnoreCase));
            if (entry is null || key is null) break;
            all.AddRange(entry.GetStrings(key));
            var m = rx.Match(key);
            if (!m.Success || m.Groups[2].Value == "*") break;
            start = int.Parse(m.Groups[2].Value) + 1;
        }
        return all;
    }

    public static string? LastClass(LdapEntry e) => e.GetStrings("objectClass").LastOrDefault();
}
