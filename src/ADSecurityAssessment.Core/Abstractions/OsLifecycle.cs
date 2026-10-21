using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ADSecurityAssessment.Core.Abstractions;

public sealed record OsProduct(string Key, string Name, string NtVersion, int? Build,
                               DateTimeOffset? MainstreamEnd, DateTimeOffset? ExtendedEnd, DateTimeOffset? EsuEnd, string ReferenceKey);

/// <summary>Datas de suporte do Windows Server (data/os-lifecycle.json, extraídas do Microsoft Lifecycle). Versões desconhecidas → null (nunca assumidas).</summary>
public sealed class OsLifecycleCatalog
{
    private static readonly Regex NameRx = new(@"Windows\s+Server\W*\s*(2008\s*R2|2008|2012\s*R2|2012|2016|2019|2022|2025)\b",
                                               RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex VerRx = new(@"^\s*(\d+\.\d+)\s*\(\s*(\d+)\s*\)", RegexOptions.Compiled);

    private readonly List<OsProduct> _products;
    private OsLifecycleCatalog(List<OsProduct> p) { _products = p; }
    public IReadOnlyList<OsProduct> Products => _products;

    public static OsLifecycleCatalog Parse(string json)
    {
        var list = new List<OsProduct>();
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip });
        foreach (var p in doc.RootElement.GetProperty("products").EnumerateArray())
        {
            DateTimeOffset? D(string n) => p.TryGetProperty(n, out var e) && e.ValueKind == JsonValueKind.String &&
                DateTimeOffset.TryParse(e.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var v) ? v : null;
            int? build = p.TryGetProperty("build", out var b) && b.ValueKind == JsonValueKind.Number ? b.GetInt32() : null;
            list.Add(new OsProduct(p.GetProperty("key").GetString()!, p.GetProperty("name").GetString()!,
                p.GetProperty("ntVersion").GetString()!, build, D("mainstreamEnd"), D("extendedEnd"), D("esuEnd"),
                p.GetProperty("reference").GetString()!));
        }
        return new OsLifecycleCatalog(list);
    }

    public static OsLifecycleCatalog LoadEmbedded()
    {
        using var s = typeof(OsLifecycleCatalog).Assembly.GetManifestResourceStream("os-lifecycle.json")
                      ?? throw new InvalidOperationException("Embedded os-lifecycle.json was not found.");
        using var r = new StreamReader(s);
        return Parse(r.ReadToEnd());
    }

    public static OsLifecycleCatalog Load(string? filePath)
    {
        if (!string.IsNullOrWhiteSpace(filePath) && File.Exists(filePath))
        {
            try { return Parse(File.ReadAllText(filePath)); } catch (JsonException) { }
        }
        return LoadEmbedded();
    }

    private static OsLifecycleCatalog? _default;
    public static OsLifecycleCatalog Default => _default ??= LoadEmbedded();
    public static void SetDefault(OsLifecycleCatalog c) => _default = c;

    /// <summary>Identifica o produto Windows Server a partir de operatingSystem / operatingSystemVersion. null = desconhecido.</summary>
    public OsProduct? Find(string? operatingSystem, string? operatingSystemVersion)
    {
        if (!string.IsNullOrWhiteSpace(operatingSystem))
        {
            var m = NameRx.Match(operatingSystem.Replace("®", "").Replace("™", ""));
            if (m.Success)
            {
                var token = Regex.Replace(m.Groups[1].Value, @"\s+", "").ToLowerInvariant(); // 2008r2
                var key = "ws" + token;
                var byName = _products.FirstOrDefault(p => p.Key.Equals(key, StringComparison.OrdinalIgnoreCase));
                if (byName is not null) return byName;
            }
        }
        if (!string.IsNullOrWhiteSpace(operatingSystemVersion))
        {
            var m = VerRx.Match(operatingSystemVersion);
            if (m.Success && int.TryParse(m.Groups[2].Value, out var build))
            {
                var nt = m.Groups[1].Value;
                var cands = _products.Where(p => p.NtVersion == nt).ToList();
                if (cands.Count == 1 && cands[0].Build is null) return cands[0];
                var byBuild = cands.FirstOrDefault(p => p.Build == build);
                if (byBuild is not null) return byBuild;
            }
        }
        return null;
    }
}
