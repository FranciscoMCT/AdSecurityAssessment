using System.Reflection;
using System.Text.Json;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Core.Abstractions;

/// <summary>
/// Catálogo de referências oficiais. Somente URLs https://learn.microsoft.com/ são aceitas: qualquer outra é rejeitada
/// no carregamento. Regras apontam para CHAVES do catálogo — nunca para URLs soltas.
/// </summary>
public sealed class ReferenceCatalog
{
    private readonly Dictionary<string, MicrosoftReference> _items;
    private ReferenceCatalog(Dictionary<string, MicrosoftReference> items, IReadOnlyList<string> rejected)
    {
        _items = items; Rejected = rejected;
    }

    public IReadOnlyList<string> Rejected { get; }
    public IReadOnlyCollection<string> Keys => _items.Keys;
    public bool Contains(string key) => _items.ContainsKey(key);

    public MicrosoftReference Resolve(string key) =>
        _items.TryGetValue(key, out var r) ? r : throw new KeyNotFoundException($"Unknown reference in the catalog: '{key}'.");

    public bool TryResolve(string key, out MicrosoftReference reference) => _items.TryGetValue(key, out reference!);

    public IReadOnlyList<MicrosoftReference> ResolveAll(IEnumerable<string> keys) => keys.Select(Resolve).ToArray();

    public static bool IsOfficialUrl(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps &&
        u.Host.Equals("learn.microsoft.com", StringComparison.OrdinalIgnoreCase);

    public static ReferenceCatalog Parse(string json)
    {
        var items = new Dictionary<string, MicrosoftReference>(StringComparer.OrdinalIgnoreCase);
        var rejected = new List<string>();
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip });
        if (doc.RootElement.TryGetProperty("references", out var refs))
        {
            foreach (var p in refs.EnumerateObject())
            {
                var title = p.Value.GetProperty("title").GetString() ?? p.Name;
                var url = p.Value.GetProperty("url").GetString() ?? "";
                if (IsOfficialUrl(url)) items[p.Name] = new MicrosoftReference(title, url);
                else rejected.Add($"{p.Name}: {url}");
            }
        }
        return new ReferenceCatalog(items, rejected);
    }

    public static ReferenceCatalog LoadEmbedded()
    {
        var asm = typeof(ReferenceCatalog).Assembly;
        using var s = asm.GetManifestResourceStream("references.json")
                      ?? throw new InvalidOperationException("Embedded references.json was not found.");
        using var r = new StreamReader(s);
        return Parse(r.ReadToEnd());
    }

    /// <summary>Carrega o arquivo em disco (rules/references.json) quando existir; senão usa o embutido.</summary>
    public static ReferenceCatalog Load(string? filePath)
    {
        if (!string.IsNullOrWhiteSpace(filePath) && File.Exists(filePath))
        {
            try { return Parse(File.ReadAllText(filePath)); } catch (JsonException) { /* cai para o embutido */ }
        }
        return LoadEmbedded();
    }

    private static ReferenceCatalog? _default;
    public static ReferenceCatalog Default => _default ??= LoadEmbedded();
    public static void SetDefault(ReferenceCatalog catalog) => _default = catalog;
}
