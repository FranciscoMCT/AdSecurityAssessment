using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using ADSecurityAssessment.Hardening.Gpo;
using ADSecurityAssessment.Hardening.Model;

namespace ADSecurityAssessment.Hardening.Catalog;

public sealed class CatalogException : Exception
{
    public IReadOnlyList<string> Errors { get; }
    public CatalogException(IReadOnlyList<string> errors) : base("Catálogo de hardening inválido:" + Environment.NewLine + string.Join(Environment.NewLine, errors.Take(25).Select(e => " - " + e)))
        => Errors = errors;
}

/// <summary>
/// Catálogo de configurações de hardening. Dados puros (JSON, esquema fechado, validado de forma estrita): nada do catálogo é código.
/// Um arquivo inválido é recusado por inteiro — a ferramenta nunca aplica um catálogo parcialmente entendido.
/// </summary>
public sealed class HardeningCatalog
{
    private static readonly Regex IdRx = new(@"^[a-z0-9]+([.-][a-z0-9]+)*$", RegexOptions.Compiled);
    private static readonly HashSet<string> Risks = new() { "low", "medium", "high" };
    private static readonly HashSet<string> Attributes = new() { "minPwdLength", "pwdProperties", "minPwdAgeDays", "pwdHistoryLength", "lockoutThreshold", "lockoutDurationMinutes", "lockoutObservationMinutes" };
    private static readonly HashSet<string> Comparisons = new() { "gte", "bit1", "range1-10" };
    private static readonly char[] BadNameChars = { '\\', '/', ':', '*', '?', '"', '<', '>', '|', '\r', '\n', '\0' };

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false
    };

    private readonly Dictionary<string, SettingDef> _byId;

    private HardeningCatalog(CatalogDoc doc, string source)
    {
        Doc = doc;
        Source = source;
        _byId = doc.Settings.ToDictionary(s => s.Id, StringComparer.Ordinal);
    }

    public CatalogDoc Doc { get; }
    public string Source { get; }
    public string Version => Doc.CatalogVersion;
    public IReadOnlyList<ProfileDef> Profiles => Doc.Profiles;
    public IReadOnlyList<ProfileDef> GpoProfiles => Doc.Profiles.Where(p => p.Kind == "gpo").ToList();
    public IReadOnlyList<SettingDef> Settings => Doc.Settings;
    public IReadOnlyList<AccountPolicyDef> AccountPolicy => Doc.AccountPolicy;

    public SettingDef Get(string id) => _byId[id];
    public bool TryGet(string id, out SettingDef setting) => _byId.TryGetValue(id, out setting!);
    public ProfileDef Profile(string id) => Doc.Profiles.First(p => p.Id == id);
    public IReadOnlyList<SettingDef> ForProfile(string profileId) => Doc.Settings.Where(s => s.Scopes.Contains(profileId)).ToList();

    // ------------------------------------------------------------------ carga
    public static HardeningCatalog LoadEmbedded()
    {
        var asm = typeof(HardeningCatalog).Assembly;
        using var stream = asm.GetManifestResourceStream("catalog.json") ?? throw new InvalidOperationException("catalog.json não está embutido no assembly.");
        using var reader = new StreamReader(stream);
        return Parse(reader.ReadToEnd(), "embutido");
    }

    /// <summary>Usa &lt;overrideDirectory&gt;\catalog.json se existir (permite ajustar o catálogo sem recompilar); senão o embutido.</summary>
    public static HardeningCatalog Load(string? overrideDirectory)
    {
        if (!string.IsNullOrWhiteSpace(overrideDirectory))
        {
            var file = Path.Combine(overrideDirectory, "catalog.json");
            if (File.Exists(file)) return Parse(File.ReadAllText(file), file);
        }
        return LoadEmbedded();
    }

    public static HardeningCatalog Parse(string json, string source)
    {
        CatalogDoc? doc;
        try { doc = JsonSerializer.Deserialize<CatalogDoc>(json, Json); }
        catch (JsonException ex) { throw new CatalogException(new[] { $"JSON inválido ou campo desconhecido: {ex.Message}" }); }
        if (doc is null) throw new CatalogException(new[] { "Catálogo vazio." });
        var errors = Validate(doc);
        if (errors.Count > 0) throw new CatalogException(errors);
        return new HardeningCatalog(doc, source);
    }

    // ------------------------------------------------------------------ validação
    public static List<string> Validate(CatalogDoc doc)
    {
        var errors = new List<string>();
        void Err(string m) => errors.Add(m);

        if (string.IsNullOrWhiteSpace(doc.CatalogVersion)) Err("catalogVersion ausente.");
        if (doc.Profiles.Count == 0) Err("Nenhum perfil definido.");

        var profileIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var p in doc.Profiles)
        {
            if (!IdRx.IsMatch(p.Id)) Err($"Perfil com id inválido: '{p.Id}'.");
            if (!profileIds.Add(p.Id)) Err($"Perfil duplicado: {p.Id}.");
            if (p.Kind is not ("gpo" or "advice")) Err($"Perfil {p.Id}: kind deve ser gpo ou advice.");
            if (string.IsNullOrWhiteSpace(p.Title)) Err($"Perfil {p.Id}: title vazio.");
            if (p.Kind == "gpo" && (string.IsNullOrWhiteSpace(p.GpoName) || p.GpoName.Length > 100 || p.GpoName.IndexOfAny(BadNameChars) >= 0))
                Err($"Perfil {p.Id}: gpoName vazio, longo (>100) ou com caractere inválido.");
        }
        var gpoProfiles = doc.Profiles.Where(p => p.Kind == "gpo").Select(p => p.Id).ToHashSet(StringComparer.Ordinal);

        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var s in doc.Settings)
        {
            var w = $"Configuração '{s.Id}'";
            if (!IdRx.IsMatch(s.Id)) { Err($"Configuração com id inválido: '{s.Id}'."); continue; }
            if (!ids.Add(s.Id)) Err($"{w}: id duplicado.");
            foreach (var (name, v) in new[] { ("category", s.Category), ("title", s.Title), ("rationale", s.Rationale), ("impact", s.Impact) })
                if (string.IsNullOrWhiteSpace(v)) Err($"{w}: {name} vazio.");
            if (!Risks.Contains(s.Risk)) Err($"{w}: risk deve ser low, medium ou high.");
            if (s.Risk == "high" && s.DefaultOn) Err($"{w}: configuração de alto risco não pode ser defaultOn.");
            if (s.Risk == "high" && string.IsNullOrWhiteSpace(s.Prerequisite)) Err($"{w}: alto risco exige prerequisite.");
            if (s.Scopes.Count == 0) Err($"{w}: scopes vazio.");
            foreach (var sc in s.Scopes) if (!gpoProfiles.Contains(sc)) Err($"{w}: escopo '{sc}' não é um perfil gpo.");
            if (s.Scopes.Distinct().Count() != s.Scopes.Count) Err($"{w}: escopo repetido.");
            if (s.References.Count == 0) Err($"{w}: precisa de ao menos uma referência.");
            foreach (var r in s.References) if (!IsLearnUrl(r)) Err($"{w}: referência fora de learn.microsoft.com: {r}");
            if (s.Entries.Count == 0) Err($"{w}: sem entries.");
            foreach (var e in s.Entries) ValidateEntry(w, e, Err);
        }

        var byId = doc.Settings.Where(s => ids.Contains(s.Id)).GroupBy(s => s.Id).ToDictionary(g => g.Key, g => g.First());
        foreach (var s in doc.Settings)
        {
            foreach (var req in s.Requires ?? new List<string>())
            {
                if (req == s.Id) Err($"Configuração '{s.Id}': requires aponta para si mesma.");
                else if (!byId.TryGetValue(req, out var target)) Err($"Configuração '{s.Id}': requires inexistente '{req}'.");
                else if (!s.Scopes.All(target.Scopes.Contains)) Err($"Configuração '{s.Id}': '{req}' não cobre todos os escopos dela.");
            }
            if (s.Entries.Any(e => e.Via == "audit") && !(s.Requires ?? new List<string>()).Contains("audit.force-subcategory"))
                Err($"Configuração '{s.Id}': auditoria avançada exige requires audit.force-subcategory.");
        }

        // Conflito: duas configurações escrevendo o mesmo destino no mesmo perfil.
        foreach (var profile in gpoProfiles)
        {
            var seen = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var s in doc.Settings.Where(x => x.Scopes.Contains(profile)))
                foreach (var e in s.Entries)
                {
                    var target = TargetOf(e);
                    if (target is null) continue;
                    if (seen.TryGetValue(target, out var other)) Err($"Perfil {profile}: '{s.Id}' e '{other}' escrevem no mesmo destino ({target}).");
                    else seen[target] = s.Id;
                }
        }

        // Detecta ciclo em requires.
        foreach (var s in doc.Settings)
        {
            var stack = new Stack<string>(); var visited = new HashSet<string>();
            stack.Push(s.Id);
            while (stack.Count > 0)
            {
                var cur = stack.Pop();
                if (!byId.TryGetValue(cur, out var def)) continue;
                foreach (var r in def.Requires ?? new List<string>())
                {
                    if (r == s.Id) { Err($"Configuração '{s.Id}': ciclo em requires."); stack.Clear(); break; }
                    if (visited.Add(r)) stack.Push(r);
                }
            }
        }

        var apIds = new HashSet<string>();
        foreach (var a in doc.AccountPolicy)
        {
            if (!IdRx.IsMatch(a.Id) || !apIds.Add(a.Id)) Err($"accountPolicy: id inválido ou duplicado '{a.Id}'.");
            if (!Attributes.Contains(a.Attribute)) Err($"accountPolicy {a.Id}: attribute desconhecido '{a.Attribute}'.");
            if (!Comparisons.Contains(a.Comparison)) Err($"accountPolicy {a.Id}: comparison desconhecido '{a.Comparison}'.");
            if (a.Recommended < 0) Err($"accountPolicy {a.Id}: recommended negativo.");
            if (string.IsNullOrWhiteSpace(a.Label)) Err($"accountPolicy {a.Id}: label vazio.");
            if (!IsLearnUrl(a.Reference)) Err($"accountPolicy {a.Id}: reference fora de learn.microsoft.com.");
        }
        return errors;
    }

    private static bool IsLearnUrl(string? url) =>
        url is not null && url.StartsWith("https://learn.microsoft.com/", StringComparison.Ordinal) && url.IndexOfAny(new[] { ' ', '"', '<', '>' }) < 0;

    /// <summary>Destino normalizado (para detectar conflito): registro sem prefixo de hive, ou subcategoria.</summary>
    private static string? TargetOf(EntryDef e) => e.Via switch
    {
        "template" when e.Path is { } p && p.StartsWith(@"MACHINE\", StringComparison.OrdinalIgnoreCase) => p[8..],
        "pol" when e.Key is not null && e.Name is not null => e.Key + @"\" + e.Name,
        "audit" when e.Subcategory is not null => "audit:" + e.Subcategory,
        _ => null
    };

    private static void ValidateEntry(string where, EntryDef e, Action<string> err)
    {
        void Only(params string[] allowed)
        {
            var present = new List<string>();
            if (e.Path is not null) present.Add("path");
            if (e.Key is not null) present.Add("key");
            if (e.Name is not null) present.Add("name");
            if (e.Type is not null) present.Add("type");
            if (e.Value is not null) present.Add("value");
            if (e.Revert is not null) present.Add("revert");
            if (e.RevertDc is not null) present.Add("revertDc");
            if (e.RevertDelete) present.Add("revertDelete");
            if (e.Subcategory is not null) present.Add("subcategory");
            if (e.Success is not null) present.Add("success");
            if (e.Failure is not null) present.Add("failure");
            foreach (var f in present.Except(allowed)) err($"{where}: campo '{f}' não é permitido em via={e.Via}.");
        }

        switch (e.Via)
        {
            case "template":
                Only("path", "type", "value", "revert", "revertDc");
                if (e.Path is null || !e.Path.StartsWith(@"MACHINE\", StringComparison.Ordinal) || e.Path.Length <= 8 || e.Path.EndsWith('\\') || e.Path.Contains('=') || e.Path.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0)
                    err($"{where}: path de template deve começar com MACHINE\\ e apontar para um valor.");
                CheckValue(where, e, err, allowDeleteRevert: false);
                break;
            case "pol":
                Only("key", "name", "type", "value", "revert", "revertDc", "revertDelete");
                if (string.IsNullOrWhiteSpace(e.Key) || e.Key.StartsWith("HKEY", StringComparison.OrdinalIgnoreCase) || e.Key.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase)
                    || e.Key.StartsWith(@"MACHINE\", StringComparison.OrdinalIgnoreCase) || e.Key.StartsWith('\\') || e.Key.EndsWith('\\') || e.Key.IndexOfAny(new[] { ';', '[', ']', '\0' }) >= 0)
                    err($"{where}: key de registry.pol inválida (sem hive, sem ';[]').");
                if (string.IsNullOrWhiteSpace(e.Name) || e.Name.IndexOfAny(new[] { ';', '[', ']', '\0', '\\' }) >= 0) err($"{where}: name de registry.pol inválido.");
                CheckValue(where, e, err, allowDeleteRevert: true);
                break;
            case "audit":
                Only("subcategory", "success", "failure");
                if (e.Subcategory is null || !AuditPolicy.All.ContainsKey(e.Subcategory)) err($"{where}: subcategoria de auditoria desconhecida '{e.Subcategory}'.");
                if (e.Success is null || e.Failure is null) err($"{where}: audit exige success e failure.");
                else if (!e.Success.Value && !e.Failure.Value) err($"{where}: audit sem sucesso nem falha.");
                break;
            default:
                err($"{where}: via desconhecido '{e.Via}'.");
                break;
        }
    }

    private static void CheckValue(string where, EntryDef e, Action<string> err, bool allowDeleteRevert)
    {
        if (!RegValues.TryParseType(e.Type, out var type)) { err($"{where}: type deve ser dword, string ou multistring."); return; }
        if (e.Value is null) { err($"{where}: value ausente."); return; }
        if (!RegValues.TryConvert(e.Value.Value, type, out _, out var msg)) err($"{where}: {msg}.");
        foreach (var (name, r) in new[] { ("revert", e.Revert), ("revertDc", e.RevertDc) })
            if (r is not null && !RegValues.TryConvert(r.Value, type, out _, out var m2)) err($"{where}: {name}: {m2}.");
        if (e.RevertDelete && !allowDeleteRevert) err($"{where}: revertDelete só vale para registry.pol.");
        if (e.RevertDelete && (e.Revert is not null || e.RevertDc is not null)) err($"{where}: revertDelete não combina com revert/revertDc.");
        if (e.RevertDc is not null && e.Revert is null) err($"{where}: revertDc exige revert.");
    }
}
