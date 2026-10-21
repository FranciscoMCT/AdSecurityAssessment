using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Rules.Json;

public sealed record RuleLoadError(string Source, string RuleId, string Message);

public sealed class RuleLoadResult
{
    public List<IAssessmentRule> Rules { get; } = new();
    public List<RuleLoadError> Errors { get; } = new();
    public string Origin { get; set; } = "";
}

/// <summary>Valida e carrega regras JSON. Regra inválida é REJEITADA (e relatada) — nunca executada parcialmente.</summary>
public static class JsonRuleLoader
{
    private static readonly Regex IdRx = new(@"^AD-[A-Z]{2,8}-\d{3}$", RegexOptions.Compiled);
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true, ReadCommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true,
        // Esquema FECHADO: qualquer campo desconhecido (ex.: "script", "code", "exec") invalida o arquivo em vez de ser ignorado em silêncio.
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    public static void LoadJson(string json, string source, ReferenceCatalog refs, RuleLoadResult into)
    {
        JsonRuleFile? file;
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
            file = doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("rules", out _)
                ? doc.RootElement.Deserialize<JsonRuleFile>(Options)
                : new JsonRuleFile { Rules = { doc.RootElement.Deserialize<JsonRuleDef>(Options)! } };
        }
        catch (JsonException ex)
        {
            into.Errors.Add(new RuleLoadError(source, "-", "Invalid JSON: " + ex.Message));
            return;
        }
        foreach (var def in file?.Rules ?? new())
        {
            var errors = new List<string>();
            var rule = Build(def, refs, errors);
            if (errors.Count > 0 || rule is null)
                into.Errors.Add(new RuleLoadError(source, def.RuleId, string.Join(" | ", errors)));
            else if (into.Rules.Any(r => r.Metadata.RuleId.Equals(def.RuleId, StringComparison.OrdinalIgnoreCase)))
                into.Errors.Add(new RuleLoadError(source, def.RuleId, "Duplicate RuleId."));
            else into.Rules.Add(rule);
        }
    }

    public static JsonRule? Build(JsonRuleDef d, ReferenceCatalog refs, List<string> errors)
    {
        if (!IdRx.IsMatch(d.RuleId ?? "")) errors.Add("invalid ruleId (expected format AD-XXX-000).");
        foreach (var (n, v) in new[] { ("title", d.Title), ("description", d.Description), ("condition", d.Condition), ("risk", d.Risk), ("recommendation", d.Recommendation) })
            if (string.IsNullOrWhiteSpace(v)) errors.Add($"field '{n}' is required.");
        if (!Enum.TryParse<Severity>(d.Severity, true, out var sev)) errors.Add($"invalid severity '{d.Severity}'.");
        if (!Categories.All.Contains(d.Category)) errors.Add($"invalid category '{d.Category}'.");
        if (!Modules.All.Contains(d.Module)) errors.Add($"invalid module '{d.Module}'.");

        if (d.References is not { Count: > 0 }) errors.Add("at least one Microsoft reference is required.");
        var resolved = new List<MicrosoftReference>();
        foreach (var k in d.References ?? new())
            if (refs.TryResolve(k, out var r)) resolved.Add(r); else errors.Add($"reference '{k}' does not exist in the official catalog.");

        if (!DatasetCatalog.TryGet(d.Dataset, out var ds)) { errors.Add($"dataset desconhecido '{d.Dataset}'."); return null; }

        var required = new List<string>(d.RequiredDatasets ?? new() { d.Dataset });
        if (d.RequiredDatasets is null)
        {
            if (d.ApplicableWhen is { Dataset: { Length: > 0 } ad } && !required.Contains(ad)) required.Add(ad);
            if (!string.IsNullOrEmpty(d.EvaluatedDataset) && !required.Contains(d.EvaluatedDataset!)) required.Add(d.EvaluatedDataset!);
        }
        foreach (var r in required) if (!DatasetCatalog.IsKnown(r)) errors.Add($"requiredDatasets: dataset desconhecido '{r}'.");

        var meta = new RuleMetadata(d.RuleId ?? "", d.Title, d.Description, d.Category, d.Module, sev, d.Condition, d.Risk, d.Recommendation, resolved, required);

        if (d.Placeholder)
        {
            if (ds.HasCollector) errors.Add("placeholder=true is only allowed for datasets without a collector.");
            return errors.Count > 0 ? null : new JsonRule(d, meta, ds, null, null, null, null, null, null, null, null, ObjectKind.Other, Array.Empty<(PropertyInfo, EvidenceDef)>());
        }

        if (!ds.HasCollector || ds.ItemType is null) { errors.Add($"dataset '{d.Dataset}' has no collector; use placeholder=true."); return null; }
        var t = ds.ItemType;

        Predicate? scope = d.Scope is null ? null : ConditionCompiler.Compile(d.Scope, t, errors, "scope");
        Predicate? where = d.Where is null ? null : ConditionCompiler.Compile(d.Where, t, errors, "where");

        Predicate? applicable = null; DatasetDefinition? appDs = null;
        if (d.ApplicableWhen is { } aw)
        {
            if (!DatasetCatalog.TryGet(aw.Dataset, out appDs) || appDs.ItemType is null) errors.Add($"applicableWhen: invalid dataset '{aw.Dataset}'.");
            else applicable = aw.Where is null ? (_, _) => true : ConditionCompiler.Compile(aw.Where, appDs.ItemType, errors, "applicableWhen.where");
        }

        DatasetDefinition? evalDs = null;
        if (!string.IsNullOrEmpty(d.EvaluatedDataset) && (!DatasetCatalog.TryGet(d.EvaluatedDataset!, out evalDs) || !evalDs.HasCollector))
            errors.Add($"invalid evaluatedDataset '{d.EvaluatedDataset}'.");

        PropertyInfo? np = null, dp = null, dnp = null;
        var kind = ObjectKind.Other;
        if (d.Affected is null) errors.Add("field 'affected' is required.");
        else
        {
            np = ConditionCompiler.FindProperty(t, d.Affected.Name);
            if (np is null) errors.Add($"affected.name '{d.Affected.Name}' does not exist on {t.Name}.");
            if (!Enum.TryParse(d.Affected.Kind, true, out kind)) errors.Add($"invalid affected.kind '{d.Affected.Kind}'.");
            if (d.Affected.Domain is not null && (dp = ConditionCompiler.FindProperty(t, d.Affected.Domain)) is null) errors.Add($"affected.domain '{d.Affected.Domain}' inexistente.");
            if (d.Affected.Dn is not null && (dnp = ConditionCompiler.FindProperty(t, d.Affected.Dn)) is null) errors.Add($"affected.dn '{d.Affected.Dn}' inexistente.");
        }

        if (d.Evidence.Count == 0) errors.Add("at least one 'evidence' item is required (no finding without evidence).");
        var ev = new List<(PropertyInfo, EvidenceDef)>();
        foreach (var e in d.Evidence)
        {
            var p = ConditionCompiler.FindProperty(t, e.Property);
            if (p is null) errors.Add($"evidence.property '{e.Property}' does not exist on {t.Name}."); else ev.Add((p, e));
        }

        return errors.Count > 0 ? null : new JsonRule(d, meta, ds, scope, where, applicable, appDs, evalDs, np, dp, dnp, kind, ev.ToArray());
    }
}
