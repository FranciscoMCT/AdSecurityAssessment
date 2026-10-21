using System.Text.Json;
using System.Text.Json.Serialization;

namespace ADSecurityAssessment.Rules.Json;

/// <summary>Esquema FECHADO das regras JSON. Não há campos para código, scripts, expressões livres ou regex.</summary>
public sealed class JsonRuleFile
{
    [JsonPropertyName("schemaVersion")] public int SchemaVersion { get; set; } = 1;
    [JsonPropertyName("rules")] public List<JsonRuleDef> Rules { get; set; } = new();
}

public sealed class JsonRuleDef
{
    [JsonPropertyName("ruleId")] public string RuleId { get; set; } = "";
    [JsonPropertyName("title")] public string Title { get; set; } = "";
    [JsonPropertyName("description")] public string Description { get; set; } = "";
    [JsonPropertyName("category")] public string Category { get; set; } = "";
    [JsonPropertyName("module")] public string Module { get; set; } = "";
    [JsonPropertyName("severity")] public string Severity { get; set; } = "";
    [JsonPropertyName("condition")] public string Condition { get; set; } = "";
    [JsonPropertyName("risk")] public string Risk { get; set; } = "";
    [JsonPropertyName("recommendation")] public string Recommendation { get; set; } = "";
    [JsonPropertyName("references")] public List<string> References { get; set; } = new();

    [JsonPropertyName("dataset")] public string Dataset { get; set; } = "";
    [JsonPropertyName("requiredDatasets")] public List<string>? RequiredDatasets { get; set; }
    /// <summary>true = regra sem collector disponível: sempre "Not Evaluated" com o motivo do dataset.</summary>
    [JsonPropertyName("placeholder")] public bool Placeholder { get; set; }

    [JsonPropertyName("applicableWhen")] public ApplicabilityDef? ApplicableWhen { get; set; }
    /// <summary>Objetos no escopo da regra (denominador). Sem scope: todos os itens do dataset.</summary>
    [JsonPropertyName("scope")] public ConditionNode? Scope { get; set; }
    /// <summary>Condição de violação. Sem where: todo objeto no escopo é uma violação.</summary>
    [JsonPropertyName("where")] public ConditionNode? Where { get; set; }
    /// <summary>Dataset cujo total serve de "objetos avaliados" quando o dataset da regra só lista violações (ex.: gpp-passwords → gpos).</summary>
    [JsonPropertyName("evaluatedDataset")] public string? EvaluatedDataset { get; set; }

    [JsonPropertyName("affected")] public AffectedDef? Affected { get; set; }
    [JsonPropertyName("evidence")] public List<EvidenceDef> Evidence { get; set; } = new();
    [JsonPropertyName("evidenceSource")] public string? EvidenceSource { get; set; }
    [JsonPropertyName("notes")] public string? Notes { get; set; }
}

public sealed class ApplicabilityDef
{
    [JsonPropertyName("dataset")] public string Dataset { get; set; } = "";
    [JsonPropertyName("where")] public ConditionNode? Where { get; set; }
    [JsonPropertyName("reason")] public string Reason { get; set; } = "Not applicable to this environment.";
}

public sealed class AffectedDef
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("kind")] public string Kind { get; set; } = "Other";
    [JsonPropertyName("domain")] public string? Domain { get; set; }
    [JsonPropertyName("dn")] public string? Dn { get; set; }
}

public sealed class EvidenceDef
{
    [JsonPropertyName("property")] public string Property { get; set; } = "";
    [JsonPropertyName("expected")] public string? Expected { get; set; }
    /// <summary>"hex" para exibir bitmasks (ex.: userAccountControl). Padrão: texto normal.</summary>
    [JsonPropertyName("format")] public string? Format { get; set; }
    [JsonPropertyName("label")] public string? Label { get; set; }
}

/// <summary>Árvore de condições: all / any / not / folha (field + op + value|valueField|valueSetting).</summary>
public sealed class ConditionNode
{
    [JsonPropertyName("all")] public List<ConditionNode>? All { get; set; }
    [JsonPropertyName("any")] public List<ConditionNode>? Any { get; set; }
    [JsonPropertyName("not")] public ConditionNode? Not { get; set; }

    [JsonPropertyName("field")] public string? Field { get; set; }
    [JsonPropertyName("op")] public string? Op { get; set; }
    [JsonPropertyName("value")] public JsonElement? Value { get; set; }
    [JsonPropertyName("valueField")] public string? ValueField { get; set; }
    /// <summary>Nome de uma propriedade NUMÉRICA de AssessmentSettings (ex.: StaleAccountDays).</summary>
    [JsonPropertyName("valueSetting")] public string? ValueSetting { get; set; }
}
