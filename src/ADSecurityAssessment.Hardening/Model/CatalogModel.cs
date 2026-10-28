using System.Text.Json;

namespace ADSecurityAssessment.Hardening.Model;

/// <summary>Tipos de valor de registro suportados (o suficiente para os baselines; nada além disso é aceito).</summary>
public enum RegType { Dword, String, MultiString }

/// <summary>Documento do catálogo (hardening/catalog.json). Esquema FECHADO: campo desconhecido invalida o arquivo.</summary>
public sealed class CatalogDoc
{
    public string CatalogVersion { get; set; } = "";
    public List<ProfileDef> Profiles { get; set; } = new();
    public List<SettingDef> Settings { get; set; } = new();
    public List<AccountPolicyDef> AccountPolicy { get; set; } = new();
}

public sealed class ProfileDef
{
    public string Id { get; set; } = "";
    /// <summary>"gpo" (gera uma GPO) ou "advice" (apenas avalia e orienta).</summary>
    public string Kind { get; set; } = "gpo";
    public string Title { get; set; } = "";
    public string GpoName { get; set; } = "";
    public string LinkTarget { get; set; } = "";
    public string Description { get; set; } = "";
}

public sealed class SettingDef
{
    public string Id { get; set; } = "";
    public string Category { get; set; } = "";
    public string Title { get; set; } = "";
    public List<string> Scopes { get; set; } = new();
    /// <summary>low | medium | high — risco de quebrar algo em produção.</summary>
    public string Risk { get; set; } = "low";
    /// <summary>Marcada por padrão no plano. Configurações de alto risco são sempre opt-in.</summary>
    public bool DefaultOn { get; set; }
    public string Rationale { get; set; } = "";
    public string Impact { get; set; } = "";
    public string? Prerequisite { get; set; }
    public List<string>? Requires { get; set; }
    public List<string> References { get; set; } = new();
    public List<EntryDef> Entries { get; set; } = new();
}

/// <summary>Uma escrita concreta. via = template (GptTmpl.inf [Registry Values]) | pol (registry.pol) | audit (audit.csv).</summary>
public sealed class EntryDef
{
    public string Via { get; set; } = "";
    // template
    public string? Path { get; set; }
    // pol
    public string? Key { get; set; }
    public string? Name { get; set; }
    // template + pol
    public string? Type { get; set; }
    public JsonElement? Value { get; set; }
    public JsonElement? Revert { get; set; }
    /// <summary>Valor de reversão específico para Controladores de Domínio (quando difere do padrão).</summary>
    public JsonElement? RevertDc { get; set; }
    /// <summary>Reversão = apagar o valor (pol).</summary>
    public bool RevertDelete { get; set; }
    // audit
    public string? Subcategory { get; set; }
    public bool? Success { get; set; }
    public bool? Failure { get; set; }
}

public sealed class AccountPolicyDef
{
    public string Id { get; set; } = "";
    public string Label { get; set; } = "";
    /// <summary>minPwdLength | pwdProperties | minPwdAgeDays | pwdHistoryLength | lockoutThreshold | lockoutDurationMinutes | lockoutObservationMinutes</summary>
    public string Attribute { get; set; } = "";
    /// <summary>gte | bit1 | range1-10</summary>
    public string Comparison { get; set; } = "";
    public int Recommended { get; set; }
    public string Unit { get; set; } = "";
    public string Note { get; set; } = "";
    public string Reference { get; set; } = "";
}

/// <summary>Valor tipado já validado.</summary>
public static class RegValues
{
    public static string TypeName(RegType t) => t switch { RegType.Dword => "dword", RegType.String => "string", _ => "multistring" };

    public static bool TryParseType(string? s, out RegType type)
    {
        switch (s)
        {
            case "dword": type = RegType.Dword; return true;
            case "string": type = RegType.String; return true;
            case "multistring": type = RegType.MultiString; return true;
            default: type = RegType.Dword; return false;
        }
    }

    /// <summary>Converte o JSON no tipo .NET correspondente (uint | string | string[]) ou devolve o motivo da recusa.</summary>
    public static bool TryConvert(JsonElement e, RegType type, out object data, out string error)
    {
        data = 0u; error = "";
        switch (type)
        {
            case RegType.Dword:
                if (e.ValueKind != JsonValueKind.Number || !e.TryGetInt64(out var n) || n < 0 || n > uint.MaxValue) { error = "valor dword deve ser inteiro entre 0 e 4294967295"; return false; }
                data = (uint)n; return true;
            case RegType.String:
                if (e.ValueKind != JsonValueKind.String) { error = "valor string deve ser texto"; return false; }
                var s = e.GetString() ?? "";
                if (s.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0) { error = "texto não pode conter quebra de linha ou NUL"; return false; }
                data = s; return true;
            default:
                if (e.ValueKind != JsonValueKind.Array) { error = "valor multistring deve ser lista de textos"; return false; }
                var list = new List<string>();
                foreach (var item in e.EnumerateArray())
                {
                    if (item.ValueKind != JsonValueKind.String) { error = "multistring só aceita textos"; return false; }
                    var t = item.GetString() ?? "";
                    if (t.Length == 0 || t.IndexOfAny(new[] { '\r', '\n', '\0', ',' }) >= 0) { error = "item multistring vazio ou com caractere inválido"; return false; }
                    list.Add(t);
                }
                data = list.ToArray(); return true;
        }
    }

    public static string Display(RegType type, object? data) => data switch
    {
        null => "(apagar valor)",
        uint u => u.ToString(System.Globalization.CultureInfo.InvariantCulture),
        string s => s,
        string[] a => string.Join(" | ", a),
        _ => data.ToString() ?? ""
    };
}
