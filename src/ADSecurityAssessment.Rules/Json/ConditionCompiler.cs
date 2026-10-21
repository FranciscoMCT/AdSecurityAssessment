using System.Collections;
using System.Globalization;
using System.Reflection;
using System.Text.Json;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Rules.Json;

public delegate bool Predicate(object item, AssessmentSettings settings);

/// <summary>
/// Compila a árvore de condições JSON em delegates. Somente: leitura de propriedades públicas dos tipos de dataset (lista fechada),
/// operadores fechados e valores literais. Não interpreta código, expressões livres nem regex.
/// </summary>
public static class ConditionCompiler
{
    public static readonly IReadOnlySet<string> Operators = new HashSet<string>(StringComparer.Ordinal)
    {
        "eq", "ne", "gt", "ge", "lt", "le", "contains", "startsWith", "endsWith", "in", "notIn",
        "isNull", "notNull", "hasFlag", "notHasFlag", "countGt", "countEq", "countLt", "empty", "notEmpty"
    };

    private static readonly HashSet<string> NoValueOps = new(StringComparer.Ordinal) { "isNull", "notNull", "empty", "notEmpty" };

    public static PropertyInfo? FindProperty(Type t, string name) =>
        t.GetProperty(name, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase) is { CanRead: true } p
        && p.GetIndexParameters().Length == 0 ? p : null;

    public static Predicate Compile(ConditionNode node, Type itemType, List<string> errors, string path = "where")
    {
        var kinds = (node.All is not null ? 1 : 0) + (node.Any is not null ? 1 : 0) + (node.Not is not null ? 1 : 0) + (node.Field is not null ? 1 : 0);
        if (kinds != 1) { errors.Add($"{path}: the node must have exactly one of all/any/not/field."); return (_, _) => false; }

        if (node.All is not null)
        {
            var kids = node.All.Select((n, i) => Compile(n, itemType, errors, $"{path}.all[{i}]")).ToArray();
            return (o, s) => { foreach (var k in kids) if (!k(o, s)) return false; return true; };
        }
        if (node.Any is not null)
        {
            var kids = node.Any.Select((n, i) => Compile(n, itemType, errors, $"{path}.any[{i}]")).ToArray();
            return (o, s) => { foreach (var k in kids) if (k(o, s)) return true; return false; };
        }
        if (node.Not is not null)
        {
            var inner = Compile(node.Not, itemType, errors, path + ".not");
            return (o, s) => !inner(o, s);
        }

        // folha
        var prop = FindProperty(itemType, node.Field!);
        if (prop is null) { errors.Add($"{path}: field '{node.Field}' does not exist on {itemType.Name}."); return (_, _) => false; }
        var op = node.Op ?? "";
        if (!Operators.Contains(op)) { errors.Add($"{path}: operator '{op}' is not allowed."); return (_, _) => false; }

        var sources = (node.Value is not null ? 1 : 0) + (node.ValueField is not null ? 1 : 0) + (node.ValueSetting is not null ? 1 : 0);
        if (NoValueOps.Contains(op))
        {
            if (sources != 0) errors.Add($"{path}: operator '{op}' does not accept a value.");
        }
        else if (sources != 1) errors.Add($"{path}: informe exatamente um de value/valueField/valueSetting.");

        Func<object, AssessmentSettings, object?> right = (_, _) => null;
        if (node.Value is { } je) { var lit = FromJson(je); right = (_, _) => lit; }
        else if (node.ValueField is not null)
        {
            var rp = FindProperty(itemType, node.ValueField);
            if (rp is null) errors.Add($"{path}: valueField '{node.ValueField}' does not exist on {itemType.Name}.");
            else right = (o, _) => Normalize(rp.GetValue(o));
        }
        else if (node.ValueSetting is not null)
        {
            var sp = FindProperty(typeof(AssessmentSettings), node.ValueSetting);
            if (sp is null || !IsNumeric(sp.PropertyType)) errors.Add($"{path}: valueSetting '{node.ValueSetting}' is not a numeric setting.");
            else right = (_, s) => Normalize(sp.GetValue(s));
        }

        return (o, s) => Apply(Normalize(prop.GetValue(o)), op, right(o, s));
    }

    private static bool IsNumeric(Type t) => t == typeof(int) || t == typeof(long) || t == typeof(double);

    private static object? FromJson(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.Number => e.GetDouble(),
        JsonValueKind.String => e.GetString(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Array => e.EnumerateArray().Select(FromJson).ToList(),
        _ => null
    };

    public static object? Normalize(object? v) => v switch
    {
        null => null,
        bool or string or DateTimeOffset => v,
        int i => (double)i,
        long l => (double)l,
        short sh => (double)sh,
        byte b => (double)b,
        double d => d,
        float f => (double)f,
        decimal m => (double)m,
        Enum e => e.ToString(),
        IEnumerable<string> list => list.ToList(),
        _ => v.ToString()
    };

    private static bool EqualsValue(object? l, object? r)
    {
        if (l is null || r is null) return false;
        if (l is double ld && r is double rd) return Math.Abs(ld - rd) < 1e-9;
        if (l is bool lb && r is bool rb) return lb == rb;
        if (l is string ls && r is string rs) return string.Equals(ls, rs, StringComparison.OrdinalIgnoreCase);
        if (l is DateTimeOffset a && r is DateTimeOffset b) return a == b;
        return false;
    }

    private static int? Cmp(object? l, object? r)
    {
        if (l is double a && r is double b) return a.CompareTo(b);
        if (l is DateTimeOffset x && r is DateTimeOffset y) return x.CompareTo(y);
        return null;
    }

    private static int? Count(object? v) => v switch
    {
        null => null,
        string s => s.Length,
        ICollection c => c.Count,
        IEnumerable<string> e => e.Count(),
        _ => null
    };

    public static bool Apply(object? l, string op, object? r)
    {
        switch (op)
        {
            case "isNull": return l is null;
            case "notNull": return l is not null;
            case "eq": return EqualsValue(l, r);
            case "ne": return l is null || r is null ? l is null != r is null : !EqualsValue(l, r);
            case "gt": return Cmp(l, r) is > 0;
            case "ge": return Cmp(l, r) is >= 0;
            case "lt": return Cmp(l, r) is < 0;
            case "le": return Cmp(l, r) is <= 0;
            case "contains":
                if (l is string s1 && r is string r1) return s1.Contains(r1, StringComparison.OrdinalIgnoreCase);
                if (l is IEnumerable<string> list && r is string r2) return list.Any(x => string.Equals(x, r2, StringComparison.OrdinalIgnoreCase));
                return false;
            case "startsWith": return l is string a1 && r is string b1 && a1.StartsWith(b1, StringComparison.OrdinalIgnoreCase);
            case "endsWith": return l is string a2 && r is string b2 && a2.EndsWith(b2, StringComparison.OrdinalIgnoreCase);
            case "in": return r is List<object?> inList && inList.Any(x => EqualsValue(l, Normalize(x)));
            case "notIn": return l is not null && r is List<object?> nl && !nl.Any(x => EqualsValue(l, Normalize(x)));
            case "hasFlag":
                return l is double f1 && r is double m1 && (((long)f1) & ((long)m1)) == (long)m1;
            case "notHasFlag":
                return l is double f2 && r is double m2 && (((long)f2) & ((long)m2)) == 0;
            case "countGt": return Count(l) is { } c1 && r is double d1 && c1 > d1;
            case "countEq": return Count(l) is { } c2 && r is double d2 && c2 == (int)d2;
            case "countLt": return Count(l) is { } c3 && r is double d3 && c3 < d3;
            case "empty": return Count(l) is 0 || l is null;
            case "notEmpty": return Count(l) is > 0;
            default: return false;
        }
    }

    public static string Format(object? v, string? format = null)
    {
        switch (v)
        {
            case null: return "(not set)";
            case DateTimeOffset d: return d.ToUniversalTime().ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture);
            case bool b: return b ? "True" : "False";
            case int i when format == "hex": return $"0x{i:X} ({i})";
            case long l when format == "hex": return $"0x{l:X} ({l})";
            case string s: return s;
            case IEnumerable<string> list:
                var items = list.ToList();
                if (items.Count == 0) return "(none)";
                return string.Join("; ", items.Take(10)) + (items.Count > 10 ? $" … (+{items.Count - 10})" : "");
            case IFormattable f: return f.ToString(null, CultureInfo.InvariantCulture);
            default: return v.ToString() ?? "";
        }
    }
}
