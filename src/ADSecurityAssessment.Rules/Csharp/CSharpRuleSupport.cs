using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Rules.Csharp;

internal static class Meta
{
    public static RuleMetadata Create(ReferenceCatalog refs, string id, string title, string description, string category, string module,
        Severity severity, string condition, string risk, string recommendation, string[] referenceKeys, string[] datasets) =>
        new(id, title, description, category, module, severity, condition, risk, recommendation, refs.ResolveAll(referenceKeys), datasets);
}

/// <summary>Verificação de suporte do SO contra data/os-lifecycle.json (datas oficiais). SO desconhecido → null (Not Evaluated).</summary>
internal static class OsSupport
{
    public sealed record Result(OsProduct Product, bool ExtendedSupportEnded, bool UnderEsuOnly);

    public static Result? Check(OsLifecycleCatalog catalog, string? productKey, DateTimeOffset now)
    {
        if (productKey is null) return null;
        var p = catalog.Products.FirstOrDefault(x => x.Key == productKey);
        if (p?.ExtendedEnd is null) return null;
        var ended = now >= p.ExtendedEnd.Value;
        var esu = ended && p.EsuEnd is not null && now < p.EsuEnd.Value;
        return new Result(p, ended, esu);
    }

    public static string Describe(Result r) =>
        r.ExtendedSupportEnded
            ? $"{r.Product.Name}: extended support ended {r.Product.ExtendedEnd:yyyy-MM-dd}" +
              (r.Product.EsuEnd is { } e ? $"; last ESU period {(r.UnderEsuOnly ? "ends" : "ended")} {e:yyyy-MM-dd}" : "; no ESU listed")
            : $"{r.Product.Name}: extended support until {r.Product.ExtendedEnd:yyyy-MM-dd}";
}
