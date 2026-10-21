using System.Text;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Reporting;

/// <summary>
/// CSV (UTF-8 com BOM, para abrir corretamente no Excel): uma linha por objeto afetado de cada finding, mais uma linha por regra
/// Not Evaluated / Not Applicable. Células que começam com = + - @ recebem apóstrofo (proteção contra CSV/formula injection:
/// nomes de objetos do AD são dados não confiáveis).
/// </summary>
public sealed class CsvReportExporter : IReportExporter
{
    private static readonly string[] Header =
    {
        "Status", "RuleId", "Severity", "Category", "Module", "Title", "AffectedObject", "ObjectType", "Domain", "DistinguishedName",
        "Evidence", "Risk", "Recommendation", "References", "Reason", "DemoData"
    };

    public string Format => "CSV";
    public string FileExtension => ".csv";

    public async Task ExportAsync(AssessmentResult result, string path, CancellationToken cancellationToken) =>
        await ReportFiles.WriteTextAtomicAsync(path, Build(result), cancellationToken, ReportFiles.Utf8Bom).ConfigureAwait(false);

    public static string Build(AssessmentResult r)
    {
        var sb = new StringBuilder(64 * 1024);
        Row(sb, Header);
        var demo = r.IsDemo ? "DEMO DATA" : "";
        foreach (var f in ReportQueries.OrderedFindings(r))
        {
            var refs = string.Join(" ; ", f.References.Select(x => x.Url));
            var evidenceByObject = f.Evidence.GroupBy(e => e.ObjectName, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => string.Join(" ; ", g.Select(e => $"{e.Property}={e.Value ?? "(not set)"}" + (e.Expected is null ? "" : $" [expected: {e.Expected}]"))), StringComparer.OrdinalIgnoreCase);
            foreach (var a in f.AffectedObjects)
                Row(sb, "Finding", f.RuleId, f.Severity.ToString(), f.Category, f.Module, f.Title, a.Name, a.Kind.ToString(), a.Domain ?? "", a.DistinguishedName ?? "",
                    evidenceByObject.GetValueOrDefault(a.Name, ""), f.Risk, f.Recommendation, refs, "", demo);
        }
        foreach (var e in r.Evaluations.Where(e => e.Outcome is RuleOutcome.NotEvaluated or RuleOutcome.NotApplicable).OrderBy(e => e.Rule.RuleId, StringComparer.OrdinalIgnoreCase))
            Row(sb, e.Outcome.ToString(), e.Rule.RuleId, e.Rule.Severity.ToString(), e.Rule.Category, e.Rule.Module, e.Rule.Title, "", "", "", "", "", e.Rule.Risk, e.Rule.Recommendation,
                string.Join(" ; ", e.Rule.References.Select(x => x.Url)), e.Reason ?? "", demo);
        return sb.ToString();
    }

    private static void Row(StringBuilder sb, params string[] cells)
    {
        for (var i = 0; i < cells.Length; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append(Escape(cells[i]));
        }
        sb.Append("\r\n");
    }

    internal static string Escape(string value)
    {
        if (value.Length > 0 && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r') value = "'" + value;
        var needsQuotes = value.AsSpan().IndexOfAny(",\"\r\n") >= 0;
        return needsQuotes ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;
    }
}
