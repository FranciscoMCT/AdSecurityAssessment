using System.Text.Json;
using System.Text.Json.Serialization;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Reporting;

/// <summary>Exportação JSON completa (todos os objetos afetados e evidências), com esquema versionado para integração futura.</summary>
public sealed class JsonReportExporter : IReportExporter
{
    public const int SchemaVersion = 1;

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public string Format => "JSON";
    public string FileExtension => ".json";

    public async Task ExportAsync(AssessmentResult result, string path, CancellationToken cancellationToken) =>
        await ReportFiles.WriteTextAtomicAsync(path, Serialize(result), cancellationToken).ConfigureAwait(false);

    public static string Serialize(AssessmentResult r)
    {
        var doc = new
        {
            schemaVersion = SchemaVersion,
            notice = r.IsDemo ? ExportWarning.DemoMessage : ExportWarning.Message,
            isDemo = r.IsDemo,
            metadata = r.Metadata,
            score = r.Score,
            environment = r.Environment,
            collectors = r.CollectorRuns,
            datasets = r.Datasets,
            // Resultado por regra SEM duplicar o finding (os findings completos vêm em "findings").
            ruleResults = r.Evaluations.OrderBy(e => e.Rule.RuleId, StringComparer.OrdinalIgnoreCase).Select(e => new
            {
                ruleId = e.Rule.RuleId, title = e.Rule.Title, category = e.Rule.Category, module = e.Rule.Module, severity = e.Rule.Severity,
                outcome = e.Outcome, reason = e.Reason, objectsEvaluated = e.ObjectsEvaluated, objectsAffected = e.ObjectsAffected
            }),
            findings = ReportQueries.OrderedFindings(r)
        };
        return JsonSerializer.Serialize(doc, Options);
    }
}
