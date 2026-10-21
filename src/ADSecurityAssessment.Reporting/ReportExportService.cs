using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Reporting;

/// <summary>
/// Orquestra exportações LOCAIS. Não há nenhum cliente de rede neste projeto. A UI deve exibir <see cref="ExportWarning"/> e obter
/// confirmação do usuário antes de chamar <see cref="ExportAsync"/>. Para adicionar PDF: implemente IReportExporter e registre aqui.
/// </summary>
public sealed class ReportExportService
{
    private readonly IReadOnlyList<IReportExporter> _exporters;
    private readonly IAssessmentLog _log;

    public ReportExportService(string? templateDirectory = null, IAssessmentLog? log = null, IEnumerable<IReportExporter>? extraExporters = null)
    {
        var list = new List<IReportExporter> { new HtmlReportExporter(templateDirectory), new JsonReportExporter(), new CsvReportExporter() };
        if (extraExporters is not null) list.AddRange(extraExporters);
        _exporters = list;
        _log = log ?? NullAssessmentLog.Instance;
    }

    public IReadOnlyList<IReportExporter> Exporters => _exporters;

    public async Task<IReadOnlyList<string>> ExportAsync(AssessmentResult result, string folder, IEnumerable<string> formats, CancellationToken ct)
    {
        Directory.CreateDirectory(folder);
        var stem = ReportQueries.FileStem(result);
        var written = new List<string>();
        foreach (var format in formats)
        {
            var exporter = _exporters.FirstOrDefault(e => e.Format.Equals(format, StringComparison.OrdinalIgnoreCase))
                           ?? throw new ArgumentException($"Unknown export format: {format}", nameof(formats));
            var path = Path.Combine(folder, stem + exporter.FileExtension);
            await exporter.ExportAsync(result, path, ct).ConfigureAwait(false);
            _log.Info($"{exporter.Format} report exported locally: {path}");
            written.Add(path);
        }
        return written;
    }
}
