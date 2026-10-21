using System.Globalization;
using System.Net;
using System.Text;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Reporting;

/// <summary>
/// Relatório HTML autocontido (sem JavaScript, sem recursos externos; CSP bloqueia qualquer carga de rede) com estilos de impressão —
/// "Imprimir → PDF" do navegador funciona hoje; um exportador PDF nativo futuro implementa a mesma interface <see cref="IReportExporter"/>.
/// Seções: Executive Summary, Environment Summary, Overall Risk, Assessment Coverage, Critical Findings, High Findings,
/// Findings by Category, Technical Findings, Evidence, Recommendations, References.
/// </summary>
public sealed class HtmlReportExporter : IReportExporter
{
    private const int MaxRowsPerTable = 100;
    private readonly string? _templateDirectory;

    public HtmlReportExporter(string? templateDirectory = null) { _templateDirectory = templateDirectory; }

    public string Format => "HTML";
    public string FileExtension => ".html";

    public async Task ExportAsync(AssessmentResult result, string path, CancellationToken cancellationToken)
    {
        var html = Render(result);
        await ReportFiles.WriteTextAtomicAsync(path, html, cancellationToken).ConfigureAwait(false);
    }

    public string Render(AssessmentResult r)
    {
        var template = LoadTemplate();
        var body = new StringBuilder(64 * 1024);
        var title = r.IsDemo ? "DEMO — AD Security Assessment Report" : "AD Security Assessment Report";

        Cover(body, r, title);
        Toc(body);
        ExecutiveSummary(body, r);
        EnvironmentSummary(body, r);
        OverallRisk(body, r);
        Coverage(body, r);
        SeveritySection(body, r, "critical-findings", "Critical Findings", Severity.Critical);
        SeveritySection(body, r, "high-findings", "High Findings", Severity.High);
        ByCategory(body, r);
        TechnicalFindings(body, r);
        EvidenceSection(body, r);
        Recommendations(body, r);
        References(body, r);

        var footer = $"{E(AssessmentOrchestratorName(r))} {E(r.Metadata.ToolVersion)} · read-only assessment · generated locally {r.Metadata.FinishedAt.ToLocalTime():yyyy-MM-dd HH:mm zzz}" +
                     (r.IsDemo ? " · DEMO DATA" : "");
        return template
            .Replace("{{TITLE}}", E(title))
            .Replace("{{GENERATOR}}", E($"{r.Metadata.ToolName} {r.Metadata.ToolVersion}"))
            .Replace("{{FOOTER}}", footer)
            .Replace("{{BODY}}", body.ToString());
    }

    private static string AssessmentOrchestratorName(AssessmentResult r) => r.Metadata.ToolName;

    private string LoadTemplate()
    {
        if (_templateDirectory is not null)
        {
            var file = Path.Combine(_templateDirectory, "report-template.html");
            try { if (File.Exists(file)) return File.ReadAllText(file); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* usa o embutido */ }
        }
        using var s = typeof(HtmlReportExporter).Assembly.GetManifestResourceStream("templates/report-template.html")
                      ?? throw new InvalidOperationException("The embedded report template was not found.");
        using var reader = new StreamReader(s, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    // ------------------------------------------------------------------ seções
    private static void Cover(StringBuilder b, AssessmentResult r, string title)
    {
        b.Append("<header class=\"cover\"><h1>").Append(E(title)).Append("</h1>");
        b.Append("<p>Target: <strong>").Append(E(r.Metadata.Target)).Append("</strong></p>");
        b.Append("<p>Assessment ID ").Append(E(r.Metadata.AssessmentId)).Append(" · started ").Append(Dt(r.Metadata.StartedAt))
         .Append(" · finished ").Append(Dt(r.Metadata.FinishedAt)).Append(" · executed by ").Append(E(r.Metadata.ExecutedBy)).Append("</p></header>");
        if (r.IsDemo) b.Append("<div class=\"notice demo\">").Append(E(ExportWarning.DemoMessage)).Append("</div>");
        b.Append("<div class=\"notice\"><strong>").Append(E(ExportWarning.Title)).Append(".</strong> ").Append(E(ExportWarning.Message)).Append("</div>");
    }

    private static void Toc(StringBuilder b)
    {
        b.Append("<nav class=\"toc\">");
        foreach (var (id, text) in new[]
        {
            ("executive-summary", "Executive Summary"), ("environment", "Environment Summary"), ("overall-risk", "Overall Risk"),
            ("coverage", "Assessment Coverage"), ("critical-findings", "Critical Findings"), ("high-findings", "High Findings"),
            ("by-category", "Findings by Category"), ("technical", "Technical Findings"), ("evidence", "Evidence"),
            ("recommendations", "Recommendations"), ("references", "References")
        })
            b.Append("<a href=\"#").Append(id).Append("\">").Append(text).Append("</a>");
        b.Append("</nav>");
    }

    private static void ExecutiveSummary(StringBuilder b, AssessmentResult r)
    {
        var o = r.Score.Overall;
        b.Append("<section id=\"executive-summary\"><h2>Executive Summary</h2>");
        b.Append("<div class=\"grid\">");
        Card(b, o.SecurityScore is null ? "n/a" : o.SecurityScore.Value.ToString("0.0", CultureInfo.InvariantCulture), "Security score (0–100)" + (r.Score.IsProvisional ? " · PROVISIONAL" : ""));
        Card(b, o.Rating ?? "Not scored", "Rating");
        Card(b, o.CoveragePercent.ToString("0", CultureInfo.InvariantCulture) + "%", "Assessment coverage");
        foreach (var s in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low })
            Card(b, ReportQueries.CountBySeverity(r, s).ToString(CultureInfo.InvariantCulture), $"{s} findings");
        b.Append("</div>");

        var total = r.Findings.Count;
        b.Append("<p>The assessment of <strong>").Append(E(r.Metadata.Target)).Append("</strong> evaluated ").Append(r.Evaluations.Count)
         .Append(" deterministic rules in read-only mode. ").Append(total).Append(total == 1 ? " finding was" : " findings were").Append(" raised; ")
         .Append(r.Evaluations.Count(e => e.Outcome == RuleOutcome.NotEvaluated)).Append(" rules could not be evaluated and ")
         .Append(r.Evaluations.Count(e => e.Outcome == RuleOutcome.NotApplicable)).Append(" are not applicable to this environment.</p>");
        if (r.Score.IsProvisional) b.Append("<div class=\"notice\">").Append(E(r.Score.ProvisionalReason ?? "")).Append("</div>");

        var top = ReportQueries.OrderedFindings(r).Where(f => f.Severity >= Severity.High).Take(8).ToList();
        if (top.Count > 0)
        {
            b.Append("<h3>Top priorities</h3><ol>");
            foreach (var f in top)
                b.Append("<li><a href=\"#f-").Append(E(f.RuleId)).Append("\">").Append(E(f.RuleId)).Append("</a> — ").Append(E(f.Title))
                 .Append(" <span class=\"muted\">(").Append(f.AffectedObjects.Count).Append(" object(s))</span></li>");
            b.Append("</ol>");
        }
        else b.Append("<p>No Critical or High findings were raised by the rules that could be evaluated. This is not a statement about areas listed under Assessment Coverage as not evaluated.</p>");
        b.Append("</section>");
    }

    private static void EnvironmentSummary(StringBuilder b, AssessmentResult r)
    {
        var e = r.Environment;
        b.Append("<section id=\"environment\"><h2>Environment Summary</h2><div class=\"grid\">");
        Card(b, E(e.ForestName ?? "unknown"), "Forest", raw: true);
        Card(b, E(e.ForestFunctionalLevel ?? "unknown"), "Forest functional level", raw: true);
        Card(b, e.Domains.Count.ToString(CultureInfo.InvariantCulture), "Domains");
        Card(b, $"{e.DomainControllerCount} ({e.ReadOnlyDomainControllerCount} RODC)", "Domain controllers");
        Card(b, e.GlobalCatalogCount.ToString(CultureInfo.InvariantCulture), "Global catalogs");
        Card(b, e.SiteCount.ToString(CultureInfo.InvariantCulture), "Sites");
        Card(b, e.TrustCount.ToString(CultureInfo.InvariantCulture), "Trusts");
        Card(b, $"{e.EnabledUserCount:N0} / {e.UserCount:N0}", "Enabled / total users");
        Card(b, e.ComputerCount.ToString("N0", CultureInfo.InvariantCulture), "Computers");
        Card(b, e.PrivilegedAccountCount.ToString("N0", CultureInfo.InvariantCulture), "Privileged users");
        Card(b, e.GpoCount.ToString("N0", CultureInfo.InvariantCulture), "GPOs");
        Card(b, e.AdCsDetected ? "Detected" : "Not detected", "AD CS");
        Card(b, e.HybridDetected ? "Evidence found" : "No evidence", "Hybrid identity");
        b.Append("</div>");

        if (e.Domains.Count > 0)
        {
            b.Append("<h3>Domains</h3><table><tr><th>Domain</th><th>NetBIOS</th><th>Functional level</th><th class=\"num\">DCs</th><th class=\"num\">Users (enabled)</th><th class=\"num\">Computers</th><th>PDC emulator</th></tr>");
            foreach (var d in e.Domains)
                b.Append("<tr><td>").Append(E(d.Name)).Append("</td><td>").Append(E(d.NetBiosName ?? "")).Append("</td><td>").Append(E(d.FunctionalLevel))
                 .Append("</td><td class=\"num\">").Append(d.DomainControllers).Append("</td><td class=\"num\">").Append(d.Users.ToString("N0", CultureInfo.InvariantCulture)).Append(" (").Append(d.EnabledUsers.ToString("N0", CultureInfo.InvariantCulture))
                 .Append(")</td><td class=\"num\">").Append(d.Computers.ToString("N0", CultureInfo.InvariantCulture)).Append("</td><td>").Append(E(d.Pdc ?? "")).Append("</td></tr>");
            b.Append("</table>");
        }
        if (e.FsmoRoles.Count > 0)
        {
            b.Append("<h3>FSMO roles</h3><ul>");
            foreach (var f in e.FsmoRoles) b.Append("<li>").Append(E(f)).Append("</li>");
            b.Append("</ul>");
        }
        if (e.DomainControllerOperatingSystems.Count > 0)
            b.Append("<h3>Domain controller operating systems</h3><p>").Append(E(string.Join(" · ", e.DomainControllerOperatingSystems))).Append("</p>");
        b.Append("</section>");
    }

    private static void OverallRisk(StringBuilder b, AssessmentResult r)
    {
        var o = r.Score.Overall;
        b.Append("<section id=\"overall-risk\"><h2>Overall Risk</h2>");
        b.Append("<p><span class=\"score\">").Append(o.SecurityScore is null ? "n/a" : o.SecurityScore.Value.ToString("0.0", CultureInfo.InvariantCulture))
         .Append("</span> <span class=\"muted\">/ 100 · risk ").Append(o.RiskScore is null ? "n/a" : o.RiskScore.Value.ToString("0.0", CultureInfo.InvariantCulture))
         .Append("% · ").Append(E(o.Rating ?? "not scored")).Append(o.CapApplied ? " · severity cap applied" : "").Append("</span></p>");
        b.Append("<table><tr><th>Category</th><th class=\"num\">Security score</th><th>Rating</th><th class=\"num\">Critical</th><th class=\"num\">High</th><th class=\"num\">Medium</th><th class=\"num\">Low</th><th class=\"num\">Coverage</th></tr>");
        foreach (var c in r.Score.Categories)
        {
            b.Append("<tr><td>").Append(E(c.Category)).Append("</td><td class=\"num\">")
             .Append(c.Status == CategoryStatus.Scored ? c.SecurityScore!.Value.ToString("0.0", CultureInfo.InvariantCulture) : c.Status == CategoryStatus.NotApplicable ? "N/A" : "Not evaluated")
             .Append("</td><td>").Append(E(c.Rating ?? "—")).Append("</td><td class=\"num\">").Append(c.Critical).Append("</td><td class=\"num\">").Append(c.High)
             .Append("</td><td class=\"num\">").Append(c.Medium).Append("</td><td class=\"num\">").Append(c.Low).Append("</td><td class=\"num\">")
             .Append(c.CoveragePercent.ToString("0", CultureInfo.InvariantCulture)).Append("%</td></tr>");
        }
        b.Append("</table><details><summary>How the score is calculated</summary><p>").Append(E(r.Score.MethodSummary)).Append("</p>")
         .Append("<p class=\"muted\">Severity weights: ").Append(E(string.Join(", ", r.Score.Configuration.SeverityWeights.Select(kv => $"{kv.Key} = {kv.Value}"))))
         .Append(". Caps: ").Append(E(string.Join(", ", r.Score.Configuration.ScoreCaps.Select(kv => $"{kv.Key} finding ⇒ score ≤ {kv.Value}")))).Append(".</p></details></section>");
    }

    private static void Coverage(StringBuilder b, AssessmentResult r)
    {
        b.Append("<section id=\"coverage\"><h2>Assessment Coverage</h2>");
        b.Append("<p>Coverage is reported separately from risk: a category that could not be evaluated never improves the score.</p>");
        b.Append("<table><tr><th>Category</th><th>Status</th><th class=\"num\">Passed</th><th class=\"num\">Failed</th><th class=\"num\">Not evaluated</th><th class=\"num\">Not applicable</th><th>Coverage</th></tr>");
        foreach (var c in r.Score.Categories)
            b.Append("<tr><td>").Append(E(c.Category)).Append("</td><td>").Append(c.Status).Append("</td><td class=\"num\">").Append(c.Passed).Append("</td><td class=\"num\">").Append(c.Failed)
             .Append("</td><td class=\"num\">").Append(c.NotEvaluated).Append("</td><td class=\"num\">").Append(c.NotApplicable).Append("</td><td><div class=\"bar\"><i style=\"width:")
             .Append(Math.Clamp(c.CoveragePercent, 0, 100).ToString("0", CultureInfo.InvariantCulture)).Append("%\"></i></div> ").Append(c.CoveragePercent.ToString("0", CultureInfo.InvariantCulture)).Append("%</td></tr>");
        b.Append("</table>");

        b.Append("<h3>Collectors</h3><table><tr><th>Collector</th><th>Status</th><th class=\"num\">Objects</th><th class=\"num\">Seconds</th><th>Notes</th></tr>");
        foreach (var c in r.CollectorRuns)
            b.Append("<tr><td>").Append(E(c.DisplayName)).Append("</td><td>").Append(c.Status).Append("</td><td class=\"num\">").Append(c.ObjectCount.ToString("N0", CultureInfo.InvariantCulture))
             .Append("</td><td class=\"num\">").Append(c.Duration.TotalSeconds.ToString("0.0", CultureInfo.InvariantCulture)).Append("</td><td>")
             .Append(E(string.Join(" | ", c.Errors.Concat(c.Warnings).Take(4)))).Append("</td></tr>");
        b.Append("</table>");

        var ne = ReportQueries.NotEvaluated(r).ToList();
        b.Append("<h3>Rules not evaluated (").Append(ne.Count).Append(")</h3>");
        if (ne.Count == 0) b.Append("<p class=\"muted\">None.</p>");
        else
        {
            b.Append("<p>These checks were <strong>not</strong> assumed compliant. The reason is shown for each.</p><table><tr><th>Rule</th><th>Title</th><th>Reason</th></tr>");
            foreach (var e in ne) b.Append("<tr><td>").Append(E(e.Rule.RuleId)).Append("</td><td>").Append(E(e.Rule.Title)).Append("</td><td>").Append(E(e.Reason ?? "")).Append("</td></tr>");
            b.Append("</table>");
        }
        var na = ReportQueries.NotApplicable(r).ToList();
        if (na.Count > 0)
        {
            b.Append("<h3>Rules not applicable (").Append(na.Count).Append(")</h3><table><tr><th>Rule</th><th>Title</th><th>Reason</th></tr>");
            foreach (var e in na) b.Append("<tr><td>").Append(E(e.Rule.RuleId)).Append("</td><td>").Append(E(e.Rule.Title)).Append("</td><td>").Append(E(e.Reason ?? "")).Append("</td></tr>");
            b.Append("</table>");
        }
        b.Append("</section>");
    }

    private static void SeveritySection(StringBuilder b, AssessmentResult r, string id, string heading, Severity severity)
    {
        var list = ReportQueries.OrderedFindings(r).Where(f => f.Severity == severity).ToList();
        b.Append("<section id=\"").Append(id).Append("\"><h2>").Append(heading).Append(" (").Append(list.Count).Append(")</h2>");
        if (list.Count == 0) b.Append("<p class=\"muted\">No ").Append(severity).Append(" findings were raised by the rules that could be evaluated.</p>");
        else
        {
            b.Append("<table><tr><th>Rule</th><th>Finding</th><th>Category</th><th class=\"num\">Objects</th></tr>");
            foreach (var f in list)
                b.Append("<tr><td><a href=\"#f-").Append(E(f.RuleId)).Append("\">").Append(E(f.RuleId)).Append("</a></td><td>").Append(E(f.Title)).Append("</td><td>").Append(E(f.Category))
                 .Append("</td><td class=\"num\">").Append(f.AffectedObjects.Count).Append("</td></tr>");
            b.Append("</table>");
        }
        b.Append("</section>");
    }

    private static void ByCategory(StringBuilder b, AssessmentResult r)
    {
        b.Append("<section id=\"by-category\"><h2>Findings by Category</h2>");
        foreach (var group in ReportQueries.OrderedFindings(r).GroupBy(f => f.Category).OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
        {
            b.Append("<h3>").Append(E(group.Key)).Append(" (").Append(group.Count()).Append(")</h3><table><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Module</th><th class=\"num\">Objects</th></tr>");
            foreach (var f in group.OrderByDescending(f => f.Severity).ThenBy(f => f.RuleId))
                b.Append("<tr><td>").Append(Sev(f.Severity)).Append("</td><td><a href=\"#f-").Append(E(f.RuleId)).Append("\">").Append(E(f.RuleId)).Append("</a></td><td>").Append(E(f.Title))
                 .Append("</td><td>").Append(E(f.Module)).Append("</td><td class=\"num\">").Append(f.AffectedObjects.Count).Append("</td></tr>");
            b.Append("</table>");
        }
        if (r.Findings.Count == 0) b.Append("<p class=\"muted\">No findings.</p>");
        b.Append("</section>");
    }

    private static void TechnicalFindings(StringBuilder b, AssessmentResult r)
    {
        b.Append("<section id=\"technical\"><h2>Technical Findings</h2>");
        foreach (var f in ReportQueries.OrderedFindings(r))
        {
            b.Append("<div class=\"finding\" id=\"f-").Append(E(f.RuleId)).Append("\"><h4>").Append(Sev(f.Severity)).Append(' ').Append(E(f.RuleId)).Append(" — ").Append(E(f.Title)).Append("</h4>");
            b.Append("<div class=\"meta\">").Append(E(f.Category)).Append(" · ").Append(E(f.Module)).Append(" · ").Append(f.AffectedObjects.Count).Append(" affected object(s)</div>");
            b.Append("<p>").Append(E(f.Description)).Append("</p>");
            b.Append("<p><strong>Condition:</strong> ").Append(E(f.Condition)).Append("</p>");
            b.Append("<p><strong>Risk:</strong> ").Append(E(f.Risk)).Append("</p>");
            if (!string.IsNullOrWhiteSpace(f.Notes)) b.Append("<p class=\"muted\">").Append(E(f.Notes!)).Append("</p>");
            b.Append("<h3>Affected objects</h3><table><tr><th>Object</th><th>Type</th><th>Domain</th><th>Distinguished name</th></tr>");
            foreach (var a in f.AffectedObjects.Take(MaxRowsPerTable))
                b.Append("<tr><td>").Append(E(a.Name)).Append("</td><td>").Append(a.Kind).Append("</td><td>").Append(E(a.Domain ?? "")).Append("</td><td class=\"mono\">").Append(E(a.DistinguishedName ?? "")).Append("</td></tr>");
            b.Append("</table>");
            More(b, f.AffectedObjects.Count);
            b.Append("</div>");
        }
        if (r.Findings.Count == 0) b.Append("<p class=\"muted\">No findings.</p>");
        b.Append("</section>");
    }

    private static void EvidenceSection(StringBuilder b, AssessmentResult r)
    {
        b.Append("<section id=\"evidence\"><h2>Evidence</h2><p>Every finding is backed by technical evidence collected from the directory. ")
         .Append("Values are shown exactly as collected; the expected value (when defined) is the condition that was not met.</p>");
        foreach (var f in ReportQueries.OrderedFindings(r))
        {
            b.Append("<details><summary>").Append(E(f.RuleId)).Append(" — ").Append(E(f.Title)).Append(" (").Append(f.Evidence.Count).Append(" evidence item(s))</summary>");
            b.Append("<table><tr><th>Object</th><th>Property</th><th>Collected value</th><th>Expected</th><th>Source</th><th>Collected at</th></tr>");
            foreach (var e in f.Evidence.Take(MaxRowsPerTable))
                b.Append("<tr><td>").Append(E(e.ObjectName)).Append("</td><td>").Append(E(e.Property)).Append("</td><td class=\"mono\">").Append(E(e.Value ?? "(not set)")).Append("</td><td>")
                 .Append(E(e.Expected ?? "")).Append("</td><td>").Append(E(e.Source)).Append("</td><td>").Append(Dt(e.CollectedAt)).Append("</td></tr>");
            b.Append("</table>");
            More(b, f.Evidence.Count);
            b.Append("</details>");
        }
        if (r.Findings.Count == 0) b.Append("<p class=\"muted\">No findings, therefore no evidence of problems to list.</p>");
        b.Append("</section>");
    }

    private static void Recommendations(StringBuilder b, AssessmentResult r)
    {
        b.Append("<section id=\"recommendations\"><h2>Recommendations</h2>")
         .Append("<p>Recommendations are guidance only. This tool never applies remediation or changes Active Directory, Group Policy, accounts or domain controllers. Test changes in a non-production environment first.</p><ol>");
        foreach (var f in ReportQueries.OrderedFindings(r))
            b.Append("<li>").Append(Sev(f.Severity)).Append(" <strong>").Append(E(f.RuleId)).Append("</strong> — ").Append(E(f.Title)).Append("<br>").Append(E(f.Recommendation)).Append("</li>");
        b.Append("</ol>");
        if (r.Findings.Count == 0) b.Append("<p class=\"muted\">No recommendations: no findings were raised.</p>");
        b.Append("</section>");
    }

    private static void References(StringBuilder b, AssessmentResult r)
    {
        var refs = r.Findings.SelectMany(f => f.References.Select(x => (Ref: x, f.RuleId)))
            .GroupBy(x => x.Ref.Url, StringComparer.OrdinalIgnoreCase)
            .OrderBy(g => g.First().Ref.Title, StringComparer.OrdinalIgnoreCase).ToList();
        b.Append("<section id=\"references\"><h2>References</h2><p>Official Microsoft documentation. The links are plain hyperlinks; nothing is requested from the Internet unless you click one.</p><ul>");
        foreach (var g in refs)
        {
            var url = g.Key;
            var safe = url.StartsWith("https://learn.microsoft.com/", StringComparison.OrdinalIgnoreCase);
            b.Append("<li>");
            if (safe) b.Append("<a href=\"").Append(E(url)).Append("\" rel=\"noopener noreferrer\">").Append(E(g.First().Ref.Title)).Append("</a>");
            else b.Append(E(g.First().Ref.Title)).Append(" — ").Append(E(url));
            b.Append(" <span class=\"muted\">(").Append(E(string.Join(", ", g.Select(x => x.RuleId).Distinct().OrderBy(x => x)))).Append(")</span></li>");
        }
        b.Append("</ul>");
        if (refs.Count == 0) b.Append("<p class=\"muted\">No references: no findings were raised.</p>");
        b.Append("</section>");
    }

    // ------------------------------------------------------------------ helpers
    private static void Card(StringBuilder b, string value, string label, bool raw = false) =>
        b.Append("<div class=\"card\"><div class=\"v\">").Append(raw ? value : E(value)).Append("</div><div class=\"l\">").Append(E(label)).Append("</div></div>");

    private static void More(StringBuilder b, int total)
    {
        if (total > MaxRowsPerTable)
            b.Append("<p class=\"muted\">Showing ").Append(MaxRowsPerTable).Append(" of ").Append(total.ToString("N0", CultureInfo.InvariantCulture)).Append(" — the complete list is in the JSON and CSV exports.</p>");
    }

    private static string Sev(Severity s) => $"<span class=\"sev {s}\">{s}</span>";
    private static string Dt(DateTimeOffset d) => E(d.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture));
    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
}
