using System.Text.Json;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;
using ADSecurityAssessment.Core.Pipeline;
using ADSecurityAssessment.Reporting;

namespace ADSecurityAssessment.Tests;

public class CsvExportTests
{
    [Theory]
    [InlineData("=HYPERLINK(\"http://evil\")", "'=HYPERLINK")]
    [InlineData("+1+1", "'+1+1")]
    [InlineData("-2+3", "'-2+3")]
    [InlineData("@SUM(A1)", "'@SUM(A1)")]
    [InlineData("\tcmd", "'\tcmd")]
    public void FormulaInjection_IsNeutralised(string input, string expectedStart)
    {
        Assert.StartsWith(expectedStart, CsvReportExporter.Escape(input).TrimStart('"'));
    }

    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("a,b", "\"a,b\"")]
    [InlineData("say \"hi\"", "\"say \"\"hi\"\"\"")]
    [InlineData("line1\nline2", "\"line1\nline2\"")]
    [InlineData("", "")]
    public void Escape_FollowsRfc4180(string input, string expected)
    {
        Assert.Equal(expected, CsvReportExporter.Escape(input));
    }

    [Fact]
    public void DemoCsv_HasHeader_AndOneRowPerEvidence_AndIsFlaggedDemo()
    {
        var csv = CsvReportExporter.Build(Fixture.Demo());

        var lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        Assert.True(lines.Length > 1);
        Assert.Contains("RuleId", lines[0]);
        Assert.Contains("DEMO", csv, StringComparison.OrdinalIgnoreCase);
    }
}

public class JsonExportTests
{
    [Fact]
    public void DemoJson_IsValid_Versioned_AndFlaggedDemo()
    {
        var json = JsonReportExporter.Serialize(Fixture.Demo());

        using var doc = JsonDocument.Parse(json);
        Assert.Equal(JsonReportExporter.SchemaVersion, doc.RootElement.GetProperty("schemaVersion").GetInt32());
        Assert.True(doc.RootElement.GetProperty("isDemo").GetBoolean());
        Assert.True(doc.RootElement.GetProperty("findings").GetArrayLength() > 0);
    }

    [Fact]
    public void Json_NeverContainsSecretFieldNames()
    {
        var json = JsonReportExporter.Serialize(Fixture.Demo());

        foreach (var forbidden in new[] { "unicodePwd", "ntPwdHistory", "supplementalCredentials", "msDS-ManagedPassword", "trustAuthIncoming" })
            Assert.DoesNotContain(forbidden, json, StringComparison.OrdinalIgnoreCase);
    }
}

public class HtmlExportTests
{
    private static readonly string[] RequiredSections =
    {
        "Executive Summary", "Environment Summary", "Overall Risk", "Assessment Coverage", "Critical Findings", "High Findings",
        "Findings by Category", "Technical Findings", "Evidence", "Recommendations", "References"
    };

    private static string Html(AssessmentResult r) => new HtmlReportExporter().Render(r);

    [Fact]
    public void Html_ContainsEveryRequiredSection()
    {
        var html = Html(Fixture.Demo());

        foreach (var section in RequiredSections)
            Assert.Contains(section, html);
    }

    [Fact]
    public void Html_IsSelfContained_NoScripts_NoExternalLoads_AndStrictCsp()
    {
        var html = Html(Fixture.Demo());

        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Content-Security-Policy", html);
        Assert.Contains("default-src 'none'", html);
        Assert.DoesNotContain("src=\"http", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<link ", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("@import", html, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Html_ShowsSensitiveDataNotice_AndDemoMarking()
    {
        var html = Html(Fixture.Demo());

        Assert.Contains("DEMO DATA", html);
        Assert.Contains("sensitive", html, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Html_EncodesHostileDataFromTheDirectory()
    {
        // Um objeto do AD com nome malicioso não pode virar HTML/JS no relatório.
        const string hostile = "<img src=x onerror=alert(1)>\"&'";
        var rule = new FakeRule("AD-TST-950", Severity.High, new[] { "users" }, (m, _) =>
            RuleEvaluation.Failed(m, new[] { T.Affected(hostile) }, new[] { T.Evidence(hostile) }, 1));
        var snapshot = new SnapshotBuilder { IsDemo = true };
        snapshot.SetState(DatasetState.Complete("users", "UserCollector"));
        var result = new AssessmentOrchestrator(Array.Empty<ICollector>(), new IAssessmentRule[] { rule }).RunDemo(snapshot.Build(T.Now), new AssessmentSettings());

        var html = Html(result);

        Assert.DoesNotContain("<img src=x", html);
        Assert.Contains("&lt;img src=x", html);
    }

    [Fact]
    public void Html_OnlyLinksToMicrosoftLearn()
    {
        var html = Html(Fixture.Demo());

        var hrefs = System.Text.RegularExpressions.Regex.Matches(html, "href=\"([^\"]+)\"").Select(m => m.Groups[1].Value).Where(h => h.StartsWith("http")).ToList();
        Assert.NotEmpty(hrefs);
        Assert.All(hrefs, h => Assert.True(ReferenceCatalog.IsOfficialUrl(System.Net.WebUtility.HtmlDecode(h)), h));
    }

    [Fact]
    public async Task ExportService_WritesAllFormats_Locally_AndAtomically()
    {
        var folder = Path.Combine(Path.GetTempPath(), "ads-tests-" + Guid.NewGuid().ToString("N"));
        try
        {
            var files = await new ReportExportService().ExportAsync(Fixture.Demo(), folder, new[] { "HTML", "JSON", "CSV" }, CancellationToken.None);

            Assert.Equal(3, files.Count);
            Assert.All(files, f => { Assert.StartsWith(folder, f); Assert.True(new FileInfo(f).Length > 0); });
            Assert.Empty(Directory.GetFiles(folder, "*.tmp"));
            Assert.Contains(files, f => f.EndsWith(".html")); Assert.Contains(files, f => f.EndsWith(".json")); Assert.Contains(files, f => f.EndsWith(".csv"));
        }
        finally
        {
            if (Directory.Exists(folder)) Directory.Delete(folder, true);
        }
    }

    [Fact]
    public void FutureFormats_CanBePlugged_WithoutChangingTheService()
    {
        var service = new ReportExportService(extraExporters: new IReportExporter[] { new FakePdfExporter() });

        Assert.Contains(service.Exporters, e => e.Format == "PDF");
        Assert.Contains(service.Exporters, e => e.Format == "HTML");
    }

    private sealed class FakePdfExporter : IReportExporter
    {
        public string Format => "PDF";
        public string FileExtension => ".pdf";
        public Task ExportAsync(AssessmentResult result, string path, CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
