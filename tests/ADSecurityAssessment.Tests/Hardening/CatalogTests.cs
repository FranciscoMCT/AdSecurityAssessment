using ADSecurityAssessment.Hardening.Catalog;
using ADSecurityAssessment.Hardening.Gpo;

namespace ADSecurityAssessment.Tests.Hardening;

public class CatalogTests
{
    [Fact]
    public void EmbeddedCatalog_LoadsAndIsConsistent()
    {
        var c = HCat.Embedded();
        Assert.True(c.Settings.Count >= 60);
        Assert.Equal(3, c.GpoProfiles.Count);
        Assert.NotEmpty(c.AccountPolicy);
        Assert.True(c.Profiles.Any(p => p.Kind == "advice"));
        foreach (var p in c.GpoProfiles) Assert.NotEmpty(c.ForProfile(p.Id));
    }

    [Fact]
    public void HighRiskSettings_AreNeverDefaultOn_AndAlwaysHavePrerequisites()
    {
        var c = HCat.Embedded();
        var high = c.Settings.Where(s => s.Risk == "high").ToList();
        Assert.NotEmpty(high);
        Assert.All(high, s => Assert.False(s.DefaultOn));
        Assert.All(high, s => Assert.False(string.IsNullOrWhiteSpace(s.Prerequisite)));
    }

    [Fact]
    public void EveryReference_IsMicrosoftLearn()
    {
        var c = HCat.Embedded();
        Assert.All(c.Settings.SelectMany(s => s.References), r => Assert.StartsWith("https://learn.microsoft.com/", r));
        Assert.All(c.AccountPolicy, a => Assert.StartsWith("https://learn.microsoft.com/", a.Reference));
    }

    [Fact]
    public void AuditSettings_RequireForceSubcategory_AndUseKnownSubcategories()
    {
        var c = HCat.Embedded();
        foreach (var s in c.Settings.Where(s => s.Entries.Any(e => e.Via == "audit")))
        {
            Assert.Contains("audit.force-subcategory", s.Requires!);
            Assert.All(s.Entries, e => Assert.True(AuditPolicy.All.ContainsKey(e.Subcategory!)));
        }
    }

    [Fact]
    public void AuditSubcategoryTable_HasUniqueKeysAndGuids_InTheMicrosoftPattern()
    {
        var all = AuditPolicy.All.Values.ToList();
        Assert.Equal(all.Count, all.Select(a => a.Id).Distinct().Count());
        Assert.All(all, a => Assert.EndsWith("-69AE-11D9-BED3-505054503030", a.Id.ToString().ToUpperInvariant()));
        Assert.All(all, a => Assert.StartsWith("0CCE", a.Id.ToString().ToUpperInvariant()));
    }

    [Fact]
    public void Minimal_Parses() => Assert.Equal("t", HardeningCatalog.Parse(HCat.Minimal, "t").Version);

    [Fact]
    public void Rejects_UnknownField() =>
        Assert.Throws<CatalogException>(() => HardeningCatalog.Parse(HCat.Minimal.Replace("\"rationale\": \"r\"", "\"rationale\": \"r\", \"script\": \"calc\""), "t"));

    [Fact]
    public void Rejects_ReferenceOutsideLearn() =>
        Assert.Throws<CatalogException>(() => HardeningCatalog.Parse(HCat.Minimal.Replace("https://learn.microsoft.com/x", "https://example.com/x"), "t"));

    [Fact]
    public void Rejects_HighRiskDefaultOn() =>
        Assert.Throws<CatalogException>(() => HardeningCatalog.Parse(HCat.Minimal.Replace("\"risk\": \"low\"", "\"risk\": \"high\""), "t"));

    [Fact]
    public void Rejects_UnknownScope() =>
        Assert.Throws<CatalogException>(() => HardeningCatalog.Parse(HCat.Minimal.Replace("\"scopes\": [\"dc\"]", "\"scopes\": [\"nope\"]"), "t"));

    [Fact]
    public void Rejects_HiveInPolKey() =>
        Assert.Throws<CatalogException>(() => HardeningCatalog.Parse(HCat.Minimal.Replace("SOFTWARE\\\\Policies\\\\X", "HKLM\\\\SOFTWARE\\\\X"), "t"));

    [Fact]
    public void Rejects_WrongValueKind() =>
        Assert.Throws<CatalogException>(() => HardeningCatalog.Parse(HCat.Minimal.Replace("\"value\": 1", "\"value\": \"um\""), "t"));

    [Fact]
    public void Rejects_UnknownVia() =>
        Assert.Throws<CatalogException>(() => HardeningCatalog.Parse(HCat.Minimal.Replace("\"via\": \"pol\"", "\"via\": \"powershell\""), "t"));

    [Fact]
    public void Rejects_DuplicateTargetInSameProfile()
    {
        const string two = """
        {
          "catalogVersion": "t",
          "profiles": [ { "id": "dc", "kind": "gpo", "title": "DC", "gpoName": "G", "linkTarget": "x", "description": "d" } ],
          "settings": [
            { "id": "a.one", "category": "c", "title": "t", "scopes": ["dc"], "risk": "low", "defaultOn": true, "rationale": "r", "impact": "i",
              "references": ["https://learn.microsoft.com/x"],
              "entries": [ { "via": "pol", "key": "SOFTWARE\\Policies\\X", "name": "V", "type": "dword", "value": 1, "revertDelete": true } ] },
            { "id": "a.two", "category": "c", "title": "t", "scopes": ["dc"], "risk": "low", "defaultOn": true, "rationale": "r", "impact": "i",
              "references": ["https://learn.microsoft.com/x"],
              "entries": [ { "via": "pol", "key": "software\\policies\\x", "name": "v", "type": "dword", "value": 2, "revertDelete": true } ] }
          ],
          "accountPolicy": []
        }
        """;
        var ex = Assert.Throws<CatalogException>(() => HardeningCatalog.Parse(two, "t"));
        Assert.Contains("mesmo destino", ex.Message);
        Assert.Equal("t", HardeningCatalog.Parse(two.Replace("software\\\\policies\\\\x", "software\\\\policies\\\\y"), "t").Version);
    }

    [Fact]
    public void Rejects_AuditWithoutRequires() =>
        Assert.Throws<CatalogException>(() => HardeningCatalog.Parse(HCat.Minimal.Replace(
            "{ \"via\": \"pol\", \"key\": \"SOFTWARE\\\\Policies\\\\X\", \"name\": \"V\", \"type\": \"dword\", \"value\": 1, \"revertDelete\": true }",
            "{ \"via\": \"audit\", \"subcategory\": \"Logon\", \"success\": true, \"failure\": true }"), "t"));

    [Fact]
    public void ExternalOverride_IsUsedWhenPresent_AndInvalidOneIsRefused()
    {
        var dir = Path.Combine(Path.GetTempPath(), "hc-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "catalog.json"), HCat.Minimal);
            Assert.Equal("t", HardeningCatalog.Load(dir).Version);
            File.WriteAllText(Path.Combine(dir, "catalog.json"), "{ nao e json");
            Assert.Throws<CatalogException>(() => HardeningCatalog.Load(dir));
        }
        finally { Directory.Delete(dir, true); }
        Assert.NotEqual("t", HardeningCatalog.Load(null).Version);
    }
}
