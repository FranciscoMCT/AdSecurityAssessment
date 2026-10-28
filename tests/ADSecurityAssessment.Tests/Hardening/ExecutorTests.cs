using ADSecurityAssessment.Hardening.Execution;
using ADSecurityAssessment.Hardening.Planning;
using ADSecurityAssessment.Hardening.Policy;
using ADSecurityAssessment.Hardening.Reporting;

namespace ADSecurityAssessment.Tests.Hardening;

public class ExecutorTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "hx-" + Guid.NewGuid().ToString("N"));
    public ExecutorTests() { Directory.CreateDirectory(_dir); }
    public void Dispose() { try { Directory.Delete(_dir, true); } catch (IOException) { } }

    private GpoLedger Ledger() => new(Path.Combine(_dir, "ledger.json"));

    private static HardeningPlan Plan(IEnumerable<string>? existing = null) =>
        HardeningPlanner.Plan(HCat.Embedded(), new PlanOptions { Selection = HardeningSelection.Default(HCat.Embedded()) }, "corp.test", existing ?? Array.Empty<string>(), null);

    [Fact]
    public void Apply_CreatesEveryGpo_RecordsThem_AndNeverLinks()
    {
        var store = new FakeGpoStore();
        var ledger = Ledger();
        var result = new HardeningExecutor(store, ledger, NullHardeningLog.Instance, "t").Apply(Plan());
        Assert.Equal(6, result.CreatedCount);
        Assert.False(result.AnyFailed);
        Assert.Equal(6, ledger.Entries.Count);
        Assert.Equal(6, store.Gpos.Count);
        Assert.Empty(store.Links);
    }

    [Fact]
    public void Apply_SkipsPlannedSkips_AndNamesThatAppearedMeanwhile()
    {
        var store = new FakeGpoStore();
        var name = HCat.Embedded().Profile("dc").GpoName;
        store.Preexisting.Add(new GpoInfo(Guid.NewGuid(), name, "CN=x"));
        var result = new HardeningExecutor(store, Ledger(), NullHardeningLog.Instance, "t").Apply(Plan());   // plano feito SEM saber da existente
        Assert.Equal(1, result.Results.Count(r => r.Outcome == GpoOutcome.Skipped));
        Assert.False(store.Gpos.Values.Any(v => v.Gpo.DisplayName == name));
    }

    [Fact]
    public void Apply_VerificationFailure_RollsBackThatGpo_AndIsNotRecorded()
    {
        var store = new FakeGpoStore { FailVerify = true };
        var ledger = Ledger();
        var result = new HardeningExecutor(store, ledger, NullHardeningLog.Instance, "t").Apply(Plan());
        Assert.True(result.AnyFailed);
        Assert.Empty(store.Gpos);
        Assert.Empty(ledger.Entries);
    }

    [Fact]
    public void Apply_CreateFailure_IsReportedPerGpo_NotThrown()
    {
        var store = new FakeGpoStore { FailCreate = true };
        var result = new HardeningExecutor(store, Ledger(), NullHardeningLog.Instance, "t").Apply(Plan());
        Assert.Equal(6, result.Results.Count(r => r.Outcome == GpoOutcome.Failed));
    }

    [Fact]
    public void Remove_OnlyWorksForGposInTheLedger_AndRefusesLinkedOnes()
    {
        var store = new FakeGpoStore();
        var ledger = Ledger();
        var exec = new HardeningExecutor(store, ledger, NullHardeningLog.Instance, "t");
        exec.Apply(Plan());

        var foreign = Guid.NewGuid();
        store.Preexisting.Add(new GpoInfo(foreign, "Default Domain Policy", "CN=x"));
        Assert.False(exec.Remove(foreign).Removed);
        Assert.True(store.ListGpos().Any(g => g.Id == foreign));

        var mine = ledger.Entries.First();
        store.Links[mine.Id] = new List<GpoLink> { new("OU=Piloto,DC=corp,DC=test", true, false) };
        var refused = exec.Remove(mine.Id);
        Assert.False(refused.Removed);
        Assert.Contains("OU=Piloto", refused.Message);
        Assert.NotNull(ledger.Find(mine.Id));

        store.Links.Clear();
        Assert.True(exec.Remove(mine.Id).Removed);
        Assert.Null(ledger.Find(mine.Id));
        Assert.Equal(1, store.Deleted.Count);
    }

    [Fact]
    public void Remove_RefusesWhenTheGpoWasRenamedByAnAdmin()
    {
        var store = new FakeGpoStore();
        var ledger = Ledger();
        var exec = new HardeningExecutor(store, ledger, NullHardeningLog.Instance, "t");
        exec.Apply(Plan());
        var mine = ledger.Entries.First();
        var (gpo, bundle) = store.Gpos[mine.Id];
        store.Gpos[mine.Id] = (gpo with { DisplayName = "Renomeada" }, bundle);
        Assert.False(exec.Remove(mine.Id).Removed);
    }

    [Fact]
    public void Ledger_PersistsAndRefusesToOverwriteACorruptFile()
    {
        var store = new FakeGpoStore();
        new HardeningExecutor(store, Ledger(), NullHardeningLog.Instance, "t").Apply(Plan());
        Assert.Equal(6, Ledger().Entries.Count);
        File.WriteAllText(Path.Combine(_dir, "ledger.json"), "{ corrompido");
        Assert.Throws<InvalidDataException>(() => Ledger());
    }

    [Fact]
    public void Store_Interface_HasNoLinkOrEditOperation()
    {
        var names = typeof(IGpoStore).GetMethods().Select(m => m.Name).ToList();
        Assert.False(names.Any(n => n.Contains("Link", StringComparison.OrdinalIgnoreCase) && n != "FindLinks"));
        Assert.False(names.Any(n => n.StartsWith("Set", StringComparison.Ordinal) || n.StartsWith("Update", StringComparison.Ordinal) || n.StartsWith("Modify", StringComparison.Ordinal)));
        Assert.Equal(new[] { "Create", "Delete", "FindLinks", "ListGpos", "ListPsos", "ReadPasswordPolicy", "Verify" },
            names.Where(n => !n.StartsWith("get_", StringComparison.Ordinal)).OrderBy(n => n, StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public void Report_EncodesEverythingAndHasNoExternalResources()
    {
        var plan = Plan();
        var html = PlanReportWriter.ToHtml(plan, new ApplyResult { Results = { new GpoResult("<script>alert(1)</script>", GpoKind.Main, GpoOutcome.Created, "ok", Guid.NewGuid(), new[] { "<b>nota</b>" }) } });
        Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;", html);
        var external = System.Text.RegularExpressions.Regex.Matches(html, @"(?:src|href)=""https?://(?!learn\.microsoft\.com/)[^""]+""");
        Assert.Equal(0, external.Count);
        Assert.StartsWith("{", PlanReportWriter.ToJson(plan).TrimStart());
    }
}
