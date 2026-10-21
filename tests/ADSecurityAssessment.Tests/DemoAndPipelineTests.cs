using ADSecurityAssessment.Collectors;
using ADSecurityAssessment.Collectors.Demo;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;
using ADSecurityAssessment.Core.Pipeline;
using ADSecurityAssessment.Rules;

namespace ADSecurityAssessment.Tests;

internal static class Fixture
{
    public static readonly IReadOnlyList<IAssessmentRule> Rules = RuleCatalog.Load(null, ReferenceCatalog.LoadEmbedded()).Rules;

    private static AssessmentResult? _demo;
    public static AssessmentResult Demo() => _demo ??=
        new AssessmentOrchestrator(Array.Empty<ICollector>(), Rules).RunDemo(DemoSnapshotFactory.Create(), new AssessmentSettings());
}

/// <summary>Demo Mode: dados fictícios identificados e nunca misturados com resultados reais.</summary>
public class DemoModeTests
{
    [Fact]
    public void DemoSnapshot_IsMarkedDemo_AndUsesReservedInvalidDomains()
    {
        var s = DemoSnapshotFactory.Create();

        Assert.True(s.IsDemo);
        Assert.All(s.Domains, d => Assert.EndsWith(".invalid", d.Name));
        Assert.All(s.Users, u => Assert.EndsWith(".invalid", u.Domain));
        Assert.Contains("DEMO DATA", DemoSnapshotFactory.Banner);
    }

    [Fact]
    public void RunDemo_RejectsASnapshotThatIsNotDemo()
    {
        var orchestrator = new AssessmentOrchestrator(Array.Empty<ICollector>(), Fixture.Rules);
        var live = new SnapshotBuilder { IsDemo = false }.Build(T.Now);

        Assert.Throws<ArgumentException>(() => orchestrator.RunDemo(live, new AssessmentSettings()));
    }

    [Fact]
    public void DemoResult_IsFlaggedEverywhere()
    {
        var r = Fixture.Demo();

        Assert.True(r.IsDemo);
        Assert.Equal(AssessmentMode.Demo, r.Metadata.Mode);
        Assert.NotEmpty(r.Findings);
        Assert.All(r.Findings, f => Assert.True(f.IsDemo));
    }

    [Fact]
    public void DemoRun_NeverExecutesCollectors()
    {
        var executed = false;
        var collector = new StubCollector("spy", new[] { "users" }, () => { executed = true; return CollectorResult.Ok(0); });
        var orchestrator = new AssessmentOrchestrator(new ICollector[] { collector }, Fixture.Rules);

        var r = orchestrator.RunDemo(DemoSnapshotFactory.Create(), new AssessmentSettings());

        Assert.True(r.IsDemo);
        Assert.False(executed);
        Assert.DoesNotContain(r.CollectorRuns, c => c.CollectorId == "spy");
    }

    [Fact]
    public void DemoResult_EveryFinding_HasTechnicalEvidenceForEveryAffectedObject()
    {
        foreach (var f in Fixture.Demo().Findings)
        {
            Assert.NotEmpty(f.Evidence);
            var evidenced = new HashSet<string>(f.Evidence.Select(e => e.ObjectName), StringComparer.OrdinalIgnoreCase);
            Assert.All(f.AffectedObjects, a => Assert.Contains(a.Name, evidenced));
            Assert.NotEmpty(f.References);
        }
    }
}

internal sealed class ThrowingGatewayFactory : IDirectoryGatewayFactory
{
    public int OpenCalls { get; private set; }

    public IDirectoryGateway Open(GatewayTarget target)
    {
        OpenCalls++;
        throw new DirectoryQueryException("Simulated: domain controller unreachable.");
    }
}

/// <summary>Falhas parciais não cancelam o assessment e a ausência de dados nunca vira "conforme".</summary>
public class LivePipelineTests
{
    [Fact]
    public async Task WhenDirectoryIsUnreachable_EverythingIsNotEvaluated_NothingIsAssumedCompliant()
    {
        var factory = new ThrowingGatewayFactory();
        var orchestrator = new AssessmentOrchestrator(CollectorCatalog.CreateAll(), Fixture.Rules);

        var r = await orchestrator.RunLiveAsync(new ConnectionInfo(), factory, new AssessmentSettings(), null, CancellationToken.None);

        Assert.False(r.IsDemo);
        Assert.Equal(AssessmentMode.Live, r.Metadata.Mode);
        Assert.Empty(r.Findings);
        Assert.DoesNotContain(r.Evaluations, e => e.Outcome is RuleOutcome.Passed or RuleOutcome.Failed);
        Assert.Equal(CategoryStatus.NotEvaluated, r.Score.Overall.Status);
        Assert.Null(r.Score.Overall.SecurityScore);
        Assert.Equal(0.0, r.Score.Overall.CoveragePercent);
        // Placeholders (NTLM/LDAP/SMB) são "Skipped"; os demais falham porque o diretório está inacessível. Nenhum "Succeeded" com 0 objetos reais.
        Assert.DoesNotContain(r.CollectorRuns, c => c.Status == CollectorStatus.Succeeded && c.ObjectCount > 0);
    }

    [Fact]
    public async Task OneFailingCollector_DoesNotStopTheOthers()
    {
        var failing = new StubCollector("boom", new[] { "users" }, () => throw new InvalidOperationException("collector exploded"));
        var healthy = new StubCollector("ok", new[] { "domains" }, () => CollectorResult.Ok(0));
        var orchestrator = new AssessmentOrchestrator(new ICollector[] { failing, healthy }, Array.Empty<IAssessmentRule>());

        var r = await orchestrator.RunLiveAsync(new ConnectionInfo(), new ThrowingGatewayFactory(), new AssessmentSettings(), null, CancellationToken.None);

        Assert.Equal(CollectorStatus.Failed, r.CollectorRuns.Single(c => c.CollectorId == "boom").Status);
        Assert.Equal(CollectorStatus.Succeeded, r.CollectorRuns.Single(c => c.CollectorId == "ok").Status);
        Assert.Equal(DatasetCoverage.None, r.Datasets.Single(d => d.Name == "users").Coverage);
        Assert.Equal(DatasetCoverage.Complete, r.Datasets.Single(d => d.Name == "domains").Coverage);
    }

    [Fact]
    public async Task CollectorThatDependsOnAFailedOne_IsSkipped()
    {
        var failing = new StubCollector("first", new[] { "forest" }, () => CollectorResult.Failed("no access"));
        var dependent = new StubCollector("second", new[] { "domains" }, () => CollectorResult.Ok(1), dependsOn: new[] { "first" });
        var orchestrator = new AssessmentOrchestrator(new ICollector[] { dependent, failing }, Array.Empty<IAssessmentRule>());

        var r = await orchestrator.RunLiveAsync(new ConnectionInfo(), new ThrowingGatewayFactory(), new AssessmentSettings(), null, CancellationToken.None);

        Assert.Equal(CollectorStatus.Skipped, r.CollectorRuns.Single(c => c.CollectorId == "second").Status);
        Assert.Equal(DatasetCoverage.None, r.Datasets.Single(d => d.Name == "domains").Coverage);
    }

    [Fact]
    public async Task Cancellation_IsPropagated()
    {
        var orchestrator = new AssessmentOrchestrator(CollectorCatalog.CreateAll(), Fixture.Rules);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            orchestrator.RunLiveAsync(new ConnectionInfo(), new ThrowingGatewayFactory(), new AssessmentSettings(), null, cts.Token));
    }

    [Fact]
    public void ConnectionInfo_NeverExposesThePassword()
    {
        using var secret = new System.Security.SecureString();
        foreach (var ch in "Sup3r-Secret!") secret.AppendChar(ch);
        var info = new ConnectionInfo { UseCurrentCredentials = false, Domain = "corp.test", Username = @"CORP\alice", Password = secret };

        Assert.DoesNotContain("Sup3r-Secret", info.ToString());
        Assert.DoesNotContain("Sup3r-Secret", info.TargetDescription);
        Assert.DoesNotContain("Sup3r-Secret", System.Text.Json.JsonSerializer.Serialize(info));
    }
}

internal sealed class StubCollector : ICollector
{
    private readonly Func<CollectorResult> _run;

    public StubCollector(string id, string[] datasets, Func<CollectorResult> run, string[]? dependsOn = null)
    {
        Id = id; DisplayName = id; Datasets = datasets; DependsOn = dependsOn ?? Array.Empty<string>(); _run = run;
    }

    public string Id { get; }
    public string DisplayName { get; }
    public IReadOnlyList<string> Datasets { get; }
    public IReadOnlyList<string> DependsOn { get; }
    public Task<CollectorResult> CollectAsync(CollectionContext context, CancellationToken cancellationToken) => Task.FromResult(_run());
}
