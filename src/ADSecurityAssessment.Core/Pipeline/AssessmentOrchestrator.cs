using System.Diagnostics;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Core.Pipeline;

public sealed record AssessmentProgress(string Phase, string Message, int Percent);

/// <summary>
/// AD → Collection → Normalization → Rule Engine → Findings → Risk Scoring → AssessmentResult.
/// Dois pontos de entrada SEPARADOS: <see cref="RunLiveAsync"/> (coleta real) e <see cref="RunDemo"/> (dados fictícios).
/// Nunca há mistura entre os dois.
/// </summary>
public sealed class AssessmentOrchestrator
{
    public const string ToolName = "AD Security Assessment";

    private readonly IReadOnlyList<ICollector> _collectors;
    private readonly IReadOnlyList<IAssessmentRule> _rules;
    private readonly IAssessmentLog _log;
    private readonly Func<DateTimeOffset> _clock;
    private readonly string _toolVersion;

    public AssessmentOrchestrator(IEnumerable<ICollector> collectors, IEnumerable<IAssessmentRule> rules,
        IAssessmentLog? log = null, Func<DateTimeOffset>? clock = null, string toolVersion = "1.0.0")
    {
        _collectors = collectors.ToArray();
        _rules = rules.ToArray();
        _log = log ?? NullAssessmentLog.Instance;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _toolVersion = toolVersion;
    }

    public IReadOnlyList<IAssessmentRule> Rules => _rules;
    public IReadOnlyList<ICollector> Collectors => _collectors;

    // ------------------------------------------------------------------ LIVE
    public async Task<AssessmentResult> RunLiveAsync(ConnectionInfo connection, IDirectoryGatewayFactory gateways,
        AssessmentSettings settings, IProgress<AssessmentProgress>? progress, CancellationToken ct)
    {
        var started = _clock();
        _log.Info($"Assessment iniciado. Alvo: {connection.TargetDescription}. Modo: READ-ONLY.");
        var builder = new SnapshotBuilder { IsDemo = false };
        var runs = new List<CollectorRun>();
        var ordered = Order(_collectors);

        var ctx = new CollectionContext
        {
            Connection = connection, Gateways = gateways, Builder = builder, Settings = settings, Log = _log, Clock = _clock,
            Report = m => progress?.Report(new AssessmentProgress("Collection", m, -1))
        };

        var status = new Dictionary<string, CollectorStatus>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < ordered.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var c = ordered[i];
            var pct = (int)(5 + 55.0 * i / Math.Max(1, ordered.Count));
            progress?.Report(new AssessmentProgress("Collection", $"{c.DisplayName}…", pct));
            var run = await RunCollectorAsync(c, ctx, status, ct).ConfigureAwait(false);
            status[c.Id] = run.Status;
            runs.Add(run);
        }

        return Evaluate(builder.Build(_clock()), runs, settings, started, connection.TargetDescription, AssessmentMode.Live, progress, ct);
    }

    private async Task<CollectorRun> RunCollectorAsync(ICollector c, CollectionContext ctx,
        Dictionary<string, CollectorStatus> status, CancellationToken ct)
    {
        var start = _clock();
        var sw = Stopwatch.StartNew();

        var blockers = c.DependsOn.Where(d => status.TryGetValue(d, out var st) && st is CollectorStatus.Failed or CollectorStatus.Skipped).ToList();
        if (blockers.Count > 0)
        {
            var reason = $"Skipped: dependency did not succeed ({string.Join(", ", blockers)}).";
            MarkDatasets(ctx.Builder, c, CollectorStatus.Skipped, reason, Array.Empty<string>());
            _log.Warn($"Collector {c.Id}: {reason}");
            return new CollectorRun(c.Id, c.DisplayName, CollectorStatus.Skipped, start, sw.Elapsed, 0, Array.Empty<string>(), new[] { reason });
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(Math.Max(5, ctx.Settings.CollectorTimeoutSeconds)));
        try
        {
            _log.Info($"Collector {c.Id}: started.");
            var result = await Task.Run(() => c.CollectAsync(ctx, cts.Token), cts.Token).ConfigureAwait(false);
            MarkDatasets(ctx.Builder, c, result.Status, string.Join(" ", result.Errors.Concat(result.Warnings)), result.Errors);
            _log.Info($"Collector {c.Id}: {result.Status}, {result.ObjectCount} objects, {sw.Elapsed.TotalSeconds:0.0}s" +
                      (result.Errors.Count > 0 ? $", errors: {result.Errors.Count}" : ""));
            foreach (var e in result.Errors) _log.Warn($"Collector {c.Id}: {e}");
            return new CollectorRun(c.Id, c.DisplayName, result.Status, start, sw.Elapsed, result.ObjectCount, result.Errors, result.Warnings);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw; // cancelamento pedido pelo usuário
        }
        catch (OperationCanceledException)
        {
            var msg = $"Collector timed out ({ctx.Settings.CollectorTimeoutSeconds}s).";
            _log.Error($"Collector {c.Id}: {msg}");
            MarkDatasets(ctx.Builder, c, CollectorStatus.Failed, msg, new[] { msg });
            return new CollectorRun(c.Id, c.DisplayName, CollectorStatus.Failed, start, sw.Elapsed, 0, new[] { msg }, Array.Empty<string>());
        }
        catch (Exception ex)
        {
            var msg = $"{ex.GetType().Name}: {ex.Message}";
            _log.Error($"Collector {c.Id} falhou.", ex);
            MarkDatasets(ctx.Builder, c, CollectorStatus.Failed, msg, new[] { msg });
            return new CollectorRun(c.Id, c.DisplayName, CollectorStatus.Failed, start, sw.Elapsed, 0, new[] { msg }, Array.Empty<string>());
        }
    }

    /// <summary>Garante um DatasetState para cada dataset declarado, sem sobrescrever o que o collector já publicou.</summary>
    private static void MarkDatasets(SnapshotBuilder b, ICollector c, CollectorStatus st, string reason, IEnumerable<string> failedScopes)
    {
        foreach (var ds in c.Datasets)
        {
            if (b.TryGetState(ds) is not null) continue;
            var state = st switch
            {
                CollectorStatus.Succeeded => DatasetState.Complete(ds, c.Id),
                CollectorStatus.Partial => DatasetState.Partial(ds, c.Id, reason, Array.Empty<string>(), failedScopes),
                CollectorStatus.NotApplicable => DatasetState.Complete(ds, c.Id, new[] { "not applicable: " + reason }),
                _ => DatasetState.None(ds, c.Id, string.IsNullOrWhiteSpace(reason) ? "The collector produced no data." : reason, failedScopes)
            };
            b.SetState(state);
        }
    }

    // ------------------------------------------------------------------ DEMO
    public AssessmentResult RunDemo(AssessmentSnapshot demoSnapshot, AssessmentSettings settings,
        IProgress<AssessmentProgress>? progress = null, CancellationToken ct = default)
    {
        if (!demoSnapshot.IsDemo) throw new ArgumentException("RunDemo only accepts snapshots flagged IsDemo=true.", nameof(demoSnapshot));
        var started = _clock();
        _log.Info("Demo Mode: evaluating DEMO DATA (fictitious data) — no connection to Active Directory is made.");
        var runs = new[] { new CollectorRun("DemoData", "DEMO DATA (fictitious)", CollectorStatus.Succeeded, started, TimeSpan.Zero,
            demoSnapshot.Users.Count + demoSnapshot.Computers.Count, Array.Empty<string>(), new[] { "Fictitious data — it does not describe any real environment." }) };
        return Evaluate(demoSnapshot, runs, settings, started, "DEMO DATA (fictitious environment)", AssessmentMode.Demo, progress, ct);
    }

    // ------------------------------------------------------------------ COMMON
    public AssessmentResult Evaluate(AssessmentSnapshot raw, IReadOnlyList<CollectorRun> runs, AssessmentSettings settings,
        DateTimeOffset started, string target, AssessmentMode mode, IProgress<AssessmentProgress>? progress, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        progress?.Report(new AssessmentProgress("Normalization", "Normalizing collected data…", 62));
        var now = raw.CollectedAt;
        var snapshot = SnapshotNormalizer.Normalize(raw, settings, OsLifecycleCatalog.Default, now);

        progress?.Report(new AssessmentProgress("Rule Engine", $"Evaluating {_rules.Count} rules…", 70));
        var engine = new RuleEngine(_log);
        var evaluations = engine.Run(_rules, new RuleContext { Snapshot = snapshot, Settings = settings, Now = now });

        progress?.Report(new AssessmentProgress("Risk Scoring", "Calculando score e cobertura…", 90));
        var findings = evaluations.Where(e => e.Outcome == RuleOutcome.Failed && e.Finding is not null)
            .Select(e => e.Finding!)
            .OrderByDescending(f => f.Severity).ThenBy(f => f.RuleId, StringComparer.OrdinalIgnoreCase).ToArray();
        var score = ScoringEngine.Calculate(evaluations, settings.Scoring);

        var states = snapshot.States.Values.OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToList();
        foreach (var def in DatasetCatalog.All.Where(d => !d.HasCollector && !snapshot.States.ContainsKey(d.Name)))
            states.Add(snapshot.GetState(def.Name));

        var result = new AssessmentResult
        {
            Metadata = new AssessmentMetadata(Guid.NewGuid().ToString("N")[..12], ToolName, _toolVersion, started, _clock(), target, mode,
                $"{Environment.UserDomainName}\\{Environment.UserName}"),
            Environment = EnvironmentSummaryBuilder.Build(snapshot),
            CollectorRuns = runs,
            Datasets = states,
            Evaluations = evaluations,
            Findings = findings,
            Score = score,
            IsDemo = mode == AssessmentMode.Demo
        };
        _log.Info($"Assessment finished: {findings.Length} findings; Security Score {score.Overall.SecurityScore?.ToString("0.0") ?? "n/a"}; coverage {score.Overall.CoveragePercent:0}%.");
        progress?.Report(new AssessmentProgress("Done", "Done.", 100));
        return result;
    }

    /// <summary>Ordenação topológica por DependsOn (estável). Ciclos/dependências inexistentes não derrubam: mantêm a ordem de registro.</summary>
    internal static List<ICollector> Order(IReadOnlyList<ICollector> collectors)
    {
        var byId = collectors.ToDictionary(c => c.Id, StringComparer.OrdinalIgnoreCase);
        var result = new List<ICollector>();
        var state = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase); // 1 visitando, 2 pronto
        void Visit(ICollector c)
        {
            if (state.TryGetValue(c.Id, out var s) && s != 0) return;
            state[c.Id] = 1;
            foreach (var d in c.DependsOn)
                if (byId.TryGetValue(d, out var dep) && !(state.TryGetValue(dep.Id, out var ds) && ds == 1)) Visit(dep);
            state[c.Id] = 2;
            result.Add(c);
        }
        foreach (var c in collectors) Visit(c);
        return result;
    }
}
