using System.Threading;
using System.Threading.Tasks;
using ADSecurityAssessment.Collectors;
using ADSecurityAssessment.Collectors.Demo;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;
using ADSecurityAssessment.Core.Pipeline;
using ADSecurityAssessment.Infrastructure.Ldap;
using ADSecurityAssessment.Rules;

namespace ADSecurityAssessment.App.Services;

/// <summary>Composição do assessment: collectors + regras (C# e JSON) + gateway LDAP somente leitura.</summary>
public sealed class AssessmentService : IAssessmentService
{
    private readonly IReadOnlyList<IAssessmentRule> _rules;
    private readonly AssessmentSettings _settings;
    private readonly IAssessmentLog _log;
    private readonly string _version;

    public AssessmentService(AssessmentSettings settings, string rulesDirectory, IAssessmentLog log, string version)
    {
        _settings = settings;
        _log = log;
        _version = version;
        var loaded = RuleCatalog.Load(rulesDirectory, ReferenceCatalog.Default, log);
        _rules = loaded.Rules;
        RuleLoadErrors = loaded.Errors.Select(e => $"{e.Source} / {e.RuleId}: {e.Message}").ToArray();
    }

    public int RuleCount => _rules.Count;
    public IReadOnlyList<string> RuleLoadErrors { get; }

    public Task<AssessmentResult> RunLiveAsync(ConnectionInfo connection, IProgress<AssessmentProgress> progress, CancellationToken ct)
    {
        var orchestrator = new AssessmentOrchestrator(CollectorCatalog.CreateAll(), _rules, _log, toolVersion: _version);
        var gateways = new LdapGatewayFactory(connection, _settings, _log);
        return orchestrator.RunLiveAsync(connection, gateways, _settings, progress, ct);
    }

    /// <summary>Demo Mode: avalia DEMO DATA com as mesmas regras. Não abre nenhuma conexão LDAP.</summary>
    public AssessmentResult RunDemo(IProgress<AssessmentProgress>? progress)
    {
        var orchestrator = new AssessmentOrchestrator(Array.Empty<ICollector>(), _rules, _log, toolVersion: _version);
        return orchestrator.RunDemo(DemoSnapshotFactory.Create(), _settings, progress);
    }
}
