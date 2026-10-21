using System.Reflection;
using System.Text.RegularExpressions;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Rules.Json;

/// <summary>Regra declarativa (JSON). Executa apenas leitura de propriedades + comparações; nenhuma execução de código.</summary>
public sealed class JsonRule : IAssessmentRule
{
    private static readonly Regex Token = new(@"\{([A-Za-z]+)\}", RegexOptions.Compiled);

    private readonly JsonRuleDef _def;
    private readonly DatasetDefinition? _dataset;
    private readonly Predicate? _scope, _where, _applicable;
    private readonly DatasetDefinition? _applicabilityDataset, _evaluatedDataset;
    private readonly PropertyInfo? _nameProp, _domainProp, _dnProp;
    private readonly ObjectKind _kind;
    private readonly (PropertyInfo Prop, EvidenceDef Def)[] _evidence;

    internal JsonRule(JsonRuleDef def, RuleMetadata metadata, DatasetDefinition? dataset, Predicate? scope, Predicate? where,
        Predicate? applicable, DatasetDefinition? applicabilityDataset, DatasetDefinition? evaluatedDataset,
        PropertyInfo? nameProp, PropertyInfo? domainProp, PropertyInfo? dnProp, ObjectKind kind,
        (PropertyInfo, EvidenceDef)[] evidence)
    {
        _def = def; Metadata = metadata; _dataset = dataset; _scope = scope; _where = where; _applicable = applicable;
        _applicabilityDataset = applicabilityDataset; _evaluatedDataset = evaluatedDataset;
        _nameProp = nameProp; _domainProp = domainProp; _dnProp = dnProp; _kind = kind; _evidence = evidence;
    }

    public RuleMetadata Metadata { get; }

    public RuleEvaluation Evaluate(RuleContext ctx)
    {
        if (_def.Placeholder || _dataset?.Accessor is null)
            return RuleEvaluation.NotEvaluated(Metadata, _dataset?.NotCollectedReason ?? "No collector is available for this rule.");

        var s = ctx.Settings;

        if (_applicable is not null && _applicabilityDataset?.Accessor is not null)
        {
            var any = _applicabilityDataset.Accessor(ctx.Snapshot).Any(o => _applicable(o, s));
            if (!any) return RuleEvaluation.NotApplicable(Metadata, Expand(_def.ApplicableWhen!.Reason, s));
        }

        var all = _dataset.Accessor(ctx.Snapshot).ToList();
        var inScope = _scope is null ? all : all.Where(o => _scope(o, s)).ToList();
        var violators = _where is null ? inScope : inScope.Where(o => _where(o, s)).ToList();
        var evaluated = _evaluatedDataset?.Accessor is not null ? _evaluatedDataset.Accessor(ctx.Snapshot).Count() : inScope.Count;

        if (violators.Count == 0) return RuleEvaluation.Passed(Metadata, evaluated);

        var meta = Metadata with
        {
            Description = Expand(Metadata.Description, s), Condition = Expand(Metadata.Condition, s),
            Risk = Expand(Metadata.Risk, s), Recommendation = Expand(Metadata.Recommendation, s)
        };

        var affected = new List<AffectedObject>(violators.Count);
        var evidence = new List<EvidenceItem>(violators.Count * Math.Max(1, _evidence.Length));
        var source = Expand(_def.EvidenceSource ?? $"Collected dataset '{_def.Dataset}'", s);
        foreach (var o in violators)
        {
            var name = ConditionCompiler.Format(_nameProp!.GetValue(o));
            affected.Add(new AffectedObject(name, _kind, _domainProp?.GetValue(o) as string, _dnProp?.GetValue(o) as string));
            foreach (var (prop, def) in _evidence)
            {
                var v = prop.GetValue(o);
                evidence.Add(new EvidenceItem(source, name, def.Label ?? prop.Name,
                    v is null ? null : ConditionCompiler.Format(v, def.Format),
                    def.Expected is null ? null : Expand(def.Expected, s), ctx.Snapshot.CollectedAt));
            }
        }
        return RuleEvaluation.Failed(meta, affected, evidence, evaluated, _def.Notes is null ? null : Expand(_def.Notes, s), ctx.Snapshot.IsDemo);
    }

    /// <summary>Substitui {NomeDaConfiguracao} pelo valor efetivo em config/settings.json (somente propriedades de AssessmentSettings).</summary>
    internal static string Expand(string text, AssessmentSettings s) =>
        text.Contains('{') ? Token.Replace(text, m =>
        {
            var p = ConditionCompiler.FindProperty(typeof(AssessmentSettings), m.Groups[1].Value);
            return p is not null && (p.PropertyType == typeof(int) || p.PropertyType == typeof(bool))
                ? Convert.ToString(p.GetValue(s), System.Globalization.CultureInfo.InvariantCulture) ?? m.Value : m.Value;
        }) : text;
}
