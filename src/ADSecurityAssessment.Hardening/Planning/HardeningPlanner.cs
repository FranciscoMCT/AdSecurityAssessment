using ADSecurityAssessment.Hardening.Catalog;
using ADSecurityAssessment.Hardening.Gpo;
using ADSecurityAssessment.Hardening.Model;
using ADSecurityAssessment.Hardening.Policy;

namespace ADSecurityAssessment.Hardening.Planning;

public enum GpoKind { Main, Rollback }
public enum GpoPlanStatus { New, Revision, Skipped }
public enum ExistingGpoPolicy { Skip, NewRevision }

/// <summary>Quais configurações estão marcadas em cada perfil. Padrão = defaultOn do catálogo (alto risco sempre desmarcado).</summary>
public sealed class HardeningSelection
{
    private readonly Dictionary<string, HashSet<string>> _enabled = new(StringComparer.Ordinal);
    private readonly HashSet<string> _profiles = new(StringComparer.Ordinal);

    public static HardeningSelection Default(HardeningCatalog catalog, IEnumerable<string>? profiles = null)
    {
        var sel = new HardeningSelection();
        foreach (var p in catalog.GpoProfiles)
        {
            if (profiles is null || profiles.Contains(p.Id)) sel._profiles.Add(p.Id);
            sel._enabled[p.Id] = catalog.ForProfile(p.Id).Where(s => s.DefaultOn).Select(s => s.Id).ToHashSet(StringComparer.Ordinal);
        }
        return sel;
    }

    public bool IsProfileSelected(string profileId) => _profiles.Contains(profileId);
    public void SetProfile(string profileId, bool selected) { if (selected) _profiles.Add(profileId); else _profiles.Remove(profileId); }
    public bool IsEnabled(string profileId, string settingId) => _enabled.TryGetValue(profileId, out var set) && set.Contains(settingId);

    public void SetEnabled(string profileId, string settingId, bool enabled)
    {
        if (!_enabled.TryGetValue(profileId, out var set)) _enabled[profileId] = set = new HashSet<string>(StringComparer.Ordinal);
        if (enabled) set.Add(settingId); else set.Remove(settingId);
    }

    public IReadOnlyCollection<string> EnabledIds(string profileId) => _enabled.TryGetValue(profileId, out var s) ? s : Array.Empty<string>();
}

public sealed class PlanOptions
{
    public required HardeningSelection Selection { get; init; }
    public ExistingGpoPolicy OnExisting { get; init; } = ExistingGpoPolicy.Skip;
    public bool IncludeRollbackTwin { get; init; } = true;
    public DateTimeOffset Now { get; init; } = DateTimeOffset.Now;
}

public sealed class PlannedSetting
{
    public required SettingDef Setting { get; init; }
    /// <summary>Incluída automaticamente porque outra configuração marcada depende dela.</summary>
    public bool AutoIncluded { get; init; }
    public bool Tattoos { get; init; }
    public bool HasFullRevert { get; init; }
}

public sealed class PlannedGpo
{
    public required string ProfileId { get; init; }
    public required string ProfileTitle { get; init; }
    public required GpoKind Kind { get; init; }
    public required string DisplayName { get; init; }
    public required GpoPlanStatus Status { get; set; }
    public string Reason { get; set; } = "";
    public required string LinkTarget { get; init; }
    public required IReadOnlyList<PlannedSetting> Settings { get; init; }
    public required GpoBundle Bundle { get; init; }
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    /// <summary>Configurações sem reversão automática conhecida (só relevante na GPO principal).</summary>
    public IReadOnlyList<string> NoAutomaticRevert { get; init; } = Array.Empty<string>();
}

public sealed class HardeningPlan
{
    public required string CatalogVersion { get; init; }
    public required string DomainName { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public required IReadOnlyList<PlannedGpo> Gpos { get; init; }
    public required IReadOnlyList<AccountPolicyRow> AccountPolicy { get; init; }
    public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    public IEnumerable<PlannedGpo> ToCreate => Gpos.Where(g => g.Status != GpoPlanStatus.Skipped);
}

public static class HardeningPlanner
{
    public const string RollbackPrefix = "[ROLLBACK] ";

    public static HardeningPlan Plan(HardeningCatalog catalog, PlanOptions options, string domainName, IEnumerable<string> existingGpoNames, DomainPasswordPolicy? passwordPolicy)
    {
        var existing = new HashSet<string>(existingGpoNames, StringComparer.OrdinalIgnoreCase);
        var gpos = new List<PlannedGpo>();
        var planWarnings = new List<string>();

        foreach (var profile in catalog.GpoProfiles)
        {
            if (!options.Selection.IsProfileSelected(profile.Id)) continue;
            var ordered = Resolve(catalog, profile.Id, options.Selection);
            if (ordered.Count == 0) { planWarnings.Add($"{profile.Title}: nenhuma configuração marcada; GPO não será gerada."); continue; }

            var name = profile.GpoName;
            var status = GpoPlanStatus.New;
            var reason = "";
            if (existing.Contains(name))
            {
                if (options.OnExisting == ExistingGpoPolicy.NewRevision)
                {
                    name = $"{profile.GpoName} (rev {options.Now:yyyyMMdd-HHmm})";
                    status = GpoPlanStatus.Revision;
                    reason = $"Já existe uma GPO chamada '{profile.GpoName}'; será criada uma nova revisão. A existente não é alterada.";
                }
                else { status = GpoPlanStatus.Skipped; reason = $"Já existe uma GPO chamada '{name}'. Nada será alterado nela (ela pode ter sido editada por você)."; }
            }

            var warnings = new List<string>();
            foreach (var ps in ordered.Where(o => o.Setting.Risk == "high"))
                warnings.Add($"Alto risco marcado: {ps.Setting.Title}. Pré-requisito: {ps.Setting.Prerequisite}");
            foreach (var ps in ordered.Where(o => o.Setting.Risk != "high" && !string.IsNullOrWhiteSpace(o.Setting.Prerequisite)))
                warnings.Add($"{ps.Setting.Title}. Pré-requisito: {ps.Setting.Prerequisite}");
            if (ordered.Any(o => o.AutoIncluded)) warnings.Add("Itens incluídos automaticamente por dependência: " + string.Join("; ", ordered.Where(o => o.AutoIncluded).Select(o => o.Setting.Title)));

            var entries = ordered.SelectMany(o => ResolveEntries.Apply(o.Setting)).ToList();
            var main = new PlannedGpo
            {
                ProfileId = profile.Id, ProfileTitle = profile.Title, Kind = GpoKind.Main, DisplayName = name, Status = status, Reason = reason,
                LinkTarget = profile.LinkTarget, Settings = ordered, Bundle = GpoBundleBuilder.Build(name, entries), Warnings = warnings,
                NoAutomaticRevert = ordered.Where(o => !o.HasFullRevert).Select(o => o.Setting.Title).ToList()
            };
            gpos.Add(main);

            if (options.IncludeRollbackTwin)
            {
                var revertEntries = ordered.SelectMany(o => ResolveEntries.Revert(o.Setting, profile.Id)).ToList();
                if (revertEntries.Count > 0)
                {
                    var rbName = RollbackPrefix + name;
                    gpos.Add(new PlannedGpo
                    {
                        ProfileId = profile.Id, ProfileTitle = profile.Title, Kind = GpoKind.Rollback, DisplayName = rbName,
                        Status = existing.Contains(rbName) ? GpoPlanStatus.Skipped : (status == GpoPlanStatus.Skipped ? GpoPlanStatus.Skipped : GpoPlanStatus.New),
                        Reason = existing.Contains(rbName) ? "Já existe uma GPO de reversão com este nome." : status == GpoPlanStatus.Skipped ? "GPO principal não será criada." : "",
                        LinkTarget = "Mesmo destino da GPO principal, com precedência MAIOR, somente se for preciso reverter",
                        Settings = ordered, Bundle = GpoBundleBuilder.Build(rbName, revertEntries),
                        Warnings = new[] { "Esta GPO DESFAZ a principal gravando os valores PADRÃO do Windows assumidos no catálogo (não o valor anterior de cada máquina). Não vincule a menos que precise reverter. Remover o vínculo da principal não reverte itens de Security Options, auditoria nem chaves fora de ...\\Policies\\." }
                    });
                }
            }
        }

        var rows = passwordPolicy is null ? new List<AccountPolicyRow>() : AccountPolicyEvaluator.Evaluate(catalog.AccountPolicy, passwordPolicy);
        return new HardeningPlan
        {
            CatalogVersion = catalog.Version, DomainName = domainName, CreatedAt = options.Now,
            Gpos = gpos, AccountPolicy = rows, Warnings = planWarnings
        };
    }

    /// <summary>Marcadas + dependências (transitivas), na ordem do catálogo.</summary>
    public static List<PlannedSetting> Resolve(HardeningCatalog catalog, string profileId, HardeningSelection selection)
    {
        var wanted = new HashSet<string>(selection.EnabledIds(profileId), StringComparer.Ordinal);
        var inScope = catalog.ForProfile(profileId).ToDictionary(s => s.Id, StringComparer.Ordinal);
        wanted.IntersectWith(inScope.Keys);
        var auto = new HashSet<string>(StringComparer.Ordinal);
        var queue = new Queue<string>(wanted);
        while (queue.Count > 0)
            foreach (var r in inScope[queue.Dequeue()].Requires ?? new List<string>())
                if (inScope.ContainsKey(r) && wanted.Add(r)) { auto.Add(r); queue.Enqueue(r); }

        return catalog.ForProfile(profileId).Where(s => wanted.Contains(s.Id))
            .Select(s => new PlannedSetting { Setting = s, AutoIncluded = auto.Contains(s.Id), Tattoos = ResolveEntries.Tattoos(s), HasFullRevert = ResolveEntries.HasFullRevert(s) })
            .ToList();
    }
}
