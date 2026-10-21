using System.Collections.ObjectModel;
using ADSecurityAssessment.App.Infrastructure;
using ADSecurityAssessment.App.Services;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.App.ViewModels;

/// <summary>Lista de findings com busca, filtro por severidade/categoria e ordenação (por severidade por padrão).</summary>
public sealed class FindingsViewModel : ObservableObject
{
    public const string All = "All";

    public static readonly IReadOnlyList<string> SortModes = new[] { "Severity", "Rule ID", "Affected objects", "Category" };

    private readonly IReadOnlyList<FindingItem> _all;
    private string _searchText = "";
    private string _selectedSeverity = All;
    private string _selectedCategory = All;
    private string _selectedSort = SortModes[0];
    private FindingItem? _selected;
    private string _countText = "";

    public FindingsViewModel(IEnumerable<Finding> findings, IDialogService dialogs)
    {
        _all = findings.Select(f => new FindingItem(f, dialogs)).ToArray();
        Severities = new[] { All }.Concat(Enum.GetValues<Severity>().OrderByDescending(s => s).Select(s => s.ToString())).ToArray();
        Categories = new[] { All }.Concat(_all.Select(f => f.Category).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(c => c)).ToArray();
        Refresh();
    }

    public IReadOnlyList<string> Severities { get; }
    public IReadOnlyList<string> Categories { get; }
    public IReadOnlyList<string> Sorts => SortModes;
    public ObservableCollection<FindingItem> Items { get; } = new();
    public bool HasFindings => _all.Count > 0;
    public bool HasItems => Items.Count > 0;

    public string SearchText { get => _searchText; set { if (SetProperty(ref _searchText, value)) Refresh(); } }
    public string SelectedSeverity { get => _selectedSeverity; set { if (SetProperty(ref _selectedSeverity, value)) Refresh(); } }
    public string SelectedCategory { get => _selectedCategory; set { if (SetProperty(ref _selectedCategory, value)) Refresh(); } }
    public string SelectedSort { get => _selectedSort; set { if (SetProperty(ref _selectedSort, value)) Refresh(); } }
    public FindingItem? Selected { get => _selected; set { if (SetProperty(ref _selected, value)) OnPropertyChanged(nameof(HasSelection)); } }
    public bool HasSelection => _selected is not null;
    public string CountText { get => _countText; private set => SetProperty(ref _countText, value); }

    /// <summary>Seleciona um finding pelo RuleId (usado pelos atalhos do dashboard). Limpa filtros se necessário.</summary>
    public void Select(string ruleId)
    {
        var item = _all.FirstOrDefault(f => f.RuleId.Equals(ruleId, StringComparison.OrdinalIgnoreCase));
        if (item is null) return;
        if (!Items.Contains(item)) { SearchText = ""; SelectedSeverity = All; SelectedCategory = All; }
        Selected = item;
    }

    public void FilterBySeverity(Severity severity) { SearchText = ""; SelectedCategory = All; SelectedSeverity = severity.ToString(); }
    public void FilterByCategory(string category) { SearchText = ""; SelectedSeverity = All; SelectedCategory = category; }

    private void Refresh()
    {
        var q = _all.AsEnumerable();
        if (_selectedSeverity != All && Enum.TryParse<Severity>(_selectedSeverity, out var sev)) q = q.Where(f => f.Severity == sev);
        if (_selectedCategory != All) q = q.Where(f => f.Category.Equals(_selectedCategory, StringComparison.OrdinalIgnoreCase));
        q = q.Where(f => f.Matches(_searchText));

        q = _selectedSort switch
        {
            "Rule ID" => q.OrderBy(f => f.RuleId, StringComparer.OrdinalIgnoreCase),
            "Affected objects" => q.OrderByDescending(f => f.AffectedCount).ThenByDescending(f => f.Severity),
            "Category" => q.OrderBy(f => f.Category, StringComparer.OrdinalIgnoreCase).ThenByDescending(f => f.Severity),
            _ => q.OrderByDescending(f => f.Severity).ThenBy(f => f.RuleId, StringComparer.OrdinalIgnoreCase)
        };

        var keep = _selected;
        Items.Clear();
        foreach (var f in q) Items.Add(f);
        CountText = $"{Items.Count} of {_all.Count} findings";
        OnPropertyChanged(nameof(HasItems));
        Selected = keep is not null && Items.Contains(keep) ? keep : Items.FirstOrDefault();
    }
}
