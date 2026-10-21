using ADSecurityAssessment.App.Infrastructure;
using ADSecurityAssessment.App.Services;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.App.ViewModels;

public sealed record ReferenceItem(string Title, string Url, RelayCommand Open);

public sealed record AffectedItem(string Name, string Kind, string Domain, string DistinguishedName);

public sealed record EvidenceRow(string Object, string Property, string Value, string Expected, string Source, string CollectedAt);

/// <summary>Visão de um Finding para a UI (somente leitura).</summary>
public sealed class FindingItem
{
    public const int MaxRowsShown = 500;

    public FindingItem(Finding f, IDialogService dialogs)
    {
        Finding = f;
        RuleId = f.RuleId;
        Title = f.Title;
        Severity = f.Severity;
        SeverityName = f.Severity.ToString();
        Category = f.Category;
        Module = f.Module;
        Description = f.Description;
        Condition = f.Condition;
        Risk = f.Risk;
        Recommendation = f.Recommendation;
        Notes = f.Notes;
        AffectedCount = f.AffectedObjects.Count;
        EvidenceCount = f.Evidence.Count;
        References = f.References.Select(r => new ReferenceItem(r.Title, r.Url, new RelayCommand(() => dialogs.OpenUrl(r.Url)))).ToArray();
        Affected = f.AffectedObjects.Take(MaxRowsShown).Select(a => new AffectedItem(a.Name, a.Kind.ToString(), a.Domain ?? "", a.DistinguishedName ?? "")).ToArray();
        Evidence = f.Evidence.Take(MaxRowsShown).Select(e => new EvidenceRow(e.ObjectName, e.Property, e.Value ?? "(not set)", e.Expected ?? "", e.Source,
            e.CollectedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm"))).ToArray();
        TruncationNote = AffectedCount > MaxRowsShown || EvidenceCount > MaxRowsShown
            ? $"Showing the first {MaxRowsShown} rows; the complete list is available in the JSON/CSV export." : null;
        var searchable = string.Join('\n', RuleId, Title, Category, Module, Description, Condition,
            string.Join('\n', f.AffectedObjects.Take(2000).Select(a => a.Name + " " + a.DistinguishedName)));
        _searchText = searchable;
    }

    private readonly string _searchText;

    public Finding Finding { get; }
    public string RuleId { get; }
    public string Title { get; }
    public Severity Severity { get; }
    public string SeverityName { get; }
    public string Category { get; }
    public string Module { get; }
    public string Description { get; }
    public string Condition { get; }
    public string Risk { get; }
    public string Recommendation { get; }
    public string? Notes { get; }
    public int AffectedCount { get; }
    public int EvidenceCount { get; }
    public IReadOnlyList<ReferenceItem> References { get; }
    public IReadOnlyList<AffectedItem> Affected { get; }
    public IReadOnlyList<EvidenceRow> Evidence { get; }
    public string? TruncationNote { get; }
    public bool HasNotes => !string.IsNullOrWhiteSpace(Notes);

    public bool Matches(string? text) =>
        string.IsNullOrWhiteSpace(text) || _searchText.Contains(text.Trim(), StringComparison.OrdinalIgnoreCase);
}
