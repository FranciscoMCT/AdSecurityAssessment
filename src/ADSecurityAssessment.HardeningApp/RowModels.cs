using System.ComponentModel;
using System.Windows.Media;
using ADSecurityAssessment.Hardening.Execution;
using ADSecurityAssessment.Hardening.Model;
using ADSecurityAssessment.Hardening.Planning;
using ADSecurityAssessment.Hardening.Policy;

namespace ADSecurityAssessment.HardeningApp;

/// <summary>Linha da lista de configurações: a caixa marca/desmarca direto na seleção do planejador.</summary>
public sealed class SettingRow : INotifyPropertyChanged
{
    private static readonly Brush High = new SolidColorBrush(Color.FromRgb(0xCF, 0x22, 0x2E));
    private static readonly Brush Medium = new SolidColorBrush(Color.FromRgb(0x9A, 0x67, 0x00));
    private static readonly Brush Low = new SolidColorBrush(Color.FromRgb(0x1A, 0x7F, 0x37));

    private readonly HardeningSelection _selection;
    public event PropertyChangedEventHandler? PropertyChanged;

    public SettingRow(HardeningSelection selection, ProfileDef profile, SettingDef setting)
    {
        _selection = selection;
        ProfileId = profile.Id;
        ProfileTitle = profile.Title;
        Setting = setting;
        Tattoos = ResolveEntries.Tattoos(setting);
    }

    public string ProfileId { get; }
    public string ProfileTitle { get; }
    public SettingDef Setting { get; }
    public bool Tattoos { get; }

    public string Title => Setting.Title;
    public string Category => Setting.Category;
    public string RiskLabel => Setting.Risk switch { "high" => "Alto", "medium" => "Médio", _ => "Baixo" };
    public Brush RiskBrush => Setting.Risk switch { "high" => High, "medium" => Medium, _ => Low };
    public string TattooLabel => Tattoos ? "Sim" : "Não (some ao desvincular)";

    public bool IsChecked
    {
        get => _selection.IsEnabled(ProfileId, Setting.Id);
        set
        {
            if (value == IsChecked) return;
            _selection.SetEnabled(ProfileId, Setting.Id, value);
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsChecked)));
        }
    }

    public void Refresh() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsChecked)));
}

public sealed class PolicyRowView
{
    public PolicyRowView(AccountPolicyRow row) { Row = row; }
    public AccountPolicyRow Row { get; }
    public string Label => Row.Label;
    public string Current => Row.Current;
    public string Recommended => Row.Recommended;
    public string Note => Row.Note;
    public string StatusText => Row.Status switch { PolicyStatus.Compliant => "Conforme", PolicyStatus.Gap => "Lacuna", _ => "Não se aplica" };
    public Brush StatusBrush => Row.Status switch
    {
        PolicyStatus.Compliant => new SolidColorBrush(Color.FromRgb(0x1A, 0x7F, 0x37)),
        PolicyStatus.Gap => new SolidColorBrush(Color.FromRgb(0xCF, 0x22, 0x2E)),
        _ => Brushes.Gray
    };
}

public sealed class LedgerRowView
{
    public LedgerRowView(LedgerEntry e) { Entry = e; }
    public LedgerEntry Entry { get; }
    public string DisplayName => Entry.DisplayName;
    public string IdText => "{" + Entry.Id.ToString().ToUpperInvariant() + "}";
    public string Profile => Entry.Profile;
    public string Kind => Entry.Kind;
    public string CreatedText => Entry.CreatedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
    public string CreatedBy => Entry.CreatedBy;
}
