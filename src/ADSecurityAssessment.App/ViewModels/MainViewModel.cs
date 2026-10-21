using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.ObjectModel;
using System.Security;
using ADSecurityAssessment.App.Infrastructure;
using ADSecurityAssessment.App.Services;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;
using ADSecurityAssessment.Core.Pipeline;
using ADSecurityAssessment.Reporting;

namespace ADSecurityAssessment.App.ViewModels;

public enum AppPage { Dashboard, Findings, Coverage, Environment, Log }
public enum ViewState { Start, Running, Results }

/// <summary>
/// Orquestra a tela: conexão → execução (com progresso/cancelamento) → resultados → exportação.
/// A senha nunca é guardada no ViewModel: é obtida de <see cref="PasswordProvider"/> (cópia de SecureString) no momento da conexão
/// e descartada ao final da execução.
/// </summary>
public sealed class MainViewModel : ObservableObject
{
    private const int MaxLogLines = 2000;

    private readonly IAssessmentService _service;
    private readonly ReportExportService _exporter;
    private string _reportFolder;
    private bool _autoExport = true;
    private readonly IUiContext _ui;
    private readonly IDialogService _dialogs;
    private readonly IThemeService _theme;
    private CancellationTokenSource? _cts;

    private ViewState _state = ViewState.Start;
    private AppPage _page = AppPage.Dashboard;
    private AssessmentResult? _result;
    private DashboardViewModel? _dashboard;
    private FindingsViewModel? _findings;
    private CoverageViewModel? _coverage;
    private EnvironmentViewModel? _environment;
    private string _domain = "";
    private string _controller = "";
    private string _username = "";
    private double _progress;
    private string _progressMessage = "";
    private bool _indeterminate = true;
    private string? _error;
    private string? _exportStatus;

    public MainViewModel(IAssessmentService service, ReportExportService exporter, string reportsFolder, IUiContext ui, IDialogService dialogs,
        IThemeService theme, CompositeLog log)
    {
        _service = service; _exporter = exporter; _reportFolder = reportsFolder; _ui = ui; _dialogs = dialogs; _theme = theme;
        log.LineWritten += line => _ui.Post(() =>
        {
            LogLines.Add(line);
            while (LogLines.Count > MaxLogLines) LogLines.RemoveAt(0);
        });
        foreach (var l in log.Snapshot()) LogLines.Add(l);

        AnalyzeCurrentCommand = new AsyncRelayCommand(_ => RunLiveAsync(new ConnectionInfo { UseCurrentCredentials = true }), _ => State == ViewState.Start, OnError);
        ConnectCommand = new AsyncRelayCommand(_ => ConnectExplicitAsync(), _ => State == ViewState.Start, OnError);
        DemoCommand = new AsyncRelayCommand(_ => RunDemoAsync(), _ => State == ViewState.Start, OnError);
        CancelCommand = new RelayCommand(() => _cts?.Cancel(), () => State == ViewState.Running);
        NewAssessmentCommand = new RelayCommand(NewAssessment, () => State == ViewState.Results);
        NavigateCommand = new RelayCommand(p => { if (p is string s && Enum.TryParse<AppPage>(s, out var page)) CurrentPage = page; });
        ExportCommand = new AsyncRelayCommand(p => ExportAsync(p as string ?? "HTML"), _ => State == ViewState.Results, OnError);
        OpenReportsFolderCommand = new RelayCommand(() => _dialogs.OpenFolder(ReportFolder));
        BrowseReportFolderCommand = new RelayCommand(() =>
        {
            var picked = _dialogs.PickFolder("Choose the folder where the report will be saved", ReportFolder);
            if (!string.IsNullOrWhiteSpace(picked)) ReportFolder = picked;
        });
        ToggleThemeCommand = new RelayCommand(() => { _theme.Apply(!_theme.IsDark); OnPropertyChanged(nameof(ThemeLabel)); });
    }

    // ------------------------------------------------------------------ estado
    public ViewState State
    {
        get => _state;
        private set
        {
            if (!SetProperty(ref _state, value)) return;
            OnPropertyChanged(nameof(IsStart)); OnPropertyChanged(nameof(IsRunning)); OnPropertyChanged(nameof(IsResults));
            RaiseCommandStates();
        }
    }

    public bool IsStart => State == ViewState.Start;
    public bool IsRunning => State == ViewState.Running;
    public bool IsResults => State == ViewState.Results;

    public AppPage CurrentPage
    {
        get => _page;
        set { if (SetProperty(ref _page, value)) { OnPropertyChanged(nameof(IsDashboardPage)); OnPropertyChanged(nameof(IsFindingsPage)); OnPropertyChanged(nameof(IsCoveragePage)); OnPropertyChanged(nameof(IsEnvironmentPage)); OnPropertyChanged(nameof(IsLogPage)); } }
    }
    public bool IsDashboardPage => CurrentPage == AppPage.Dashboard;
    public bool IsFindingsPage => CurrentPage == AppPage.Findings;
    public bool IsCoveragePage => CurrentPage == AppPage.Coverage;
    public bool IsEnvironmentPage => CurrentPage == AppPage.Environment;
    public bool IsLogPage => CurrentPage == AppPage.Log;

    public AssessmentResult? Result { get => _result; private set { if (SetProperty(ref _result, value)) { OnPropertyChanged(nameof(IsDemo)); OnPropertyChanged(nameof(WindowTitle)); } } }
    public DashboardViewModel? Dashboard { get => _dashboard; private set => SetProperty(ref _dashboard, value); }
    public FindingsViewModel? Findings { get => _findings; private set => SetProperty(ref _findings, value); }
    public CoverageViewModel? Coverage { get => _coverage; private set => SetProperty(ref _coverage, value); }
    public EnvironmentViewModel? Environment { get => _environment; private set => SetProperty(ref _environment, value); }

    public bool IsDemo => Result?.IsDemo == true;
    public string DemoBanner => "DEMO DATA — fictitious data for demonstration only. It does not describe any real environment.";
    public string WindowTitle => IsDemo ? "AD Security Assessment — DEMO DATA" : "AD Security Assessment";
    public string ThemeLabel => _theme.IsDark ? "Light mode" : "Dark mode";
    public string RulesInfo => $"{_service.RuleCount} rules loaded";
    public IReadOnlyList<string> RuleLoadErrors => _service.RuleLoadErrors;
    public bool HasRuleLoadErrors => _service.RuleLoadErrors.Count > 0;

    // ------------------------------------------------------------------ conexão
    public string ConnectDomain { get => _domain; set => SetProperty(ref _domain, value); }
    public string ConnectController { get => _controller; set => SetProperty(ref _controller, value); }
    public string ConnectUsername { get => _username; set => SetProperty(ref _username, value); }

    /// <summary>Fornecido pela View: retorna uma CÓPIA do SecureString do PasswordBox (descartada pelo ViewModel).</summary>
    public Func<SecureString?>? PasswordProvider { get; set; }
    /// <summary>Chamado ao final da execução para a View limpar o PasswordBox.</summary>
    public Action? ClearPassword { get; set; }

    public double ProgressPercent { get => _progress; private set => SetProperty(ref _progress, value); }
    public string ProgressMessage { get => _progressMessage; private set => SetProperty(ref _progressMessage, value); }
    public bool IsIndeterminate { get => _indeterminate; private set => SetProperty(ref _indeterminate, value); }
    public string? ErrorMessage { get => _error; private set { if (SetProperty(ref _error, value)) OnPropertyChanged(nameof(HasError)); } }
    public bool HasError => !string.IsNullOrEmpty(ErrorMessage);
    public string? ExportStatus { get => _exportStatus; private set { if (SetProperty(ref _exportStatus, value)) OnPropertyChanged(nameof(HasExportStatus)); } }
    public bool HasExportStatus => !string.IsNullOrEmpty(ExportStatus);
    public ObservableCollection<string> LogLines { get; } = new();

    public string PrivacyStatement =>
        "Read-only assessment · no changes are made to Active Directory · passwords are never stored · all processing is local (nothing is sent to the Internet).";

    // ------------------------------------------------------------------ comandos
    public AsyncRelayCommand AnalyzeCurrentCommand { get; }
    public AsyncRelayCommand ConnectCommand { get; }
    public AsyncRelayCommand DemoCommand { get; }
    public RelayCommand CancelCommand { get; }
    public RelayCommand NewAssessmentCommand { get; }
    public RelayCommand NavigateCommand { get; }
    public AsyncRelayCommand ExportCommand { get; }
    public RelayCommand OpenReportsFolderCommand { get; }
    public RelayCommand BrowseReportFolderCommand { get; }

    /// <summary>Pasta onde os relatórios são gravados (editável; padrão = reports\ ao lado do executável).</summary>
    public string ReportFolder
    {
        get => _reportFolder;
        set => SetProperty(ref _reportFolder, value ?? "");
    }

    /// <summary>Se verdadeiro, exporta HTML + JSON + CSV automaticamente ao terminar a análise (após o aviso de dados sensíveis).</summary>
    public bool AutoExport
    {
        get => _autoExport;
        set => SetProperty(ref _autoExport, value);
    }
    public RelayCommand ToggleThemeCommand { get; }

    private void RaiseCommandStates()
    {
        AnalyzeCurrentCommand.RaiseCanExecuteChanged(); ConnectCommand.RaiseCanExecuteChanged(); DemoCommand.RaiseCanExecuteChanged();
        CancelCommand.RaiseCanExecuteChanged(); NewAssessmentCommand.RaiseCanExecuteChanged(); ExportCommand.RaiseCanExecuteChanged();
    }

    private void OnError(Exception ex) { ErrorMessage = ex.Message; State = ViewState.Start; }

    private async Task ConnectExplicitAsync()
    {
        var domain = ConnectDomain.Trim();
        if (domain.Length == 0) { ErrorMessage = "Enter the domain name (for example contoso.com)."; return; }

        var user = ConnectUsername.Trim();
        SecureString? password = null;
        try
        {
            if (user.Length > 0)
            {
                password = PasswordProvider?.Invoke();
                if (password is null || password.Length == 0) { ErrorMessage = "Enter the password for the specified user."; return; }
            }
            var connection = new ConnectionInfo
            {
                UseCurrentCredentials = user.Length == 0,
                Domain = domain,
                DomainController = string.IsNullOrWhiteSpace(ConnectController) ? null : ConnectController.Trim(),
                Username = user.Length == 0 ? null : user,
                Password = password
            };
            await RunLiveAsync(connection).ConfigureAwait(true);
        }
        finally
        {
            password?.Dispose();
            ClearPassword?.Invoke();
        }
    }

    private Task RunLiveAsync(ConnectionInfo connection) =>
        RunAsync((progress, ct) => _service.RunLiveAsync(connection, progress, ct));

    private Task RunDemoAsync() =>
        RunAsync((progress, ct) => Task.Run(() => _service.RunDemo(progress), ct));

    private async Task RunAsync(Func<IProgress<AssessmentProgress>, CancellationToken, Task<AssessmentResult>> work)
    {
        ErrorMessage = null; ExportStatus = null;
        ProgressPercent = 0; ProgressMessage = "Starting…"; IsIndeterminate = true;
        State = ViewState.Running;
        _cts = new CancellationTokenSource();
        var progress = new Progress<AssessmentProgress>(p =>
        {
            ProgressMessage = p.Message;
            if (p.Percent >= 0) { IsIndeterminate = false; ProgressPercent = p.Percent; }
        });
        try
        {
            var result = await work(progress, _cts.Token).ConfigureAwait(true);
            ShowResult(result);
            if (AutoExport) await TryAutoExportAsync().ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
            ErrorMessage = "The assessment was cancelled. No data was changed in Active Directory.";
            State = ViewState.Start;
        }
        catch (Exception ex)
        {
            ErrorMessage = $"The assessment could not be completed: {ex.Message}";
            State = ViewState.Start;
        }
        finally
        {
            _cts?.Dispose();
            _cts = null;
        }
    }

    private void ShowResult(AssessmentResult r)
    {
        var findings = new FindingsViewModel(r.Findings, _dialogs);
        Findings = findings;
        Dashboard = new DashboardViewModel(r,
            sev => { findings.FilterBySeverity(sev); CurrentPage = AppPage.Findings; },
            cat => { findings.FilterByCategory(cat); CurrentPage = AppPage.Findings; },
            id => { findings.Select(id); CurrentPage = AppPage.Findings; });
        Coverage = new CoverageViewModel(r);
        Environment = new EnvironmentViewModel(r);
        Result = r;
        CurrentPage = AppPage.Dashboard;
        State = ViewState.Results;
    }

    private void NewAssessment()
    {
        Result = null; Dashboard = null; Findings = null; Coverage = null; Environment = null; ExportStatus = null; ErrorMessage = null;
        State = ViewState.Start;
    }

    /// <summary>Exportação automática: um erro aqui nunca descarta o resultado já exibido.</summary>
    private async Task TryAutoExportAsync()
    {
        try { await ExportAsync("ALL").ConfigureAwait(true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            ExportStatus = "The report could not be saved: " + ex.Message;
        }
    }

    private async Task ExportAsync(string format)
    {
        if (Result is null) return;
        var folder = ReportFolder.Trim();
        if (folder.Length == 0) { ExportStatus = "Choose a report folder first."; return; }
        if (!_dialogs.ConfirmExport(ExportWarning.Title, (Result.IsDemo ? ExportWarning.DemoMessage + "\n\n" : "") + ExportWarning.Message + "\n\nFiles are written locally to:\n" + folder))
            return;
        var formats = format.Equals("ALL", StringComparison.OrdinalIgnoreCase) ? new[] { "HTML", "JSON", "CSV" } : new[] { format };
        var files = await _exporter.ExportAsync(Result, folder, formats, CancellationToken.None).ConfigureAwait(true);
        ExportStatus = "Exported: " + string.Join("; ", files.Select(Path.GetFileName)) + "  →  " + folder;
    }
}
