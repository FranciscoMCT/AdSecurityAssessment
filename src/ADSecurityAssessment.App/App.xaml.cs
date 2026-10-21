using System.IO;
using System.Windows;
using System.Windows.Threading;
using ADSecurityAssessment.App.Platform;
using ADSecurityAssessment.App.Services;
using ADSecurityAssessment.App.ViewModels;
using ADSecurityAssessment.App.Views;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Infrastructure.Storage;
using ADSecurityAssessment.Reporting;

namespace ADSecurityAssessment.App;

/// <summary>Raiz de composição: monta caminhos portáteis, log, configuração, catálogos, serviço de assessment e a janela principal.</summary>
public partial class App : Application
{
    private CompositeLog? _log;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) => _log?.Error("Unhandled exception: " + args.ExceptionObject);
        TaskScheduler.UnobservedTaskException += (_, args) => { _log?.Error("Unobserved task exception.", args.Exception); args.SetObserved(); };

        try
        {
            var paths = PortablePaths.Resolve();
            var fileLog = new FileAssessmentLog(paths.Logs);
            _log = new CompositeLog(2000, fileLog);
            var version = typeof(App).Assembly.GetName().Version?.ToString(3) ?? "1.0.0";
            _log.Info($"AD Security Assessment {version} starting. Folder: {paths.Root}");
            if (paths.UsingFallbackForWrites)
                _log.Warn($"The application folder is not writable; reports, logs and data use {Path.GetDirectoryName(paths.Reports)}.");
            _log.Info("Mode: READ-ONLY. No Active Directory object is ever modified; no data leaves this computer.");

            SettingsStore.WriteDefaultsIfMissing(paths.Config, _log);
            var settings = SettingsStore.Load(paths.Config, _log);

            // Catálogos externos opcionais (referências oficiais e ciclo de vida do SO). Se ausentes/ inválidos, usa os embutidos.
            ReferenceCatalog.SetDefault(ReferenceCatalog.Load(Path.Combine(paths.Rules, "references.json")));
            OsLifecycleCatalog.SetDefault(OsLifecycleCatalog.Load(Path.Combine(paths.Root, "data", "os-lifecycle.json")));

            var service = new AssessmentService(settings, paths.Rules, _log, version);
            _log.Info($"{service.RuleCount} rules loaded ({service.RuleLoadErrors.Count} rejected).");
            foreach (var err in service.RuleLoadErrors) _log.Warn("Rule rejected: " + err);

            var exporter = new ReportExportService(paths.Templates, _log);
            var dialogs = new WpfDialogService(_log);
            var theme = new ThemeService(paths.Data, _log);
            theme.Initialize();

            var viewModel = new MainViewModel(service, exporter, paths.Reports, new WpfUiContext(Dispatcher), dialogs, theme, _log);
            var window = new MainWindow { DataContext = viewModel };
            MainWindow = window;
            window.Show();
        }
        catch (Exception ex)
        {
            _log?.Error("Startup failure.", ex);
            MessageBox.Show("AD Security Assessment could not start:\n\n" + ex.Message, "AD Security Assessment", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown(1);
        }
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        _log?.Error("Unhandled UI exception.", e.Exception);
        MessageBox.Show("An unexpected error occurred. The assessment never changes Active Directory.\n\n" + e.Exception.Message +
                        "\n\nDetails were written to the log.", "AD Security Assessment", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _log?.Info("AD Security Assessment closed.");
        base.OnExit(e);
    }
}
