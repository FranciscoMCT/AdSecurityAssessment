using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Threading;
using ADSecurityAssessment.App.Services;
using ADSecurityAssessment.Core.Abstractions;

namespace ADSecurityAssessment.App.Platform;

/// <summary>Marshaling para a thread de UI (os collectors e o log rodam em threads de fundo).</summary>
public sealed class WpfUiContext : IUiContext
{
    private readonly Dispatcher _dispatcher;
    public WpfUiContext(Dispatcher dispatcher) => _dispatcher = dispatcher;

    public void Post(Action action)
    {
        if (_dispatcher.HasShutdownStarted) return;
        if (_dispatcher.CheckAccess()) action();
        else _dispatcher.BeginInvoke(action);
    }
}

/// <summary>Diálogos simples (MessageBox) e abertura de pasta/URL. URLs só abrem se forem do Microsoft Learn (catálogo oficial).</summary>
public sealed class WpfDialogService : IDialogService
{
    private readonly IAssessmentLog _log;
    public WpfDialogService(IAssessmentLog log) => _log = log;

    private static Window? Owner => Application.Current?.MainWindow;

    private static MessageBoxResult Show(string message, string title, MessageBoxButton buttons, MessageBoxImage icon, MessageBoxResult def)
        => Owner is { } owner
            ? MessageBox.Show(owner, message, title, buttons, icon, def)
            : MessageBox.Show(message, title, buttons, icon, def);

    public bool ConfirmExport(string title, string message) =>
        Show(message + "\n\nPress OK to export, or Cancel to abort.", title, MessageBoxButton.OKCancel, MessageBoxImage.Warning, MessageBoxResult.Cancel) == MessageBoxResult.OK;

    public void ShowInfo(string title, string message) => Show(message, title, MessageBoxButton.OK, MessageBoxImage.Information, MessageBoxResult.OK);
    public void ShowError(string title, string message) => Show(message, title, MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.OK);

    public string? PickFolder(string title, string? initialFolder)
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog { Title = title, Multiselect = false };
        if (!string.IsNullOrWhiteSpace(initialFolder) && Directory.Exists(initialFolder)) dialog.InitialDirectory = initialFolder;
        return dialog.ShowDialog(Owner) == true ? dialog.FolderName : null;
    }

    public void OpenFolder(string path)
    {
        try
        {
            Directory.CreateDirectory(path);
            var psi = new ProcessStartInfo("explorer.exe") { UseShellExecute = false };
            psi.ArgumentList.Add(path);
            Process.Start(psi)?.Dispose();
            _log.Info("Opened folder in Explorer: " + path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            _log.Warn("Could not open folder: " + ex.Message);
            ShowError("Open folder", "The folder could not be opened: " + ex.Message);
        }
    }

    public void OpenUrl(string url)
    {
        if (!ReferenceCatalog.IsOfficialUrl(url))
        {
            _log.Warn("Blocked attempt to open a non-Microsoft Learn URL.");
            ShowError("Open reference", "Only Microsoft Learn references can be opened from this application.");
            return;
        }
        try
        {
            Process.Start(new ProcessStartInfo(url) { UseShellExecute = true })?.Dispose();
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            _log.Warn("Could not open reference link: " + ex.Message);
            ShowError("Open reference", "The link could not be opened: " + ex.Message);
        }
    }
}

/// <summary>
/// Tema claro/escuro. As cores do app vêm de Themes/Light.xaml e Themes/Dark.xaml (trocados em tempo de execução);
/// em .NET 9+ o tema Fluent do WPF (Application.ThemeMode) também é aplicado, para que os controles padrão acompanhem.
/// A única preferência gravada é o nome do tema, em data/theme.txt.
/// </summary>
public sealed class ThemeService : IThemeService
{
    private readonly string _stateFile;
    private readonly IAssessmentLog _log;

    public ThemeService(string dataDirectory, IAssessmentLog log)
    {
        _stateFile = Path.Combine(dataDirectory, "theme.txt");
        _log = log;
    }

    public bool IsDark { get; private set; }

    public void Initialize()
    {
        IsDark = ReadSaved() ?? SystemPrefersDark();
        Install();
    }

    public void Apply(bool dark)
    {
        IsDark = dark;
        Install();
        try { File.WriteAllText(_stateFile, dark ? "dark" : "light"); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { _log.Debug("Theme preference not saved: " + ex.Message); }
    }

    private void Install()
    {
        var app = Application.Current;
        var source = new Uri($"/ADSecurityAssessment;component/Themes/{(IsDark ? "Dark" : "Light")}.xaml", UriKind.Relative);
        var merged = app.Resources.MergedDictionaries;
        var existing = merged.FirstOrDefault(d => d.Source is { } s &&
            (s.OriginalString.EndsWith("Themes/Light.xaml", StringComparison.OrdinalIgnoreCase) || s.OriginalString.EndsWith("Themes/Dark.xaml", StringComparison.OrdinalIgnoreCase)));
        var fresh = new ResourceDictionary { Source = source };
        if (existing is null) merged.Insert(0, fresh);
        else merged[merged.IndexOf(existing)] = fresh;

#if NET9_0_OR_GREATER
        app.ThemeMode = IsDark ? ThemeMode.Dark : ThemeMode.Light;
#endif
    }

    private bool? ReadSaved()
    {
        try
        {
            if (!File.Exists(_stateFile)) return null;
            return File.ReadAllText(_stateFile).Trim().ToLowerInvariant() switch { "dark" => true, "light" => false, _ => null };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    private static bool SystemPrefersDark()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int v && v == 0;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException) { return false; }
    }
}
