using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using ADSecurityAssessment.Hardening;
using ADSecurityAssessment.Hardening.Catalog;
using ADSecurityAssessment.Hardening.Execution;
using ADSecurityAssessment.Hardening.Gpo;
using ADSecurityAssessment.Hardening.Planning;
using ADSecurityAssessment.Hardening.Policy;
using ADSecurityAssessment.Hardening.Reporting;
using ADSecurityAssessment.Hardening.Windows;

namespace ADSecurityAssessment.HardeningApp;

public partial class MainWindow : Window
{
    private readonly ToolPaths _paths;
    private readonly HardeningLog _log;
    private readonly HardeningCatalog _catalog;
    private HardeningSelection _selection;
    private readonly ObservableCollection<SettingRow> _rows = new();
    private readonly ObservableCollection<PolicyRowView> _policyRows = new();
    private readonly ObservableCollection<LedgerRowView> _ledgerRows = new();

    private LdapGpoStore? _store;
    private List<string> _existingNames = new();
    private DomainPasswordPolicy? _passwordPolicy;
    private IReadOnlyList<PsoInfo> _psos = Array.Empty<PsoInfo>();
    private bool _busy;

    public MainWindow()
    {
        InitializeComponent();

        _paths = ToolPaths.Resolve(AppContext.BaseDirectory);
        _log = new HardeningLog(Path.Combine(_paths.Logs, $"hardening-{DateTime.Now:yyyyMMdd}.log"));
        _log.LineAdded += line => Dispatcher.InvokeAsync(() => { TxtLog.AppendText(line + Environment.NewLine); TxtLog.ScrollToEnd(); });
        _log.Info($"AD Security Hardening iniciado. Pasta de trabalho: {_paths.Root}");

        try { _catalog = HardeningCatalog.Load(_paths.Config); }
        catch (CatalogException ex)
        {
            _log.Error(ex.Message);
            MessageBox.Show("O arquivo config\\catalog.json é inválido e foi ignorado; usando o catálogo embutido.\n\n" + ex.Message, "Catálogo inválido", MessageBoxButton.OK, MessageBoxImage.Warning);
            _catalog = HardeningCatalog.LoadEmbedded();
        }
        _log.Info($"Catálogo {_catalog.Version} ({_catalog.Source}): {_catalog.Settings.Count} configurações.");

        _selection = HardeningSelection.Default(_catalog);
        BuildSettingRows();
        LstPolicy.ItemsSource = _policyRows;
        LstLedger.ItemsSource = _ledgerRows;
        LstLedger.SelectionChanged += (_, _) => BtnRemove.IsEnabled = LstLedger.SelectedItem is not null && _store is not null && !_busy;
        RefreshLedger();
        ShowAdvicePlaceholder();
    }

    // ---------------------------------------------------------------- plano
    private void BuildSettingRows()
    {
        _rows.Clear();
        PnlProfiles.Children.Clear();
        foreach (var profile in _catalog.GpoProfiles)
        {
            var p = profile;
            var box = new CheckBox { Content = $"{p.Title}  →  {p.GpoName}", IsChecked = _selection.IsProfileSelected(p.Id), Margin = new Thickness(0, 0, 18, 4), ToolTip = p.Description };
            box.Checked += (_, _) => _selection.SetProfile(p.Id, true);
            box.Unchecked += (_, _) => _selection.SetProfile(p.Id, false);
            PnlProfiles.Children.Add(box);
            foreach (var s in _catalog.ForProfile(p.Id)) _rows.Add(new SettingRow(_selection, p, s));
        }
        var view = CollectionViewSource.GetDefaultView(_rows);
        view.GroupDescriptions.Clear();
        view.GroupDescriptions.Add(new PropertyGroupDescription(nameof(SettingRow.ProfileTitle)));
        LstSettings.ItemsSource = view;
    }

    private void OnResetDefaults(object sender, RoutedEventArgs e)
    {
        _selection = HardeningSelection.Default(_catalog);
        BuildSettingRows();
        _log.Info("Seleção restaurada para o padrão recomendado (itens de alto risco desmarcados).");
    }

    private void OnSettingSelected(object sender, SelectionChangedEventArgs e)
    {
        if (LstSettings.SelectedItem is not SettingRow row) return;
        var s = row.Setting;
        var sb = new StringBuilder();
        sb.AppendLine(s.Title).AppendLine();
        sb.AppendLine("Por quê: " + s.Rationale).AppendLine();
        sb.AppendLine("Impacto e cuidados: " + s.Impact);
        if (!string.IsNullOrWhiteSpace(s.Prerequisite)) sb.AppendLine().AppendLine("PRÉ-REQUISITO: " + s.Prerequisite);
        sb.AppendLine().AppendLine(row.Tattoos
            ? "Este item fica gravado na máquina mesmo depois de desvincular a GPO. Para desfazer use a GPO [ROLLBACK]."
            : "Este item é removido pelo próprio Windows quando a GPO deixa de valer para a máquina.");
        if (!ResolveEntries.HasFullRevert(s)) sb.AppendLine("Sem reversão automática conhecida: volte ao valor anterior manualmente se precisar.");
        sb.AppendLine().AppendLine("Referência: " + string.Join("  ", s.References));
        TxtDetails.Text = sb.ToString();
    }

    private void OnCheckAuditTable(object sender, RoutedEventArgs e)
    {
        try
        {
            var psi = new ProcessStartInfo("auditpol.exe", "/list /subcategory:* /v") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var proc = Process.Start(psi) ?? throw new InvalidOperationException("auditpol não iniciou.");
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(15000);
            var missing = AuditPolicy.All.Values.Where(s => output.IndexOf(s.Id.ToString(), StringComparison.OrdinalIgnoreCase) < 0).ToList();
            if (missing.Count == 0)
                MessageBox.Show($"OK: as {AuditPolicy.All.Count} subcategorias de auditoria usadas pelo catálogo existem nesta versão do Windows com os mesmos GUIDs.", "Verificação de auditoria", MessageBoxButton.OK, MessageBoxImage.Information);
            else
                MessageBox.Show("Estas subcategorias não foram encontradas nesta máquina (ignoradas pelo Windows se ausentes):\n\n" + string.Join("\n", missing.Select(m => m.EnglishName)), "Verificação de auditoria", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            MessageBox.Show("Não foi possível executar o auditpol: " + ex.Message, "Verificação de auditoria", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    // ---------------------------------------------------------------- conexão
    private async void OnConnect(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        SetBusy(true);
        TxtStatus.Text = "Conectando...";
        try
        {
            var server = string.IsNullOrWhiteSpace(TxtServer.Text) ? null : TxtServer.Text.Trim();
            var result = await Task.Run(() =>
            {
                var store = new LdapGpoStore(null, server, _log);
                var names = store.ListGpos().Select(g => g.DisplayName).ToList();
                var policy = store.ReadPasswordPolicy();
                var psos = store.ListPsos();
                return (store, names, policy, psos);
            });
            _store?.Dispose();
            _store = result.store;
            _existingNames = result.names;
            _passwordPolicy = result.policy;
            _psos = result.psos;
            TxtStatus.Text = $"Conectado a {_store.Domain.Server} · domínio {_store.Domain.DnsName} · {_existingNames.Count} GPOs existentes. Criação habilitada (sempre sem vínculo).";
            BtnCreate.IsEnabled = true;
            ShowAccountPolicy();
        }
        catch (Exception ex)
        {
            _log.Error("Falha na conexão: " + ex.Message);
            TxtStatus.Text = "Falha na conexão: " + ex.Message;
            MessageBox.Show(ex.Message, "Não foi possível conectar", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally { SetBusy(false); }
    }

    private void ShowAccountPolicy()
    {
        _policyRows.Clear();
        if (_passwordPolicy is null) return;
        foreach (var r in AccountPolicyEvaluator.Evaluate(_catalog.AccountPolicy, _passwordPolicy)) _policyRows.Add(new PolicyRowView(r));
        TxtPsos.Text = _psos.Count == 0
            ? "Nenhum PSO legível (ou sem permissão para listá-los). A tabela acima reflete a Default Domain Policy."
            : "PSOs existentes (valem sobre a Default Domain Policy para os alvos deles): " +
              string.Join("; ", _psos.Select(p => $"{p.Name} (precedência {p.Precedence}, mínimo {p.MinLength}, bloqueio {p.LockoutThreshold})"));
    }

    private void ShowAdvicePlaceholder()
    {
        TxtPsos.Text = "Conecte ao domínio para ler a política de senha e de bloqueio atual.";
    }

    // ---------------------------------------------------------------- prévia / criação
    private HardeningPlan BuildPlan() =>
        HardeningPlanner.Plan(_catalog, new PlanOptions
        {
            Selection = _selection,
            OnExisting = CmbExisting.SelectedIndex == 1 ? ExistingGpoPolicy.NewRevision : ExistingGpoPolicy.Skip,
            IncludeRollbackTwin = ChkRollback.IsChecked == true,
            Now = DateTimeOffset.Now
        }, _store?.Domain.DnsName ?? "(sem conexão)", _existingNames, _passwordPolicy);

    private string SaveReport(HardeningPlan plan, ApplyResult? applied)
    {
        var safeDomain = new string(plan.DomainName.Select(c => char.IsLetterOrDigit(c) || c is '.' or '-' ? c : '_').ToArray());
        var stem = Path.Combine(_paths.Reports, $"Hardening-{safeDomain}-{DateTime.Now:yyyyMMdd-HHmmss}");
        File.WriteAllText(stem + ".html", PlanReportWriter.ToHtml(plan, applied, _psos), new UTF8Encoding(false));
        File.WriteAllText(stem + ".json", PlanReportWriter.ToJson(plan, applied), new UTF8Encoding(false));
        return stem + ".html";
    }

    private static void Open(string path)
    {
        try { Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException) { MessageBox.Show("Não foi possível abrir: " + path + "\n" + ex.Message); }
    }

    private static string Summarize(HardeningPlan plan)
    {
        var sb = new StringBuilder();
        foreach (var g in plan.Gpos)
        {
            sb.AppendLine($"[{(g.Status == GpoPlanStatus.Skipped ? "IGNORADA" : g.Status == GpoPlanStatus.Revision ? "NOVA REVISÃO" : "NOVA")}] {g.DisplayName}");
            sb.AppendLine($"    {g.Bundle.RegistryValueCount} valores de registro · {g.Bundle.SecurityOptionCount} Security Options · {g.Bundle.AuditSubcategoryCount} auditorias · {g.Settings.Count} configurações");
            if (!string.IsNullOrEmpty(g.Reason)) sb.AppendLine("    " + g.Reason);
            foreach (var w in g.Warnings) sb.AppendLine("    ⚠ " + w);
        }
        foreach (var w in plan.Warnings) sb.AppendLine("⚠ " + w);
        if (plan.Gpos.Count == 0 && plan.Warnings.Count == 0) sb.AppendLine("Nada a criar: marque ao menos um escopo e uma configuração.");
        return sb.ToString();
    }

    private void OnPreview(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        try
        {
            var plan = BuildPlan();
            var path = SaveReport(plan, null);
            TxtOutput.Text = "PRÉVIA (nada foi criado)\n\n" + Summarize(plan) + "\nRelatório: " + path;
            _log.Info("Prévia gerada: " + path);
            Open(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            MessageBox.Show(ex.Message, "Falha ao gerar a prévia", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void OnCreate(object sender, RoutedEventArgs e)
    {
        if (_busy || _store is null) return;
        var store = _store;
        HardeningPlan plan;
        GpoLedger ledger;
        try
        {
            // Atualiza a lista de nomes existentes antes de planejar, para não criar duplicatas.
            _existingNames = await Task.Run(() => store.ListGpos().Select(g => g.DisplayName).ToList());
            plan = BuildPlan();
            ledger = new GpoLedger(_paths.LedgerFile);
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Não foi possível preparar a criação", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        var toCreate = plan.ToCreate.ToList();
        if (toCreate.Count == 0) { TxtOutput.Text = Summarize(plan); MessageBox.Show("Não há GPO nova para criar com a seleção atual.", "Nada a criar"); return; }

        var confirm = MessageBox.Show(
            $"Serão criadas {toCreate.Count} GPO(s) em {store.Domain.DnsName}, todas SEM vínculo:\n\n" +
            string.Join("\n", toCreate.Select(g => "  • " + g.DisplayName)) +
            "\n\nNenhum computador será afetado até você vinculá-las. Deseja continuar?",
            "Confirmar criação", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
        if (confirm != MessageBoxResult.Yes) return;

        SetBusy(true);
        try
        {
            var executor = new HardeningExecutor(store, ledger, _log);
            var applied = await Task.Run(() => executor.Apply(plan));
            var path = SaveReport(plan, applied);
            var sb = new StringBuilder("RESULTADO\n\n");
            foreach (var r in applied.Results)
            {
                sb.AppendLine($"[{r.Outcome}] {r.DisplayName}");
                sb.AppendLine("    " + r.Message);
                foreach (var n in r.Notes) sb.AppendLine("    ⚠ " + n);
            }
            sb.AppendLine().AppendLine("Relatório: " + path);
            sb.AppendLine().AppendLine("PRÓXIMO PASSO: no GPMC, vincule a GPO a uma OU piloto (não ao domínio inteiro) e valide com gpupdate /force e gpresult /h.");
            TxtOutput.Text = sb.ToString();
            _existingNames = await Task.Run(() => store.ListGpos().Select(g => g.DisplayName).ToList());
            RefreshLedger();
            Open(path);
        }
        catch (Exception ex)
        {
            _log.Error("Falha na criação: " + ex.Message);
            MessageBox.Show(ex.Message, "Falha na criação", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally { SetBusy(false); }
    }

    // ---------------------------------------------------------------- GPOs criadas
    private void RefreshLedger()
    {
        _ledgerRows.Clear();
        try { foreach (var en in new GpoLedger(_paths.LedgerFile).Entries.OrderByDescending(x => x.CreatedAtUtc)) _ledgerRows.Add(new LedgerRowView(en)); }
        catch (InvalidDataException ex) { MessageBox.Show(ex.Message, "Registro corrompido", MessageBoxButton.OK, MessageBoxImage.Warning); }
    }

    private void OnRefreshLedger(object sender, RoutedEventArgs e) => RefreshLedger();

    private void OnOpenReports(object sender, RoutedEventArgs e) => Open(_paths.Reports);

    private async void OnRemove(object sender, RoutedEventArgs e)
    {
        if (_busy || _store is null || LstLedger.SelectedItem is not LedgerRowView row) return;
        var store = _store;
        var ok = MessageBox.Show($"Remover a GPO '{row.DisplayName}' ({row.IdText})?\n\nSó é removida se estiver SEM vínculo. Isso apaga o objeto no AD e a pasta no SYSVOL.",
            "Confirmar remoção", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (ok != MessageBoxResult.Yes) return;
        SetBusy(true);
        try
        {
            var result = await Task.Run(() => new HardeningExecutor(store, new GpoLedger(_paths.LedgerFile), _log).Remove(row.Entry.Id));
            MessageBox.Show(result.Message, result.Removed ? "Removida" : "Não removida", MessageBoxButton.OK, result.Removed ? MessageBoxImage.Information : MessageBoxImage.Warning);
            RefreshLedger();
        }
        catch (Exception ex)
        {
            _log.Error("Falha na remoção: " + ex.Message);
            MessageBox.Show(ex.Message, "Falha na remoção", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally { SetBusy(false); }
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        BtnConnect.IsEnabled = !busy;
        BtnPreview.IsEnabled = !busy;
        BtnCreate.IsEnabled = !busy && _store is not null;
        BtnRemove.IsEnabled = !busy && _store is not null && LstLedger.SelectedItem is not null;
        Cursor = busy ? System.Windows.Input.Cursors.Wait : null;
    }

    protected override void OnClosed(EventArgs e)
    {
        _store?.Dispose();
        base.OnClosed(e);
    }
}
