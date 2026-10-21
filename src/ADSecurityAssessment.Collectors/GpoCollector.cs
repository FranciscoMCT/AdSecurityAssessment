using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using ADSecurityAssessment.Collectors.Support;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Collectors;

/// <summary>
/// GPOs (objetos groupPolicyContainer) e varredura SOMENTE LEITURA do SYSVOL por arquivos de Group Policy Preferences contendo
/// o atributo cpassword. O valor do cpassword NUNCA é armazenado nem logado: registra-se apenas GPO, arquivo e tipo.
/// A varredura usa as credenciais Windows do processo (SMB); com credenciais explícitas ela é omitida e reportada como Not Evaluated.
/// </summary>
public sealed class GpoCollector : CollectorBase
{
    private static readonly string[] GppFileNames = { "Groups.xml", "Services.xml", "ScheduledTasks.xml", "DataSources.xml", "Printers.xml", "Drives.xml" };
    private static readonly Regex CPassword = new("cpassword\\s*=\\s*\"[^\"]+\"", RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromSeconds(5));
    private const long MaxFileBytes = 5 * 1024 * 1024;

    public override string Id => "gpo";
    public override string DisplayName => "Group Policy (GPO inventory + SYSVOL GPP scan)";
    public override IReadOnlyList<string> Datasets { get; } = new[] { DatasetNames.Gpos, DatasetNames.GppPasswords };
    public override IReadOnlyList<string> DependsOn { get; } = new[] { "domain" };

    public override async Task<CollectorResult> CollectAsync(CollectionContext ctx, CancellationToken ct)
    {
        var domains = ctx.Builder.Domains.ToArray();
        if (domains.Length == 0) return NoDomains();

        var gpoTracker = new ScopeTracker();
        foreach (var domain in domains)
        {
            ct.ThrowIfCancellationRequested();
            Try(ctx, gpoTracker, domain.Name, () =>
            {
                using var gw = OpenDomain(ctx, domain);
                foreach (var e in gw.Search(new SearchSpec($"CN=Policies,CN=System,{domain.DistinguishedName}", "(objectClass=groupPolicyContainer)",
                    SearchScopeKind.OneLevel, new[] { "displayName", "name", "flags", "whenChanged", "gPCFileSysPath" }), ct))
                {
                    ctx.Builder.Gpos.Add(new GpoRecord
                    {
                        Domain = domain.Name,
                        DisplayName = e.GetString("displayName") ?? e.GetString("name") ?? e.DistinguishedName,
                        Guid = e.GetString("name") ?? "",
                        DistinguishedName = e.DistinguishedName,
                        Flags = e.GetInt("flags"),
                        WhenChanged = e.GetGeneralizedTime("whenChanged"),
                        FileSysPath = e.GetString("gPCFileSysPath")
                    });
                }
            });
        }
        Publish(ctx, gpoTracker, DatasetNames.Gpos, Id);

        // ---- varredura de SYSVOL
        var gppTracker = new ScopeTracker();
        if (!ctx.Settings.ScanSysvolForGppPasswords)
            ctx.Builder.SetState(DatasetState.None(DatasetNames.GppPasswords, Id, "SYSVOL scan is disabled in config/settings.json (ScanSysvolForGppPasswords=false)."));
        else if (!ctx.Connection.UseCurrentCredentials)
            ctx.Builder.SetState(DatasetState.None(DatasetNames.GppPasswords, Id,
                "The SYSVOL scan uses the Windows identity of the process (SMB). Explicit credentials are used for LDAP only and are never persisted, so SYSVOL was not scanned."));
        else if (ctx.Builder.Gpos.Count == 0)
            ctx.Builder.SetState(DatasetState.None(DatasetNames.GppPasswords, Id, "No GPO was collected; there is nothing to scan."));
        else
        {
            var found = new ConcurrentBag<GppPasswordRecord>();
            var scanned = 0;
            var gate = new object();
            var budget = ctx.Settings.MaxGpoFilesToScan;
            await Parallel.ForEachAsync(ctx.Builder.Gpos.ToArray(), new ParallelOptions { MaxDegreeOfParallelism = 4, CancellationToken = ct }, (gpo, token) =>
            {
                var scope = $"{gpo.DisplayName} ({gpo.Domain})";
                try
                {
                    var files = ScanGpo(gpo, found, token, ref scanned, budget);
                    lock (gate) gppTracker.Succeeded(scope);
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or RegexMatchTimeoutException or InvalidOperationException)
                {
                    lock (gate) gppTracker.Fail(scope, ex.Message);
                }
                return ValueTask.CompletedTask;
            }).ConfigureAwait(false);

            foreach (var r in found.OrderBy(r => r.Domain, StringComparer.OrdinalIgnoreCase).ThenBy(r => r.RelativePath, StringComparer.OrdinalIgnoreCase))
                ctx.Builder.GppPasswords.Add(r);
            Publish(ctx, gppTracker, DatasetNames.GppPasswords, Id);
            ctx.Log.Info($"gpo: {ctx.Builder.Gpos.Count} GPOs; {scanned} GPP files examined; {found.Count} with cpassword.");
        }

        var errors = gpoTracker.Errors.Concat(gppTracker.Errors).ToArray();
        if (gpoTracker.Ok.Count == 0 && gpoTracker.Failed.Count > 0) return CollectorResult.Failed(errors);
        return errors.Length == 0
            ? CollectorResult.Ok(ctx.Builder.Gpos.Count, gppTracker.Warnings)
            : CollectorResult.Partial(ctx.Builder.Gpos.Count, errors, gppTracker.Warnings);
    }

    private static int ScanGpo(GpoRecord gpo, ConcurrentBag<GppPasswordRecord> found, CancellationToken ct, ref int scanned, int budget)
    {
        var root = gpo.FileSysPath;
        if (string.IsNullOrWhiteSpace(root)) throw new InvalidOperationException("gPCFileSysPath vazio.");
        if (!Directory.Exists(root)) throw new IOException($"GPO folder is not accessible: {root}");

        var examined = 0;
        foreach (var scopeFolder in new[] { "Machine", "User" })
        {
            var preferences = Path.Combine(root, scopeFolder, "Preferences");
            if (!Directory.Exists(preferences)) continue;
            foreach (var name in GppFileNames)
            {
                foreach (var file in Directory.EnumerateFiles(preferences, name, SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    if (Interlocked.Increment(ref scanned) > budget) throw new InvalidOperationException($"Limit of {budget:N0} GPP files examined reached (MaxGpoFilesToScan).");
                    examined++;
                    if (new FileInfo(file).Length > MaxFileBytes) continue;
                    // O conteúdo é lido apenas para testar a presença de cpassword; o valor não é guardado.
                    if (!CPassword.IsMatch(File.ReadAllText(file))) continue;
                    found.Add(new GppPasswordRecord
                    {
                        Domain = gpo.Domain,
                        GpoGuid = gpo.Guid,
                        GpoName = gpo.DisplayName,
                        RelativePath = Path.GetRelativePath(root, file),
                        Setting = name
                    });
                }
            }
        }
        return examined;
    }
}
