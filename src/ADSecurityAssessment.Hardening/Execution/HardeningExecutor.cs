using ADSecurityAssessment.Hardening.Planning;

namespace ADSecurityAssessment.Hardening.Execution;

public enum GpoOutcome { Created, Skipped, Failed }

public sealed record GpoResult(string DisplayName, GpoKind Kind, GpoOutcome Outcome, string Message, Guid? Id, IReadOnlyList<string> Notes);

public sealed class ApplyResult
{
    public List<GpoResult> Results { get; } = new();
    public bool AnyFailed => Results.Any(r => r.Outcome == GpoOutcome.Failed);
    public int CreatedCount => Results.Count(r => r.Outcome == GpoOutcome.Created);
}

public sealed record RemoveResult(bool Removed, string Message);

/// <summary>
/// Cria as GPOs do plano (sempre SEM vínculo), confere o que gravou e registra no ledger. Se a conferência falhar, desfaz aquela GPO.
/// Não existe caminho de código que vincule GPOs ou altere GPOs existentes.
/// </summary>
public sealed class HardeningExecutor
{
    private readonly IGpoStore _store;
    private readonly GpoLedger _ledger;
    private readonly IHardeningLog _log;
    private readonly string _user;

    public HardeningExecutor(IGpoStore store, GpoLedger ledger, IHardeningLog log, string? user = null)
    {
        _store = store; _ledger = ledger; _log = log;
        _user = user ?? Environment.UserDomainName + "\\" + Environment.UserName;
    }

    public ApplyResult Apply(HardeningPlan plan, CancellationToken ct = default)
    {
        var result = new ApplyResult();
        var existing = new HashSet<string>(_store.ListGpos().Select(g => g.DisplayName), StringComparer.OrdinalIgnoreCase);

        foreach (var gpo in plan.Gpos)
        {
            ct.ThrowIfCancellationRequested();
            if (gpo.Status == GpoPlanStatus.Skipped)
            {
                result.Results.Add(new GpoResult(gpo.DisplayName, gpo.Kind, GpoOutcome.Skipped, gpo.Reason, null, Array.Empty<string>()));
                continue;
            }
            // Reconfere no momento de gravar: alguém pode ter criado uma GPO com esse nome desde a prévia.
            if (existing.Contains(gpo.DisplayName))
            {
                var msg = $"Já existe uma GPO chamada '{gpo.DisplayName}' agora; nada foi criado.";
                _log.Warn(msg);
                result.Results.Add(new GpoResult(gpo.DisplayName, gpo.Kind, GpoOutcome.Skipped, msg, null, Array.Empty<string>()));
                continue;
            }

            CreatedGpo? created = null;
            try
            {
                _log.Info($"Criando GPO '{gpo.DisplayName}' ({gpo.Bundle.Files.Count} arquivos, sem vínculo)...");
                created = _store.Create(gpo.Bundle);
                var check = _store.Verify(gpo.Bundle, created);
                if (!check.Ok)
                {
                    _log.Error($"Conferência falhou para '{gpo.DisplayName}': {string.Join("; ", check.Issues)}. Desfazendo.");
                    _store.Delete(created);
                    result.Results.Add(new GpoResult(gpo.DisplayName, gpo.Kind, GpoOutcome.Failed,
                        "A conferência após a criação falhou e a GPO foi removida: " + string.Join("; ", check.Issues), null, check.Notes));
                    created = null;
                    continue;
                }

                _ledger.Add(new LedgerEntry
                {
                    Id = created.Id, DisplayName = created.DisplayName, DistinguishedName = created.DistinguishedName, SysvolPath = created.SysvolPath,
                    Profile = gpo.ProfileId, Kind = gpo.Kind.ToString(), CatalogVersion = plan.CatalogVersion, CreatedBy = _user,
                    CreatedAtUtc = DateTimeOffset.UtcNow, Domain = _store.Domain.DnsName
                });
                existing.Add(gpo.DisplayName);
                foreach (var n in check.Notes) _log.Warn($"{gpo.DisplayName}: {n}");
                _log.Info($"GPO '{gpo.DisplayName}' criada e conferida: {{{created.Id.ToString().ToUpperInvariant()}}} (SEM vínculo).");
                result.Results.Add(new GpoResult(gpo.DisplayName, gpo.Kind, GpoOutcome.Created, "Criada, conferida e SEM vínculo.", created.Id, check.Notes));
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                _log.Error($"Falha ao criar '{gpo.DisplayName}': {ex.Message}");
                var cleanup = "";
                if (created is not null && _ledger.Find(created.Id) is null)
                {
                    try { _store.Delete(created); cleanup = " A GPO parcial foi removida."; }
                    catch (Exception ex2) { cleanup = $" ATENÇÃO: não foi possível remover a GPO parcial ({ex2.Message}); remova {created.DistinguishedName} manualmente."; _log.Error(cleanup); }
                }
                result.Results.Add(new GpoResult(gpo.DisplayName, gpo.Kind, GpoOutcome.Failed, ex.Message + cleanup, null, Array.Empty<string>()));
            }
        }
        return result;
    }

    /// <summary>Remove uma GPO criada por esta ferramenta. Recusa se não estiver no ledger ou se estiver vinculada.</summary>
    public RemoveResult Remove(Guid id)
    {
        var entry = _ledger.Find(id);
        if (entry is null) return new RemoveResult(false, "Esta GPO não foi criada por esta ferramenta (não consta no registro); não será removida.");

        var links = _store.FindLinks(id);
        if (links.Count > 0)
            return new RemoveResult(false, "A GPO está vinculada em: " + string.Join("; ", links.Select(l => l.ContainerDn)) + ". Remova os vínculos no GPMC antes.");

        var current = _store.ListGpos().FirstOrDefault(g => g.Id == id);
        if (current is null)
        {
            _ledger.Remove(id);
            return new RemoveResult(true, "A GPO já não existe no domínio; o registro foi limpo.");
        }
        if (!string.Equals(current.DisplayName, entry.DisplayName, StringComparison.Ordinal))
            return new RemoveResult(false, $"O nome da GPO mudou ('{entry.DisplayName}' → '{current.DisplayName}'); ela foi editada por alguém e não será removida automaticamente.");

        _store.Delete(new CreatedGpo(entry.Id, entry.DisplayName, entry.DistinguishedName, entry.SysvolPath));
        _ledger.Remove(id);
        _log.Info($"GPO '{entry.DisplayName}' removida.");
        return new RemoveResult(true, "GPO removida.");
    }
}
