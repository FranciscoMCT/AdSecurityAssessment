using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Collectors.Support;

/// <summary>
/// Acumula quais "escopos" (ex.: um domínio, um DC) foram coletados com sucesso e quais falharam, para que uma falha parcial
/// resulte em dataset PARCIAL (e regras "Not Evaluated"), nunca em "Compliant".
/// </summary>
public sealed class ScopeTracker
{
    public List<string> Ok { get; } = new();
    public List<string> Failed { get; } = new();
    public List<string> Errors { get; } = new();
    public List<string> Warnings { get; } = new();

    public void Succeeded(string scope) => Ok.Add(scope);
    public void Fail(string scope, string error) { Failed.Add(scope); Errors.Add($"{scope}: {error}"); }
    public void Warn(string warning) => Warnings.Add(warning);

    public DatasetState ToState(string dataset, string collectorId)
    {
        var reason = string.Join(" | ", Errors.Take(5)) + (Errors.Count > 5 ? $" (+{Errors.Count - 5})" : "");
        if (Failed.Count == 0) return DatasetState.Complete(dataset, collectorId, Ok);
        return Ok.Count > 0
            ? DatasetState.Partial(dataset, collectorId, reason, Ok, Failed)
            : DatasetState.None(dataset, collectorId, reason, Failed);
    }

    public CollectorResult ToResult(int objectCount)
    {
        if (Failed.Count == 0) return CollectorResult.Ok(objectCount, Warnings);
        if (Ok.Count > 0) return CollectorResult.Partial(objectCount, Errors, Warnings);
        return new CollectorResult(CollectorStatus.Failed, objectCount, Errors.ToArray(), Warnings.ToArray());
    }
}

public abstract class CollectorBase : ICollector
{
    public abstract string Id { get; }
    public abstract string DisplayName { get; }
    public abstract IReadOnlyList<string> Datasets { get; }
    public virtual IReadOnlyList<string> DependsOn => Array.Empty<string>();
    public abstract Task<CollectorResult> CollectAsync(CollectionContext context, CancellationToken cancellationToken);

    /// <summary>Conexão inicial (domínio/DC informados pelo usuário, ou o domínio atual).</summary>
    protected static IDirectoryGateway OpenInitial(CollectionContext ctx) =>
        ctx.Gateways.Open(new GatewayTarget(null, ctx.Connection.Domain));

    /// <summary>Conexão com um domínio já descoberto (reaproveita o DC usado na descoberta).</summary>
    protected static IDirectoryGateway OpenDomain(CollectionContext ctx, DomainInfo domain) =>
        ctx.Gateways.Open(new GatewayTarget(domain.ControllerUsed, domain.Name));

    protected static void Publish(CollectionContext ctx, ScopeTracker tracker, string dataset, string collectorId) =>
        ctx.Builder.SetState(tracker.ToState(dataset, collectorId));

    /// <summary>Executa uma ação isolando falhas: registra no tracker e no log; cancelamento sempre propaga.</summary>
    protected bool Try(CollectionContext ctx, ScopeTracker tracker, string scope, Action action)
    {
        try
        {
            action();
            tracker.Succeeded(scope);
            return true;
        }
        catch (OperationCanceledException) { throw; }
        catch (DirectoryQueryException ex)
        {
            tracker.Fail(scope, ex.Message + (ex.IsPermissionDenied ? " [insufficient permission]" : ex.IsTimeout ? " [timeout]" : ""));
            ctx.Log.Warn($"{Id}/{scope}: {ex.Message}");
            return false;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            tracker.Fail(scope, $"{ex.GetType().Name}: {ex.Message}");
            ctx.Log.Warn($"{Id}/{scope}: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    protected static CollectorResult NoDomains() =>
        CollectorResult.Failed("No domain was discovered (the DomainCollector produced no data).");
}
