using System.Globalization;
using ADSecurityAssessment.App.Infrastructure;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.App.ViewModels;

public sealed record FactRow(string Name, string Value);
public sealed record DomainRow(string Name, string NetBios, string Level, int DomainControllers, string Users, int Computers, string Pdc);

public sealed class EnvironmentViewModel : ObservableObject
{
    public EnvironmentViewModel(AssessmentResult r)
    {
        var e = r.Environment;
        string N(int v) => v.ToString("N0", CultureInfo.InvariantCulture);
        Facts = new[]
        {
            new FactRow("Target", r.Metadata.Target),
            new FactRow("Forest", e.ForestName ?? "unknown"),
            new FactRow("Forest functional level", e.ForestFunctionalLevel ?? "unknown"),
            new FactRow("Domains", e.Domains.Count.ToString(CultureInfo.InvariantCulture)),
            new FactRow("Domain controllers", $"{e.DomainControllerCount} ({e.ReadOnlyDomainControllerCount} read-only, {e.GlobalCatalogCount} global catalog)"),
            new FactRow("Sites", e.SiteCount.ToString(CultureInfo.InvariantCulture)),
            new FactRow("Trusts", e.TrustCount.ToString(CultureInfo.InvariantCulture)),
            new FactRow("Users (enabled / total)", $"{N(e.EnabledUserCount)} / {N(e.UserCount)}"),
            new FactRow("Privileged users", N(e.PrivilegedAccountCount)),
            new FactRow("Computers", N(e.ComputerCount)),
            new FactRow("GPOs", N(e.GpoCount)),
            new FactRow("AD CS", e.AdCsDetected ? "Detected" : "Not detected"),
            new FactRow("Hybrid identity", e.HybridDetected ? "Evidence found" : "No evidence found"),
            new FactRow("Assessment executed by", r.Metadata.ExecutedBy),
            new FactRow("Started", r.Metadata.StartedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture))
        };
        Domains = e.Domains.Select(d => new DomainRow(d.Name, d.NetBiosName ?? "", d.FunctionalLevel, d.DomainControllers,
            $"{N(d.EnabledUsers)} / {N(d.Users)}", d.Computers, d.Pdc ?? "")).ToArray();
        Fsmo = e.FsmoRoles;
        OperatingSystems = e.DomainControllerOperatingSystems;
    }

    public IReadOnlyList<FactRow> Facts { get; }
    public IReadOnlyList<DomainRow> Domains { get; }
    public IReadOnlyList<string> Fsmo { get; }
    public IReadOnlyList<string> OperatingSystems { get; }
}
