using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Core.Pipeline;

public static class EnvironmentSummaryBuilder
{
    public static EnvironmentSummary Build(AssessmentSnapshot s)
    {
        var domains = s.Domains.Select(d => new DomainSummary(
            d.Name, d.NetBiosName, d.FunctionalLevelName,
            s.DomainControllers.Count(x => x.Domain.Equals(d.Name, StringComparison.OrdinalIgnoreCase)),
            s.Users.Count(u => u.Domain.Equals(d.Name, StringComparison.OrdinalIgnoreCase)),
            s.Users.Count(u => u.Enabled && u.Domain.Equals(d.Name, StringComparison.OrdinalIgnoreCase)),
            s.Computers.Count(c => c.Domain.Equals(d.Name, StringComparison.OrdinalIgnoreCase)),
            d.PdcEmulator)).ToArray();

        return new EnvironmentSummary
        {
            ForestName = s.Forest?.Name,
            ForestFunctionalLevel = s.Forest?.FunctionalLevelName,
            Domains = domains,
            DomainControllerCount = s.DomainControllers.Count,
            ReadOnlyDomainControllerCount = s.DomainControllers.Count(d => d.IsReadOnly),
            GlobalCatalogCount = s.DomainControllers.Count(d => d.IsGlobalCatalog),
            SiteCount = s.Sites.Count,
            TrustCount = s.Trusts.Count,
            UserCount = s.Users.Count,
            EnabledUserCount = s.Users.Count(u => u.Enabled),
            ComputerCount = s.Computers.Count,
            PrivilegedAccountCount = s.Users.Count(u => u.IsPrivileged),
            GpoCount = s.Gpos.Count,
            AdCsDetected = s.CertificationAuthorities.Count > 0,
            HybridDetected = s.HybridIndicators.Count > 0,
            FsmoRoles = s.FsmoRoles.Select(f => $"{f.DisplayName}: {f.OwnerHostName ?? f.OwnerServerDn ?? "?"}").ToArray(),
            DomainControllerOperatingSystems = s.DomainControllers
                .GroupBy(d => d.OperatingSystem ?? "unknown").Select(g => $"{g.Key} × {g.Count()}").ToArray()
        };
    }
}
