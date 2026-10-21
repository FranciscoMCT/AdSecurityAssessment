using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Rules.Csharp;

/// <summary>AD-INFRA-003 — domínio com menos de 2 DCs graváveis.</summary>
public sealed class DomainControllerRedundancyRule : IAssessmentRule
{
    public DomainControllerRedundancyRule(ReferenceCatalog refs)
    {
        Metadata = Meta.Create(refs, "AD-INFRA-003", "Domain with fewer than two writable domain controllers",
            "Each domain should have more than one writable domain controller so that authentication and directory changes survive the loss of a DC.",
            Categories.Infrastructure, Modules.DomainControllers, Severity.Medium,
            "Number of writable (non-RODC) domain controllers discovered for a domain is lower than 2.",
            "With a single writable domain controller, a hardware, OS or virtualization failure interrupts authentication and directory writes for the entire domain, and recovery depends on backups.",
            "Add at least one more writable domain controller to the domain (ideally on a different host/failure domain) and verify replication health. Review your DC placement plan before changing the topology.",
            new[] { "dc-redundancy", "fsmo-placement" }, new[] { DatasetNames.Domains, DatasetNames.DomainControllers });
    }

    public RuleMetadata Metadata { get; }

    public RuleEvaluation Evaluate(RuleContext ctx)
    {
        var s = ctx.Snapshot;
        var affected = new List<AffectedObject>();
        var evidence = new List<EvidenceItem>();
        foreach (var d in s.Domains)
        {
            var writable = s.DomainControllers.Count(x => x.Domain.Equals(d.Name, StringComparison.OrdinalIgnoreCase) && !x.IsReadOnly);
            if (writable >= 2) continue;
            affected.Add(new AffectedObject(d.Name, ObjectKind.Domain, d.Name, d.DistinguishedName));
            evidence.Add(new EvidenceItem("LDAP: DC discovery (CN=Sites / Domain Controllers OU)", d.Name, "WritableDomainControllers",
                writable.ToString(), ">= 2", s.CollectedAt));
        }
        return affected.Count == 0
            ? RuleEvaluation.Passed(Metadata, s.Domains.Count)
            : RuleEvaluation.Failed(Metadata, affected, evidence, s.Domains.Count, isDemo: s.IsDemo);
    }
}

/// <summary>AD-DC-001 — DCs com Windows Server fora de suporte.</summary>
public sealed class DomainControllerOsSupportRule : IAssessmentRule
{
    public DomainControllerOsSupportRule(ReferenceCatalog refs)
    {
        _refs = refs;
        Metadata = Meta.Create(refs, "AD-DC-001", "Domain controller running an operating system past end of support",
            "Domain controllers must run a Windows Server version that still receives security updates. Support dates come from the official Microsoft Lifecycle pages (data/os-lifecycle.json).",
            Categories.Infrastructure, Modules.DomainControllers, Severity.High,
            "Assessment date is later than the extended support end date of the DC operating system.",
            "A domain controller without security updates exposes the entire identity infrastructure: a single unpatched vulnerability on a DC can lead to full domain compromise.",
            "Plan the replacement or in-place upgrade of the affected domain controllers to a supported Windows Server release. Where migration is not immediately possible, review Extended Security Updates eligibility as a temporary measure only.",
            new[] { "lifecycle-products", "esu-windows-server" }, new[] { DatasetNames.DomainControllers });
    }

    private readonly ReferenceCatalog _refs;
    public RuleMetadata Metadata { get; }

    public RuleEvaluation Evaluate(RuleContext ctx)
    {
        var s = ctx.Snapshot;
        var affected = new List<AffectedObject>();
        var evidence = new List<EvidenceItem>();
        var extraRefs = new Dictionary<string, MicrosoftReference>();
        var evaluated = 0;
        var unknown = new List<string>();
        foreach (var dc in s.DomainControllers)
        {
            var r = OsSupport.Check(ctx.Lifecycle, dc.OsProductKey, ctx.Now);
            if (r is null) { unknown.Add(dc.Name); continue; }
            evaluated++;
            if (!r.ExtendedSupportEnded) continue;
            affected.Add(new AffectedObject(dc.Name, ObjectKind.DomainController, dc.Domain, dc.ComputerDn));
            evidence.Add(new EvidenceItem("LDAP: computer object (operatingSystem / operatingSystemVersion)", dc.Name, "operatingSystem",
                $"{dc.OperatingSystem} {dc.OperatingSystemVersion}".Trim(), "Windows Server release within support", s.CollectedAt));
            evidence.Add(new EvidenceItem("Microsoft Lifecycle (data/os-lifecycle.json)", dc.Name, "SupportStatus", OsSupport.Describe(r), "Assessment date earlier than extended support end", s.CollectedAt));
            if (_refs.TryResolve(r.Product.ReferenceKey, out var pr)) extraRefs[r.Product.ReferenceKey] = pr;
        }
        var note = unknown.Count > 0 ? $"Operating system not recognized (not evaluated) on: {string.Join(", ", unknown)}." : null;
        if (evaluated == 0)
            return RuleEvaluation.NotEvaluated(Metadata, s.DomainControllers.Count == 0
                ? "No domain controllers were discovered."
                : "The operating system of the discovered domain controllers could not be identified against the lifecycle catalog.");
        if (affected.Count == 0) return RuleEvaluation.Passed(Metadata, evaluated);
        var meta = Metadata with { References = Metadata.References.Concat(extraRefs.Values).DistinctBy(x => x.Url).ToArray() };
        return RuleEvaluation.Failed(meta, affected, evidence, evaluated, note, s.IsDemo);
    }
}

/// <summary>AD-COMP-002 — servidores membros com SO fora de suporte.</summary>
public sealed class ServerOsSupportRule : IAssessmentRule
{
    private readonly ReferenceCatalog _refs;
    public ServerOsSupportRule(ReferenceCatalog refs)
    {
        _refs = refs;
        Metadata = Meta.Create(refs, "AD-COMP-002", "Member server running an operating system past end of support",
            "Enabled, recently active server computer accounts whose Windows Server version is past its extended support end date (Microsoft Lifecycle).",
            Categories.Infrastructure, Modules.Legacy, Severity.Medium,
            "Enabled, non-stale computer account with a Windows Server OS whose extended support has ended.",
            "Unsupported servers no longer receive security fixes and are common pivot points for lateral movement toward domain controllers and privileged credentials.",
            "Inventory the listed servers, decommission stale objects and plan migration or upgrade to a supported release. Review ESU eligibility only as a temporary bridge.",
            new[] { "lifecycle-products", "ws2012-end-of-support", "esu-windows-server" }, new[] { DatasetNames.Computers });
    }

    public RuleMetadata Metadata { get; }

    public RuleEvaluation Evaluate(RuleContext ctx)
    {
        var s = ctx.Snapshot;
        var affected = new List<AffectedObject>();
        var evidence = new List<EvidenceItem>();
        var extra = new Dictionary<string, MicrosoftReference>();
        var evaluated = 0;
        foreach (var c in s.Computers.Where(c => c.Enabled && !c.IsStale && !c.IsDomainController && c.IsServerOs))
        {
            var r = OsSupport.Check(ctx.Lifecycle, c.OsProductKey, ctx.Now);
            if (r is null) continue;
            evaluated++;
            if (!r.ExtendedSupportEnded) continue;
            affected.Add(new AffectedObject(c.Name, ObjectKind.Computer, c.Domain, c.DistinguishedName));
            evidence.Add(new EvidenceItem("LDAP: computer object (operatingSystem)", c.Name, "operatingSystem", $"{c.OperatingSystem} {c.OperatingSystemVersion}".Trim(), "Windows Server release within support", s.CollectedAt));
            evidence.Add(new EvidenceItem("LDAP: computer object (lastLogonTimestamp)", c.Name, "lastLogonTimestamp", c.LastLogonTimestamp?.ToString("yyyy-MM-dd") ?? "(not set)", $"active within {ctx.Settings.StaleAccountDays} days", s.CollectedAt));
            evidence.Add(new EvidenceItem("Microsoft Lifecycle (data/os-lifecycle.json)", c.Name, "SupportStatus", OsSupport.Describe(r), "Assessment date earlier than extended support end", s.CollectedAt));
            if (_refs.TryResolve(r.Product.ReferenceKey, out var pr)) extra[r.Product.ReferenceKey] = pr;
        }
        if (affected.Count == 0) return RuleEvaluation.Passed(Metadata, evaluated);
        var meta = Metadata with { References = Metadata.References.Concat(extra.Values).DistinctBy(x => x.Url).ToArray() };
        return RuleEvaluation.Failed(meta, affected, evidence, evaluated, "Only enabled computer accounts with logon activity within the stale-account threshold are considered; client operating systems are not evaluated.", s.IsDemo);
    }
}

/// <summary>AD-DC-003 — diferença de relógio entre DC e PDC Emulator acima da tolerância Kerberos.</summary>
public sealed class DomainControllerClockSkewRule : IAssessmentRule
{
    public DomainControllerClockSkewRule(ReferenceCatalog refs)
    {
        Metadata = Meta.Create(refs, "AD-DC-003", "Domain controller clock differs from the PDC Emulator beyond the Kerberos tolerance",
            "Kerberos requires clocks to be within the maximum tolerated skew (5 minutes by default). Each DC's current time (rootDSE currentTime) is compared with the PDC Emulator of its domain.",
            Categories.Authentication, Modules.Kerberos, Severity.High,
            "|DC time − PDC Emulator time| is greater than MaxClockSkewMinutes ({MaxClockSkewMinutes} min by default).",
            "Excessive clock skew causes Kerberos authentication failures and can lead to fallback to weaker protocols or outages of authentication for users and services.",
            "Verify the Windows Time service hierarchy: the PDC Emulator should sync from a reliable source and the other DCs from the domain hierarchy. Investigate the listed DCs.",
            new[] { "kerberos-troubleshooting", "windows-time-service" }, new[] { DatasetNames.DomainControllers, DatasetNames.Domains });
    }

    public RuleMetadata Metadata { get; }

    public RuleEvaluation Evaluate(RuleContext ctx)
    {
        var s = ctx.Snapshot;
        var limit = ctx.Settings.MaxClockSkewMinutes * 60.0;
        var measured = s.DomainControllers.Where(d => d.ClockSkewSecondsVsPdc is not null).ToList();
        if (measured.Count == 0)
            return RuleEvaluation.NotEvaluated(Metadata, "The current time of the PDC Emulator and/or the DCs could not be read via LDAP rootDSE.");
        var affected = new List<AffectedObject>();
        var evidence = new List<EvidenceItem>();
        foreach (var dc in measured.Where(d => Math.Abs(d.ClockSkewSecondsVsPdc!.Value) > limit))
        {
            affected.Add(new AffectedObject(dc.Name, ObjectKind.DomainController, dc.Domain, dc.ComputerDn));
            evidence.Add(new EvidenceItem("LDAP: rootDSE currentTime", dc.Name, "ClockSkewVsPdcSeconds",
                dc.ClockSkewSecondsVsPdc!.Value.ToString("0.0"), $"|skew| <= {limit:0} s", s.CollectedAt));
        }
        var meta = Metadata with { Condition = Metadata.Condition.Replace("{MaxClockSkewMinutes}", ctx.Settings.MaxClockSkewMinutes.ToString()) };
        return affected.Count == 0 ? RuleEvaluation.Passed(meta, measured.Count)
            : RuleEvaluation.Failed(meta, affected, evidence, measured.Count, "Skew is measured against the clocks reported by each DC at collection time (network latency is negligible compared to the minute-scale threshold).", s.IsDemo);
    }
}

/// <summary>AD-REPL-002 — replicação sem sucesso por mais tempo que o tombstone lifetime.</summary>
public sealed class ReplicationTombstoneRule : IAssessmentRule
{
    public ReplicationTombstoneRule(ReferenceCatalog refs)
    {
        Metadata = Meta.Create(refs, "AD-REPL-002", "Replication partner has not replicated successfully within the tombstone lifetime",
            "If a domain controller does not replicate inbound for longer than the forest tombstone lifetime, it can reintroduce deleted objects (lingering objects) and is blocked from replicating (event 2042).",
            Categories.Infrastructure, Modules.Replication, Severity.Critical,
            "Time since the last successful inbound replication of a naming context is greater than tombstoneLifetime of the forest.",
            "Lingering objects and divergent directory data; the affected DC may need to be demoted/rebuilt, and deleted accounts or groups may reappear.",
            "Identify the failing replication links (repadmin /showrepl), correct the underlying cause, and follow Microsoft guidance for event 2042 before re-enabling replication. Do not force replication with strict consistency disabled without reviewing the guidance.",
            new[] { "tombstone-event-2042", "replication-error-8614" }, new[] { DatasetNames.ReplicationLinks, DatasetNames.Forest });
    }

    public RuleMetadata Metadata { get; }

    public RuleEvaluation Evaluate(RuleContext ctx)
    {
        var s = ctx.Snapshot;
        var tsl = s.Forest?.TombstoneLifetimeDays;
        if (tsl is null) return RuleEvaluation.NotEvaluated(Metadata, "tombstoneLifetime could not be read from CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration.");
        var withSync = s.ReplicationLinks.Where(l => l.LastSuccessfulSync is not null).ToList();
        var affected = new List<AffectedObject>();
        var evidence = new List<EvidenceItem>();
        foreach (var l in withSync.Where(l => (ctx.Now - l.LastSuccessfulSync!.Value).TotalDays > tsl.Value))
        {
            var name = $"{l.DestinationServer} <- {l.SourceServer} [{l.NamingContext}]";
            affected.Add(new AffectedObject(name, ObjectKind.DomainController, l.Domain, null));
            evidence.Add(new EvidenceItem("Replication metadata (ReplicationNeighbor)", name, "LastSuccessfulSync", l.LastSuccessfulSync!.Value.ToString("yyyy-MM-dd HH:mm 'UTC'"), $"within {tsl} days (tombstoneLifetime)", s.CollectedAt));
            evidence.Add(new EvidenceItem("Replication metadata (ReplicationNeighbor)", name, "ConsecutiveFailures", l.ConsecutiveFailures.ToString(), "0", s.CollectedAt));
        }
        return affected.Count == 0 ? RuleEvaluation.Passed(Metadata, withSync.Count)
            : RuleEvaluation.Failed(Metadata, affected, evidence, withSync.Count, $"tombstoneLifetime read from the forest: {tsl} days.", s.IsDemo);
    }
}

/// <summary>AD-LAPS-002 — computadores sem LAPS. Só conclui quando há prova de que o atributo é legível.</summary>
public sealed class LapsCoverageRule : IAssessmentRule
{
    public LapsCoverageRule(ReferenceCatalog refs)
    {
        Metadata = Meta.Create(refs, "AD-LAPS-002", "Computers without Windows LAPS / legacy LAPS password management",
            "Enabled, recently active, non-DC computers should have a managed local administrator password (LAPS password expiration attribute populated).",
            Categories.Identity, Modules.Laps, Severity.Medium,
            "Enabled non-DC computer with neither msLAPS-PasswordExpirationTime nor ms-Mcs-AdmPwdExpirationTime populated, in a domain where LAPS is demonstrably in use.",
            "A shared or static local administrator password across machines allows one compromised host to be used for lateral movement to many others.",
            "Deploy Windows LAPS (policy-driven) to the listed computers and verify that the managed password is being backed up to Active Directory or Microsoft Entra ID as intended.",
            new[] { "laps-overview", "laps-schema" }, new[] { DatasetNames.Computers, DatasetNames.LapsInfo });
    }

    public RuleMetadata Metadata { get; }

    public RuleEvaluation Evaluate(RuleContext ctx)
    {
        var s = ctx.Snapshot;
        var affected = new List<AffectedObject>();
        var evidence = new List<EvidenceItem>();
        var evaluated = 0;
        var skipped = new List<string>();
        foreach (var info in s.LapsInfo)
        {
            var eligible = s.Computers.Where(c => c.Domain.Equals(info.Domain, StringComparison.OrdinalIgnoreCase) && c.Enabled && !c.IsDomainController && !c.IsStale).ToList();
            if (!info.SchemaExtended) { skipped.Add($"{info.Domain}: LAPS schema not present (see AD-LAPS-001)"); continue; }
            // Prova de legibilidade: se nenhum computador exibe o atributo, não dá para distinguir "sem LAPS" de "sem permissão de leitura".
            if (!eligible.Any(c => c.HasLapsExpiration)) { skipped.Add($"{info.Domain}: no computer exposes a LAPS expiration attribute (cannot distinguish 'not deployed' from 'not readable')"); continue; }
            foreach (var c in eligible)
            {
                evaluated++;
                if (c.HasLapsExpiration) continue;
                affected.Add(new AffectedObject(c.Name, ObjectKind.Computer, c.Domain, c.DistinguishedName));
                evidence.Add(new EvidenceItem("LDAP: computer object", c.Name, "msLAPS-PasswordExpirationTime / ms-Mcs-AdmPwdExpirationTime", "(not set)", "populated", s.CollectedAt));
            }
        }
        if (evaluated == 0)
        {
            var applicable = s.LapsInfo.Count > 0 && s.LapsInfo.All(i => !i.SchemaExtended);
            return applicable
                ? RuleEvaluation.NotApplicable(Metadata, "LAPS schema is not present in any domain; deployment gap is reported by AD-LAPS-001.")
                : RuleEvaluation.NotEvaluated(Metadata, string.Join("; ", skipped.DefaultIfEmpty("No LAPS information collected.")));
        }
        var note = "Absence of the expiration attribute means LAPS has not managed the computer (or the assessing account cannot read it)." + (skipped.Count > 0 ? " Not evaluated: " + string.Join("; ", skipped) + "." : "");
        return affected.Count == 0 ? RuleEvaluation.Passed(Metadata, evaluated)
            : RuleEvaluation.Failed(Metadata, affected, evidence, evaluated, note, s.IsDemo);
    }
}

/// <summary>AD-ADCS-001 — detecção de AD CS; sem CA → Not Applicable; com CA → análise de templates ainda não implementada (Not Evaluated).</summary>
public sealed class AdCsDetectionRule : IAssessmentRule
{
    public AdCsDetectionRule(ReferenceCatalog refs)
    {
        Metadata = Meta.Create(refs, "AD-ADCS-001", "AD CS certification authority security assessment",
            "AD CS is detected first (Enrollment Services container). When Enterprise CAs exist, template/ACL (ESC-style) analysis is required for a verdict.",
            Categories.AdCs, Modules.AdCs, Severity.High,
            "At least one Enterprise CA is published in CN=Enrollment Services and its certificate templates and CA permissions have been analyzed.",
            "Misconfigured certificate templates or CA permissions can allow privilege escalation to domain administrator.",
            "Review certificate template enrollment permissions, subject name supply flags and CA administration roles using the Microsoft guidance for securing AD CS.",
            new[] { "adcs-ca-role", "adcs-templates", "adcs-secure-admin" }, new[] { DatasetNames.CertificationAuthorities });
    }

    public RuleMetadata Metadata { get; }

    public RuleEvaluation Evaluate(RuleContext ctx)
    {
        var cas = ctx.Snapshot.CertificationAuthorities;
        if (cas.Count == 0)
            return RuleEvaluation.NotApplicable(Metadata, "No Enterprise Certification Authority was found in CN=Enrollment Services,CN=Public Key Services (AD CS not detected).");
        return RuleEvaluation.NotEvaluated(Metadata,
            $"AD CS detected ({cas.Count} Enterprise CA: {string.Join(", ", cas.Select(c => c.Name))}). Certificate template and CA permission analysis is not implemented in this version, so no conclusion is made — review the CAs manually.");
    }
}
