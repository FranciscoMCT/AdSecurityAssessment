using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Core.Pipeline;

/// <summary>
/// Etapa "Normalization": deriva campos a partir dos dados coletados (idade de senha, inatividade, pertencimento privilegiado,
/// produto/ciclo de vida do SO, diferença de relógio). Não cria conclusões — só fatos derivados, com o relógio da coleta.
/// </summary>
public static class SnapshotNormalizer
{
    public static AssessmentSnapshot Normalize(AssessmentSnapshot s, AssessmentSettings settings, OsLifecycleCatalog lifecycle, DateTimeOffset now)
    {
        var privilegedByDn = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var protectedUsers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var m in s.PrivilegedMemberships)
        {
            if (string.IsNullOrEmpty(m.MemberDn)) continue;
            if (m.GroupKey == "ProtectedUsers") { protectedUsers.Add(m.MemberDn); continue; }
            if (!privilegedByDn.TryGetValue(m.MemberDn, out var l)) privilegedByDn[m.MemberDn] = l = new List<string>();
            var label = $"{m.GroupName}@{m.Domain}";
            if (!l.Contains(label)) l.Add(label);
        }

        var domainHasPu = s.Domains.ToDictionary(d => d.Name, d => d.ProtectedUsersGroupExists, StringComparer.OrdinalIgnoreCase);

        var users = s.Users.Select(u =>
        {
            var dn = u.DistinguishedName ?? "";
            privilegedByDn.TryGetValue(dn, out var groups);
            return u with
            {
                IsPrivileged = groups is { Count: > 0 },
                PrivilegedGroups = groups?.ToArray() ?? Array.Empty<string>(),
                IsProtectedUsersMember = protectedUsers.Contains(dn),
                DomainHasProtectedUsersGroup = domainHasPu.TryGetValue(u.Domain, out var has) && has,
                PasswordAgeDays = u.PasswordLastSet is null ? null : Days(now, u.PasswordLastSet.Value),
                DaysSinceLastLogon = u.LastLogonTimestamp is null ? null : Days(now, u.LastLogonTimestamp.Value),
                IsStale = IsStale(u.LastLogonTimestamp, u.WhenCreated, now, settings.StaleAccountDays)
            };
        }).ToArray();

        var computers = s.Computers.Select(c =>
        {
            var product = lifecycle.Find(c.OperatingSystem, c.OperatingSystemVersion);
            return c with
            {
                OsProductKey = product?.Key,
                DaysSinceLastLogon = c.LastLogonTimestamp is null ? null : Days(now, c.LastLogonTimestamp.Value),
                IsStale = IsStale(c.LastLogonTimestamp, c.WhenCreated, now, settings.StaleAccountDays)
            };
        }).ToArray();

        // Relógio dos DCs em relação ao PDC Emulator do mesmo domínio.
        var pdcByDomain = s.Domains.Where(d => !string.IsNullOrEmpty(d.PdcEmulator))
            .ToDictionary(d => d.Name, d => d.PdcEmulator!, StringComparer.OrdinalIgnoreCase);
        var dcs = s.DomainControllers.Select(dc =>
        {
            double? skew = null;
            if (dc.CurrentTime is not null && pdcByDomain.TryGetValue(dc.Domain, out var pdcHost))
            {
                var pdc = s.DomainControllers.FirstOrDefault(x => x.Domain.Equals(dc.Domain, StringComparison.OrdinalIgnoreCase)
                    && (string.Equals(x.DnsHostName, pdcHost, StringComparison.OrdinalIgnoreCase) || string.Equals(x.Name, pdcHost, StringComparison.OrdinalIgnoreCase)));
                if (pdc?.CurrentTime is not null) skew = (dc.CurrentTime.Value - pdc.CurrentTime.Value).TotalSeconds;
            }
            var product = lifecycle.Find(dc.OperatingSystem, dc.OperatingSystemVersion);
            return dc with { ClockSkewSecondsVsPdc = skew, OsProductKey = product?.Key };
        }).ToArray();

        var hybrid = s.HybridIndicators.Select(h => h with { PasswordAgeDays = h.PasswordLastSet is null ? null : Days(now, h.PasswordLastSet.Value) }).ToArray();

        return s with { Users = users, Computers = computers, DomainControllers = dcs, HybridIndicators = hybrid };
    }

    public static int Days(DateTimeOffset now, DateTimeOffset then) => (int)Math.Floor((now - then).TotalDays);

    /// <summary>
    /// Stale = sem logon (lastLogonTimestamp) há mais de N dias; contas que nunca logaram usam whenCreated.
    /// lastLogonTimestamp só é replicado quando mais antigo que msDS-LogonTimeSyncInterval (padrão 14 dias), por isso o limiar é grande.
    /// </summary>
    public static bool IsStale(DateTimeOffset? lastLogon, DateTimeOffset? created, DateTimeOffset now, int staleDays)
    {
        var reference = lastLogon ?? created;
        return reference is not null && (now - reference.Value).TotalDays > staleDays;
    }
}
