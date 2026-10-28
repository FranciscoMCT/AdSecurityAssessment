using System.Text;

namespace ADSecurityAssessment.Hardening.Gpo;

/// <summary>Tabela das subcategorias de auditoria avançada usadas pelo catálogo e geração de audit.csv.</summary>
public static class AuditPolicy
{
    public sealed record Subcategory(string Key, string EnglishName, Guid Id);

    private static Subcategory S(string key, string name, string guid) => new(key, name, Guid.Parse(guid));

    public static IReadOnlyDictionary<string, Subcategory> All { get; } = new[]
    {
        S("CredentialValidation", "Audit Credential Validation", "0CCE923F-69AE-11D9-BED3-505054503030"),
        S("KerberosAuthenticationService", "Audit Kerberos Authentication Service", "0CCE9242-69AE-11D9-BED3-505054503030"),
        S("KerberosServiceTicketOperations", "Audit Kerberos Service Ticket Operations", "0CCE9240-69AE-11D9-BED3-505054503030"),
        S("ComputerAccountManagement", "Audit Computer Account Management", "0CCE9236-69AE-11D9-BED3-505054503030"),
        S("SecurityGroupManagement", "Audit Security Group Management", "0CCE9237-69AE-11D9-BED3-505054503030"),
        S("DistributionGroupManagement", "Audit Distribution Group Management", "0CCE9238-69AE-11D9-BED3-505054503030"),
        S("OtherAccountManagementEvents", "Audit Other Account Management Events", "0CCE923A-69AE-11D9-BED3-505054503030"),
        S("UserAccountManagement", "Audit User Account Management", "0CCE9235-69AE-11D9-BED3-505054503030"),
        S("DirectoryServiceAccess", "Audit Directory Service Access", "0CCE923B-69AE-11D9-BED3-505054503030"),
        S("DirectoryServiceChanges", "Audit Directory Service Changes", "0CCE923C-69AE-11D9-BED3-505054503030"),
        S("Logon", "Audit Logon", "0CCE9215-69AE-11D9-BED3-505054503030"),
        S("Logoff", "Audit Logoff", "0CCE9216-69AE-11D9-BED3-505054503030"),
        S("AccountLockout", "Audit Account Lockout", "0CCE9217-69AE-11D9-BED3-505054503030"),
        S("SpecialLogon", "Audit Special Logon", "0CCE921B-69AE-11D9-BED3-505054503030"),
        S("OtherLogonLogoffEvents", "Audit Other Logon/Logoff Events", "0CCE921C-69AE-11D9-BED3-505054503030"),
        S("GroupMembership", "Audit Group Membership", "0CCE9249-69AE-11D9-BED3-505054503030"),
        S("ProcessCreation", "Audit Process Creation", "0CCE922B-69AE-11D9-BED3-505054503030"),
        S("AuditPolicyChange", "Audit Audit Policy Change", "0CCE922F-69AE-11D9-BED3-505054503030"),
        S("AuthenticationPolicyChange", "Audit Authentication Policy Change", "0CCE9230-69AE-11D9-BED3-505054503030"),
        S("SensitivePrivilegeUse", "Audit Sensitive Privilege Use", "0CCE9228-69AE-11D9-BED3-505054503030"),
        S("SecurityStateChange", "Audit Security State Change", "0CCE9210-69AE-11D9-BED3-505054503030"),
        S("SecuritySystemExtension", "Audit Security System Extension", "0CCE9211-69AE-11D9-BED3-505054503030"),
        S("SystemIntegrity", "Audit System Integrity", "0CCE9212-69AE-11D9-BED3-505054503030"),
        S("PnpActivity", "Audit PNP Activity", "0CCE9248-69AE-11D9-BED3-505054503030"),
        S("RemovableStorage", "Audit Removable Storage", "0CCE9245-69AE-11D9-BED3-505054503030"),
    }.ToDictionary(s => s.Key, StringComparer.Ordinal);

    public const string CsvHeader = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value";

    /// <summary>Valor de "Setting Value": 0 nenhum, 1 sucesso, 2 falha, 3 ambos.</summary>
    public static int SettingValue(bool success, bool failure) => (success ? 1 : 0) | (failure ? 2 : 0);

    public static string Inclusion(bool success, bool failure) =>
        success && failure ? "Success and Failure" : success ? "Success" : failure ? "Failure" : "No Auditing";

    /// <summary>audit.csv (UTF-8 sem BOM, CRLF), uma linha por subcategoria, ordenada de forma estável.</summary>
    public static byte[] BuildCsv(IEnumerable<AuditEntry> entries)
    {
        var sb = new StringBuilder();
        sb.Append(CsvHeader).Append("\r\n");
        foreach (var e in entries.GroupBy(x => x.SubcategoryKey).Select(g => g.Last()).OrderBy(x => x.SubcategoryKey, StringComparer.Ordinal))
        {
            var sub = All[e.SubcategoryKey];
            sb.Append(",System,").Append(sub.EnglishName).Append(",{").Append(sub.Id.ToString().ToUpperInvariant()).Append("},")
              .Append(Inclusion(e.Success, e.Failure)).Append(",,").Append(SettingValue(e.Success, e.Failure)).Append("\r\n");
        }
        return new UTF8Encoding(false).GetBytes(sb.ToString());
    }
}
