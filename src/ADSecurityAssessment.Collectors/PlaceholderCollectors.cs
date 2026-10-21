using ADSecurityAssessment.Collectors.Support;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Collectors;

/// <summary>
/// NTLM, LDAP signing/channel binding e SMB signing/SMBv1 são configurações de política/registro dos DCs: NÃO são legíveis por LDAP.
/// Esses collectors existem para tornar a lacuna explícita no relatório de cobertura (Skipped → regras "Not Evaluated").
/// Nunca assumem "Compliant".
/// </summary>
public abstract class UnreadableConfigurationCollector : CollectorBase
{
    protected abstract string Reason { get; }
    public override Task<CollectorResult> CollectAsync(CollectionContext ctx, CancellationToken ct)
    {
        ctx.Log.Info($"{Id}: skipped — {Reason}");
        return Task.FromResult(CollectorResult.Skipped(Reason));
    }
}

public sealed class NtlmCollector : UnreadableConfigurationCollector
{
    public override string Id => "ntlm";
    public override string DisplayName => "NTLM configuration";
    public override IReadOnlyList<string> Datasets { get; } = new[] { DatasetNames.NtlmConfig };
    protected override string Reason => "LmCompatibilityLevel and NTLM restrictions are policy/registry settings and cannot be read over LDAP.";
}

public sealed class LdapSecurityCollector : UnreadableConfigurationCollector
{
    public override string Id => "ldap-security";
    public override string DisplayName => "LDAP signing / channel binding";
    public override IReadOnlyList<string> Datasets { get; } = new[] { DatasetNames.LdapSigningConfig, DatasetNames.LdapChannelBindingConfig };
    protected override string Reason => "LDAP signing and channel binding are registry/policy settings of the DCs and cannot be read over LDAP.";
}

public sealed class SmbSecurityCollector : UnreadableConfigurationCollector
{
    public override string Id => "smb-security";
    public override string DisplayName => "SMB signing / SMBv1";
    public override IReadOnlyList<string> Datasets { get; } = new[] { DatasetNames.SmbSigningConfig, DatasetNames.Smb1Config };
    protected override string Reason => "SMB signing and the SMBv1 state are local server settings and cannot be read over LDAP.";
}
