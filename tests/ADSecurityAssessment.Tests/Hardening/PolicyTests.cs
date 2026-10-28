using ADSecurityAssessment.Hardening.Policy;

namespace ADSecurityAssessment.Tests.Hardening;

public class PolicyTests
{
    private static AccountPolicyRow Row(DomainPasswordPolicy p, string id) =>
        AccountPolicyEvaluator.Evaluate(HCat.Embedded().AccountPolicy, p).First(r => r.Id == id);

    [Fact]
    public void WeakDefaults_AreReportedAsGaps()
    {
        var weak = new DomainPasswordPolicy(7, 1, 0, 24, 0, 30, 30);
        Assert.Equal(PolicyStatus.Gap, Row(weak, "min-length").Status);
        Assert.Equal(PolicyStatus.Gap, Row(weak, "min-age").Status);
        Assert.Equal(PolicyStatus.Compliant, Row(weak, "complexity").Status);
        Assert.Equal(PolicyStatus.Compliant, Row(weak, "history").Status);
        Assert.Equal(PolicyStatus.Gap, Row(weak, "lockout-threshold").Status);
    }

    [Fact]
    public void LockoutDuration_IsNotApplicable_WhenLockoutIsOff()
    {
        var off = new DomainPasswordPolicy(14, 1, 1, 24, 0, 0, 0);
        Assert.Equal(PolicyStatus.NotApplicable, Row(off, "lockout-duration").Status);
        Assert.Equal(PolicyStatus.NotApplicable, Row(off, "lockout-window").Status);
        var on = new DomainPasswordPolicy(14, 1, 1, 24, 5, 5, 5);
        Assert.Equal(PolicyStatus.Gap, Row(on, "lockout-duration").Status);
        Assert.Equal(PolicyStatus.Compliant, Row(on, "lockout-threshold").Status);
    }

    [Fact]
    public void CompliantPolicy_HasNoGaps()
    {
        var good = new DomainPasswordPolicy(14, 1, 1, 24, 10, 15, 15);
        Assert.True(AccountPolicyEvaluator.Evaluate(HCat.Embedded().AccountPolicy, good).All(r => r.Status == PolicyStatus.Compliant));
    }

    [Fact]
    public void Complexity_ReadsBitZeroOfPwdProperties()
    {
        Assert.Equal(PolicyStatus.Gap, Row(new DomainPasswordPolicy(14, 0, 1, 24, 10, 15, 15), "complexity").Status);
        Assert.Equal(PolicyStatus.Gap, Row(new DomainPasswordPolicy(14, 8, 1, 24, 10, 15, 15), "complexity").Status);
    }

    // ---- descritor de segurança binário montado à mão (formato auto-relativo), sem APIs de ACL do Windows
    private static readonly byte[] Au = { 1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0 };
    private static readonly byte[] Da = { 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 2, 0, 0 };

    private static byte[] Ace(byte type, uint mask, byte[] sid, Guid? objectType = null)
    {
        var body = new List<byte>();
        body.AddRange(BitConverter.GetBytes(mask));
        if (type is 5 or 6)
        {
            body.AddRange(BitConverter.GetBytes(objectType is null ? 0u : 1u));
            if (objectType is not null) body.AddRange(objectType.Value.ToByteArray());
        }
        body.AddRange(sid);
        var size = (ushort)(4 + body.Count);
        return new byte[] { type, 0 }.Concat(BitConverter.GetBytes(size)).Concat(body).ToArray();
    }

    private static byte[] Sd(params byte[][] aces)
    {
        var acl = new List<byte> { 2, 0 };
        acl.AddRange(BitConverter.GetBytes((ushort)(8 + aces.Sum(a => a.Length))));
        acl.AddRange(BitConverter.GetBytes((ushort)aces.Length));
        acl.AddRange(new byte[2]);
        foreach (var a in aces) acl.AddRange(a);
        var sd = new List<byte> { 1, 0 };
        sd.AddRange(BitConverter.GetBytes((ushort)0x8004));     // self-relative + DACL present
        sd.AddRange(BitConverter.GetBytes(0u)); sd.AddRange(BitConverter.GetBytes(0u)); sd.AddRange(BitConverter.GetBytes(0u));
        sd.AddRange(BitConverter.GetBytes(20u));
        sd.AddRange(acl);
        return sd.ToArray();
    }

    [Fact]
    public void ApplyRight_ForAuthenticatedUsers_IsDetected()
    {
        var apply = GpcSecurity.ApplyGroupPolicy;
        Assert.True(GpcSecurity.AuthenticatedUsersCanApply(Sd(Ace(5, 0x100, Au, apply), Ace(0, 0x20094, Au))));
        Assert.False(GpcSecurity.AuthenticatedUsersCanApply(Sd(Ace(0, 0x20094, Au), Ace(0, 0xF01FF, Da))));                       // só leitura
        Assert.False(GpcSecurity.AuthenticatedUsersCanApply(Sd(Ace(5, 0x100, Au, new Guid("00299570-246d-11d0-a768-00aa006e0529")))));  // outro direito estendido
        Assert.False(GpcSecurity.AuthenticatedUsersCanApply(Sd(Ace(6, 0x100, Au, apply), Ace(5, 0x100, Au, apply))));              // negação vence
        Assert.True(GpcSecurity.AuthenticatedUsersCanApply(Sd(Ace(0, 0x100, Au))));                                              // controle de acesso genérico
        Assert.False(GpcSecurity.AuthenticatedUsersCanApply(Sd(Ace(5, 0x100, Da, apply))));                                      // outro SID
        Assert.Throws<InvalidDataException>(() => GpcSecurity.AuthenticatedUsersCanApply(new byte[4]));
    }
}
