using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;
using ADSecurityAssessment.Core.Pipeline;

namespace ADSecurityAssessment.Tests;

public class NormalizerTests
{
    private const string AdminDn = "CN=alice,OU=Admins,DC=corp,DC=test";

    private static AssessmentSnapshot Normalize(SnapshotBuilder b, AssessmentSettings? settings = null) =>
        SnapshotNormalizer.Normalize(b.Build(T.Now), settings ?? new AssessmentSettings(), OsLifecycleCatalog.Default, T.Now);

    private static PrivilegedMembership Member(string groupKey, string groupName, string dn, bool direct = true) =>
        new() { Domain = "corp.test", GroupKey = groupKey, GroupName = groupName, MemberName = "alice", MemberDn = dn, IsDirect = direct };

    [Fact]
    public void UserInPrivilegedGroup_IsMarkedPrivileged_WithGroupLabels()
    {
        var b = new SnapshotBuilder();
        b.Users.Add(new UserRecord { Domain = "corp.test", SamAccountName = "alice", DistinguishedName = AdminDn });
        b.Users.Add(new UserRecord { Domain = "corp.test", SamAccountName = "bob", DistinguishedName = "CN=bob,DC=corp,DC=test" });
        b.PrivilegedMemberships.Add(Member("DomainAdmins", "Domain Admins", AdminDn));
        b.PrivilegedMemberships.Add(Member("BackupOperators", "Backup Operators", AdminDn, direct: false));

        var s = Normalize(b);

        var alice = s.Users.Single(u => u.SamAccountName == "alice");
        Assert.True(alice.IsPrivileged);
        Assert.Equal(2, alice.PrivilegedGroups.Count);
        Assert.Contains("Domain Admins@corp.test", alice.PrivilegedGroups);
        Assert.False(s.Users.Single(u => u.SamAccountName == "bob").IsPrivileged);
    }

    [Fact]
    public void ProtectedUsersMembership_IsTrackedSeparately_AndDoesNotMakeAUserPrivileged()
    {
        var b = new SnapshotBuilder();
        b.Domains.Add(new DomainInfo { Name = "corp.test", ProtectedUsersGroupExists = true });
        b.Users.Add(new UserRecord { Domain = "corp.test", SamAccountName = "alice", DistinguishedName = AdminDn });
        b.PrivilegedMemberships.Add(Member("ProtectedUsers", "Protected Users", AdminDn));

        var alice = Normalize(b).Users.Single();

        Assert.True(alice.IsProtectedUsersMember);
        Assert.False(alice.IsPrivileged);
        Assert.True(alice.DomainHasProtectedUsersGroup);
    }

    [Fact]
    public void PasswordAge_AndInactivity_AreDerivedFromTheCollectionClock()
    {
        var b = new SnapshotBuilder();
        b.Users.Add(new UserRecord
        {
            Domain = "corp.test", SamAccountName = "alice", DistinguishedName = AdminDn,
            PasswordLastSet = T.Now.AddDays(-400), LastLogonTimestamp = T.Now.AddDays(-30), WhenCreated = T.Now.AddDays(-900)
        });

        var alice = Normalize(b).Users.Single();

        Assert.Equal(400, alice.PasswordAgeDays);
        Assert.Equal(30, alice.DaysSinceLastLogon);
        Assert.False(alice.IsStale);
    }

    [Theory]
    [InlineData(179, false)]
    [InlineData(180, false)]   // limiar é "mais de N dias"
    [InlineData(181, true)]
    [InlineData(400, true)]
    public void StaleThreshold_IsConfigurable_AndStrictlyGreaterThan(int daysSinceLogon, bool expectedStale)
    {
        Assert.Equal(expectedStale, SnapshotNormalizer.IsStale(T.Now.AddDays(-daysSinceLogon), null, T.Now, 180));
    }

    [Fact]
    public void AccountThatNeverLoggedOn_UsesCreationDate_ForStaleness()
    {
        Assert.True(SnapshotNormalizer.IsStale(null, T.Now.AddDays(-500), T.Now, 180));
        Assert.False(SnapshotNormalizer.IsStale(null, T.Now.AddDays(-10), T.Now, 180));
        Assert.False(SnapshotNormalizer.IsStale(null, null, T.Now, 180));   // sem nenhuma data: não afirmar nada
    }

    [Fact]
    public void MissingTimestamps_RemainNull_NotZero()
    {
        var b = new SnapshotBuilder();
        b.Users.Add(new UserRecord { Domain = "corp.test", SamAccountName = "alice", DistinguishedName = AdminDn });

        var alice = Normalize(b).Users.Single();

        Assert.Null(alice.PasswordAgeDays);
        Assert.Null(alice.DaysSinceLastLogon);
    }

    [Fact]
    public void Normalization_DoesNotCreateOrDropObjects()
    {
        var b = new SnapshotBuilder();
        for (var i = 0; i < 25; i++) b.Users.Add(new UserRecord { Domain = "corp.test", SamAccountName = "u" + i, DistinguishedName = $"CN=u{i},DC=corp,DC=test" });

        var s = Normalize(b);

        Assert.Equal(25, s.Users.Count);
    }

    [Fact]
    public void UserAccountControl_Flags_AreDecodedCorrectly()
    {
        var u = new UserRecord
        {
            Domain = "corp.test", SamAccountName = "x",
            UserAccountControl = 0x200 | 0x10000 | 0x20 | 0x400000 | 0x80000   // NORMAL + DONT_EXPIRE + PASSWD_NOTREQD + DONT_REQ_PREAUTH + TRUSTED_FOR_DELEGATION
        };

        Assert.True(u.Enabled);
        Assert.True(u.PasswordNeverExpires);
        Assert.True(u.PasswordNotRequired);
        Assert.True(u.DoesNotRequirePreAuth);
        Assert.True(u.TrustedForDelegation);
        Assert.False(u.ReversibleEncryption);
        Assert.False(new UserRecord { Domain = "d", SamAccountName = "y", UserAccountControl = 0x202 }.Enabled);
    }
}
