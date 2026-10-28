using System.Text;
using ADSecurityAssessment.Hardening.Gpo;
using ADSecurityAssessment.Hardening.Model;

namespace ADSecurityAssessment.Tests.Hardening;

public class GpoFileFormatTests
{
    [Fact]
    public void RegistryPol_SingleDword_MatchesTheDocumentedBytes()
    {
        var bytes = RegistryPol.Build(new[] { new PolEntry("x", "A", "B", RegType.Dword, 1u, false) });
        var expected = new List<byte> { 0x50, 0x52, 0x65, 0x67, 1, 0, 0, 0 };
        void U(string s) { expected.AddRange(Encoding.Unicode.GetBytes(s)); }
        U("["); U("A\0"); U(";"); U("B\0"); U(";");
        expected.AddRange(new byte[] { 4, 0, 0, 0 }); U(";");
        expected.AddRange(new byte[] { 4, 0, 0, 0 }); U(";");
        expected.AddRange(new byte[] { 1, 0, 0, 0 }); U("]");
        Assert.True(bytes.SequenceEqual(expected));
    }

    [Fact]
    public void RegistryPol_RoundTrips_AllTypesAndDeletes()
    {
        var input = new[]
        {
            new PolEntry("a", @"SOFTWARE\Policies\X", "D", RegType.Dword, 4294967295u, false),
            new PolEntry("a", @"SOFTWARE\Policies\X", "S", RegType.String, "texto ç", false),
            new PolEntry("a", @"SYSTEM\Y", "M", RegType.MultiString, new[] { "Bowser", "MRxSmb20", "NSI" }, false),
            new PolEntry("a", @"SYSTEM\Y", "Gone", RegType.Dword, null, true),
        };
        var parsed = RegistryPol.Parse(RegistryPol.Build(input));
        Assert.Equal(4, parsed.Count);
        Assert.Equal(4294967295u, (uint)parsed[0].Data!);
        Assert.Equal("texto ç", (string)parsed[1].Data!);
        Assert.True(((string[])parsed[2].Data!).SequenceEqual(new[] { "Bowser", "MRxSmb20", "NSI" }));
        Assert.True(parsed[3].Delete);
        Assert.Equal("Gone", parsed[3].Name);
    }

    [Fact]
    public void RegistryPol_RejectsGarbage()
    {
        Assert.Throws<InvalidDataException>(() => RegistryPol.Parse(new byte[] { 1, 2, 3 }));
        var bytes = RegistryPol.Build(new[] { new PolEntry("a", "K", "N", RegType.Dword, 1u, false) });
        bytes[bytes.Length - 2] = (byte)'X';
        Assert.Throws<InvalidDataException>(() => RegistryPol.Parse(bytes));
    }

    [Fact]
    public void SecurityTemplate_IsUtf16WithBom_AndHasTheRegistryValuesSection()
    {
        var bytes = SecurityTemplate.Build(new[]
        {
            new TemplateEntry("a", @"MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel", RegType.Dword, 5u),
            new TemplateEntry("a", @"MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM", RegType.String, "O:BAG:BAD:(A;;RC;;;BA)")
        });
        Assert.Equal(0xFF, bytes[0]); Assert.Equal(0xFE, bytes[1]);
        var text = Encoding.Unicode.GetString(bytes);
        Assert.Contains("[Registry Values]", text);
        var map = SecurityTemplate.ParseRegistryValues(bytes);
        Assert.Equal("4,5", map[@"MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel"]);
        Assert.Equal("1,\"O:BAG:BAD:(A;;RC;;;BA)\"", map[@"MACHINE\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM"]);
    }

    [Fact]
    public void AuditCsv_HasTheSevenColumnHeader_AndCorrectSettingValues()
    {
        var csv = Encoding.UTF8.GetString(AuditPolicy.BuildCsv(new[]
        {
            new AuditEntry("a", "Logon", true, true), new AuditEntry("a", "Logoff", true, false), new AuditEntry("a", "AccountLockout", false, true), new AuditEntry("a", "SystemIntegrity", false, false)
        }));
        var lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal("Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value", lines[0]);
        Assert.Contains(",System,Audit Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3", lines);
        Assert.Contains(",System,Audit Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},Success,,1", lines);
        Assert.Contains(",System,Audit Account Lockout,{0CCE9217-69AE-11D9-BED3-505054503030},Failure,,2", lines);
        Assert.Contains(",System,Audit System Integrity,{0CCE9212-69AE-11D9-BED3-505054503030},No Auditing,,0", lines);
    }

    [Fact]
    public void Bundle_HasSortedExtensionPairs_VersionAndGptIni()
    {
        var b = GpoBundleBuilder.Build("G", new ResolvedEntry[]
        {
            new AuditEntry("a", "Logon", true, true),
            new TemplateEntry("t", @"MACHINE\X\Y", RegType.Dword, 1u),
            new PolEntry("p", @"SOFTWARE\Policies\Z", "N", RegType.Dword, 1u, false)
        });
        Assert.Equal(GpoBundleBuilder.RegistryCse + GpoBundleBuilder.SecurityCse + GpoBundleBuilder.AuditCse, b.MachineExtensionNames);
        Assert.Equal(1, b.VersionNumber);
        Assert.Equal("[General]\r\nVersion=1\r\n", Encoding.ASCII.GetString(b.Find("GPT.INI")!.Content));
        Assert.NotNull(b.Find(GpoBundleBuilder.RegistryPolPath));
        Assert.NotNull(b.Find(GpoBundleBuilder.SecurityTemplatePath));
        Assert.NotNull(b.Find(GpoBundleBuilder.AuditCsvPath));
        Assert.Equal(new[] { "Machine", "User" }, b.Folders.ToArray());
    }

    [Fact]
    public void Bundle_OnlyIncludesTheCsesItNeeds()
    {
        var b = GpoBundleBuilder.Build("G", new ResolvedEntry[] { new PolEntry("p", "K", "N", RegType.Dword, 1u, false) });
        Assert.Equal(GpoBundleBuilder.RegistryCse, b.MachineExtensionNames);
        Assert.Null(b.Find(GpoBundleBuilder.AuditCsvPath));
        Assert.Throws<InvalidOperationException>(() => GpoBundleBuilder.Build("G", Array.Empty<ResolvedEntry>()));
    }
}
