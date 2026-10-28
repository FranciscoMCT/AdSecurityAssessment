using System.Text;
using ADSecurityAssessment.Hardening.Gpo;
using ADSecurityAssessment.Hardening.Planning;
using ADSecurityAssessment.Hardening.Policy;

namespace ADSecurityAssessment.Tests.Hardening;

public class PlannerTests
{
    private static HardeningPlan PlanFor(HardeningSelection sel, IEnumerable<string>? existing = null, ExistingGpoPolicy policy = ExistingGpoPolicy.Skip, bool rollback = true) =>
        HardeningPlanner.Plan(HCat.Embedded(), new PlanOptions { Selection = sel, OnExisting = policy, IncludeRollbackTwin = rollback, Now = new DateTimeOffset(2026, 10, 28, 9, 30, 0, TimeSpan.Zero) },
            "corp.test", existing ?? Array.Empty<string>(), null);

    [Fact]
    public void DefaultPlan_BuildsEveryProfile_WithoutHighRiskSettings()
    {
        var c = HCat.Embedded();
        var plan = PlanFor(HardeningSelection.Default(c));
        var mains = plan.Gpos.Where(g => g.Kind == GpoKind.Main).ToList();
        Assert.Equal(3, mains.Count);
        Assert.All(mains, g => Assert.True(g.Settings.All(s => s.Setting.Risk != "high")));
        Assert.All(mains, g => Assert.Equal(GpoPlanStatus.New, g.Status));
        Assert.Equal(3, plan.Gpos.Count(g => g.Kind == GpoKind.Rollback));
    }

    [Fact]
    public void GeneratedFiles_ParseBack_AndMatchTheSelection()
    {
        var plan = PlanFor(HardeningSelection.Default(HCat.Embedded()));
        foreach (var g in plan.Gpos)
        {
            var pol = g.Bundle.Find(GpoBundleBuilder.RegistryPolPath);
            if (pol is not null) Assert.Equal(g.Bundle.RegistryValueCount, RegistryPol.Parse(pol.Content).Count);
            var tmpl = g.Bundle.Find(GpoBundleBuilder.SecurityTemplatePath);
            if (tmpl is not null) Assert.Equal(g.Bundle.SecurityOptionCount, SecurityTemplate.ParseRegistryValues(tmpl.Content).Count);
        }
    }

    [Fact]
    public void HighRiskSettings_OnlyEnterWhenExplicitlyEnabled_AndRaiseWarnings()
    {
        var c = HCat.Embedded();
        var sel = HardeningSelection.Default(c);
        sel.SetEnabled("dc", "dc.ldap-signing-required", true);
        var dc = PlanFor(sel).Gpos.First(g => g.ProfileId == "dc" && g.Kind == GpoKind.Main);
        Assert.True(dc.Settings.Any(s => s.Setting.Id == "dc.ldap-signing-required"));
        Assert.True(dc.Warnings.Any(w => w.Contains("Alto risco") && w.Contains("2889")));
        var map = SecurityTemplate.ParseRegistryValues(dc.Bundle.Find(GpoBundleBuilder.SecurityTemplatePath)!.Content);
        Assert.Equal("4,2", map[@"MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity"]);
    }

    [Fact]
    public void Dependencies_AreAutoIncluded()
    {
        var c = HCat.Embedded();
        var sel = HardeningSelection.Default(c);
        sel.SetEnabled("dc", "audit.force-subcategory", false);
        var dc = PlanFor(sel).Gpos.First(g => g.ProfileId == "dc" && g.Kind == GpoKind.Main);
        var dep = dc.Settings.First(s => s.Setting.Id == "audit.force-subcategory");
        Assert.True(dep.AutoIncluded);
    }

    [Fact]
    public void ExistingName_IsSkipped_OrBecomesANewRevision_NeverModified()
    {
        var c = HCat.Embedded();
        var name = c.Profile("dc").GpoName;
        var skipped = PlanFor(HardeningSelection.Default(c), new[] { name.ToUpperInvariant() });
        Assert.Equal(GpoPlanStatus.Skipped, skipped.Gpos.First(g => g.ProfileId == "dc" && g.Kind == GpoKind.Main).Status);
        Assert.Equal(GpoPlanStatus.Skipped, skipped.Gpos.First(g => g.ProfileId == "dc" && g.Kind == GpoKind.Rollback).Status);

        var rev = PlanFor(HardeningSelection.Default(c), new[] { name }, ExistingGpoPolicy.NewRevision);
        var main = rev.Gpos.First(g => g.ProfileId == "dc" && g.Kind == GpoKind.Main);
        Assert.Equal(GpoPlanStatus.Revision, main.Status);
        Assert.Equal(name + " (rev 20261028-0930)", main.DisplayName);
        Assert.Equal("[ROLLBACK] " + main.DisplayName, rev.Gpos.First(g => g.ProfileId == "dc" && g.Kind == GpoKind.Rollback).DisplayName);
    }

    [Fact]
    public void RollbackTwin_RestoresPreviousValues_AndDeletesWhatDidNotExist()
    {
        var c = HCat.Embedded();
        var sel = HardeningSelection.Default(c);
        sel.SetEnabled("member", "auth.lm-compat", true);
        var rb = PlanFor(sel).Gpos.First(g => g.ProfileId == "member" && g.Kind == GpoKind.Rollback);
        var tmpl = SecurityTemplate.ParseRegistryValues(rb.Bundle.Find(GpoBundleBuilder.SecurityTemplatePath)!.Content);
        Assert.Equal("4,3", tmpl[@"MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel"]);
        var pol = RegistryPol.Parse(rb.Bundle.Find(GpoBundleBuilder.RegistryPolPath)!.Content);
        var wdigest = pol.First(p => p.Name == "UseLogonCredential");
        Assert.True(wdigest.Delete);
        var audit = Encoding.UTF8.GetString(rb.Bundle.Find(GpoBundleBuilder.AuditCsvPath)!.Content);
        Assert.Contains("No Auditing", audit);
        Assert.DoesNotContain("Success and Failure", audit);
    }

    [Fact]
    public void RollbackTwin_UsesDomainControllerSpecificRevertValues()
    {
        var c = HCat.Embedded();
        string Revert(string profile)
        {
            var rb = PlanFor(HardeningSelection.Default(c)).Gpos.First(g => g.ProfileId == profile && g.Kind == GpoKind.Rollback);
            return SecurityTemplate.ParseRegistryValues(rb.Bundle.Find(GpoBundleBuilder.SecurityTemplatePath)!.Content)[@"MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature"];
        }
        Assert.Equal("4,1", Revert("dc"));       // DC já exige assinatura SMB por padrão
        Assert.Equal("4,0", Revert("member"));
    }

    [Fact]
    public void Tattooing_IsFlaggedForNonPolicyKeys_AndSecurityOptions()
    {
        var c = HCat.Embedded();
        var plan = PlanFor(HardeningSelection.Default(c));
        var ws = plan.Gpos.First(g => g.ProfileId == "workstation" && g.Kind == GpoKind.Main);
        Assert.True(ws.Settings.First(s => s.Setting.Id == "auth.wdigest").Tattoos);
        Assert.True(ws.Settings.First(s => s.Setting.Id == "auth.no-lm-hash").Tattoos);
        Assert.False(ws.Settings.First(s => s.Setting.Id == "net.llmnr-off").Tattoos);
    }

    [Fact]
    public void NoProfileSelected_ProducesNoGpo_AndNoneEnabledWarns()
    {
        var c = HCat.Embedded();
        var sel = HardeningSelection.Default(c, new[] { "dc" });
        foreach (var s in c.ForProfile("dc")) sel.SetEnabled("dc", s.Id, false);
        var plan = PlanFor(sel);
        Assert.Empty(plan.Gpos);
        Assert.True(plan.Warnings.Count == 1);
    }

    [Fact]
    public void RollbackCanBeTurnedOff() =>
        Assert.True(PlanFor(HardeningSelection.Default(HCat.Embedded()), rollback: false).Gpos.All(g => g.Kind == GpoKind.Main));

    [Fact]
    public void DcOnlySettings_NeverLeakIntoMemberOrWorkstationGpos()
    {
        var plan = PlanFor(HardeningSelection.Default(HCat.Embedded()));
        foreach (var g in plan.Gpos.Where(g => g.ProfileId != "dc"))
        {
            Assert.False(g.Settings.Any(s => s.Setting.Id.StartsWith("dc.", StringComparison.Ordinal)));
            Assert.False(g.Settings.Any(s => s.Setting.Id.StartsWith("audit.dc.", StringComparison.Ordinal)));
        }
    }

    [Fact]
    public void PlanningIsDeterministic()
    {
        var a = PlanFor(HardeningSelection.Default(HCat.Embedded()));
        var b = PlanFor(HardeningSelection.Default(HCat.Embedded()));
        for (var i = 0; i < a.Gpos.Count; i++)
            Assert.True(a.Gpos[i].Bundle.Files.Select(f => f.Sha256).SequenceEqual(b.Gpos[i].Bundle.Files.Select(f => f.Sha256)));
    }
}
