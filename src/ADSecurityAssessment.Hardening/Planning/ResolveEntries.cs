using ADSecurityAssessment.Hardening.Gpo;
using ADSecurityAssessment.Hardening.Model;

namespace ADSecurityAssessment.Hardening.Planning;

/// <summary>Converte as entries do catálogo (já validadas) em escritas concretas — para aplicar ou para reverter.</summary>
public static class ResolveEntries
{
    public static IEnumerable<ResolvedEntry> Apply(SettingDef setting)
    {
        foreach (var e in setting.Entries)
        {
            switch (e.Via)
            {
                case "template":
                    {
                        RegValues.TryParseType(e.Type, out var t);
                        RegValues.TryConvert(e.Value!.Value, t, out var data, out _);
                        yield return new TemplateEntry(setting.Id, e.Path!, t, data);
                        break;
                    }
                case "pol":
                    {
                        RegValues.TryParseType(e.Type, out var t);
                        RegValues.TryConvert(e.Value!.Value, t, out var data, out _);
                        yield return new PolEntry(setting.Id, e.Key!, e.Name!, t, data, false);
                        break;
                    }
                case "audit":
                    yield return new AuditEntry(setting.Id, e.Subcategory!, e.Success!.Value, e.Failure!.Value);
                    break;
            }
        }
    }

    /// <summary>Escritas que restauram o valor anterior. Entradas sem reversão conhecida são omitidas (ver <see cref="HasFullRevert"/>).</summary>
    public static IEnumerable<ResolvedEntry> Revert(SettingDef setting, string profileId)
    {
        foreach (var e in setting.Entries)
        {
            switch (e.Via)
            {
                case "template":
                    {
                        var rv = profileId == "dc" && e.RevertDc is not null ? e.RevertDc : e.Revert;
                        if (rv is null) break;
                        RegValues.TryParseType(e.Type, out var t);
                        RegValues.TryConvert(rv.Value, t, out var data, out _);
                        yield return new TemplateEntry(setting.Id, e.Path!, t, data);
                        break;
                    }
                case "pol":
                    {
                        RegValues.TryParseType(e.Type, out var t);
                        if (e.RevertDelete) { yield return new PolEntry(setting.Id, e.Key!, e.Name!, t, null, true); break; }
                        var rv = profileId == "dc" && e.RevertDc is not null ? e.RevertDc : e.Revert;
                        if (rv is null) break;
                        RegValues.TryConvert(rv.Value, t, out var data, out _);
                        yield return new PolEntry(setting.Id, e.Key!, e.Name!, t, data, false);
                        break;
                    }
                case "audit":
                    // "Sem auditoria" é o estado neutro; auditoria avançada não tem "valor anterior" legível aqui.
                    yield return new AuditEntry(setting.Id, e.Subcategory!, false, false);
                    break;
            }
        }
    }

    public static bool HasFullRevert(SettingDef setting) =>
        setting.Entries.All(e => e.Via == "audit" || e.RevertDelete || e.Revert is not null);

    /// <summary>
    /// "Tatuagem": Security Options, auditoria e valores de registro fora de ...\Policies\ permanecem na máquina depois que a GPO deixa de valer.
    /// Remover o vínculo NÃO reverte esses itens — por isso existe a GPO de reversão.
    /// </summary>
    public static bool Tattoos(SettingDef setting) =>
        setting.Entries.Any(e => e.Via != "pol" || !(e.Key ?? "").Contains(@"\Policies\", StringComparison.OrdinalIgnoreCase) && !(e.Key ?? "").StartsWith(@"Policies\", StringComparison.OrdinalIgnoreCase));
}
