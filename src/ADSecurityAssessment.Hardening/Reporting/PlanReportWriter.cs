using System.Net;
using System.Text;
using System.Text.Json;
using ADSecurityAssessment.Hardening.Execution;
using ADSecurityAssessment.Hardening.Planning;
using ADSecurityAssessment.Hardening.Policy;

namespace ADSecurityAssessment.Hardening.Reporting;

/// <summary>Relatório do plano (e, se houver, do resultado da criação) em HTML autônomo e JSON. Sem recursos externos.</summary>
public static class PlanReportWriter
{
    private static string H(string? s) => WebUtility.HtmlEncode(s ?? "");

    private static string RiskLabel(string risk) => risk switch { "high" => "Alto", "medium" => "Médio", _ => "Baixo" };

    public static string ToHtml(HardeningPlan plan, ApplyResult? applied = null, IReadOnlyList<PsoInfo>? psos = null)
    {
        var sb = new StringBuilder();
        sb.Append("<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
        sb.Append("<title>Plano de hardening - ").Append(H(plan.DomainName)).Append("</title><style>");
        sb.Append(":root{--bg:#fff;--fg:#1b1f24;--mut:#59636e;--line:#d0d7de;--card:#f6f8fa;--ok:#1a7f37;--warn:#9a6700;--bad:#cf222e}");
        sb.Append("@media(prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--mut:#9198a1;--line:#30363d;--card:#161b22;--ok:#3fb950;--warn:#d29922;--bad:#f85149}}");
        sb.Append("body{font:14px/1.5 system-ui,Segoe UI,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:24px;max-width:1100px;margin-inline:auto}");
        sb.Append("h1{font-size:22px}h2{font-size:18px;margin-top:32px;border-bottom:1px solid var(--line);padding-bottom:6px}h3{font-size:15px;margin:20px 0 6px}");
        sb.Append("table{border-collapse:collapse;width:100%;margin:8px 0}th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}th{background:var(--card)}");
        sb.Append(".card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:12px 0}.mut{color:var(--mut)}");
        sb.Append(".ok{color:var(--ok);font-weight:600}.warn{color:var(--warn);font-weight:600}.bad{color:var(--bad);font-weight:600}code{font-family:Consolas,monospace}");
        sb.Append("</style></head><body>");

        sb.Append("<h1>Plano de hardening do Active Directory</h1>");
        sb.Append("<p class=\"mut\">Domínio <b>").Append(H(plan.DomainName)).Append("</b> · gerado em ").Append(plan.CreatedAt.ToString("yyyy-MM-dd HH:mm")).Append(" · catálogo ").Append(H(plan.CatalogVersion)).Append("</p>");
        sb.Append("<div class=\"card\"><b>Como ler:</b> as GPOs deste plano são criadas <b>sem vínculo</b>, portanto não afetam nenhum computador até que você as vincule a uma OU piloto. ");
        sb.Append("Valores de <i>Security Options</i>, auditoria e chaves fora de <code>...\\Policies\\</code> ficam gravados nas máquinas mesmo depois de desvincular a GPO (\"tatuagem\"): para reverter use a GPO <code>[ROLLBACK]</code> correspondente (ela grava os valores padrão do Windows assumidos no catálogo, não o valor anterior de cada máquina). ");
        sb.Append("Itens de alto risco só entram se você os marcou e têm pré-requisitos listados.</div>");

        if (plan.Warnings.Count > 0)
        {
            sb.Append("<div class=\"card\"><b class=\"warn\">Avisos</b><ul>");
            foreach (var w in plan.Warnings) sb.Append("<li>").Append(H(w)).Append("</li>");
            sb.Append("</ul></div>");
        }

        if (applied is not null)
        {
            sb.Append("<h2>Resultado da criação</h2><table><tr><th>GPO</th><th>Resultado</th><th>Detalhe</th><th>GUID</th></tr>");
            foreach (var r in applied.Results)
            {
                var cls = r.Outcome == GpoOutcome.Created ? "ok" : r.Outcome == GpoOutcome.Failed ? "bad" : "warn";
                var label = r.Outcome == GpoOutcome.Created ? "Criada (sem vínculo)" : r.Outcome == GpoOutcome.Failed ? "Falhou" : "Ignorada";
                sb.Append("<tr><td>").Append(H(r.DisplayName)).Append("</td><td class=\"").Append(cls).Append("\">").Append(label).Append("</td><td>").Append(H(r.Message));
                foreach (var n in r.Notes) sb.Append("<br><span class=\"warn\">").Append(H(n)).Append("</span>");
                sb.Append("</td><td><code>").Append(r.Id is null ? "" : "{" + r.Id.Value.ToString().ToUpperInvariant() + "}").Append("</code></td></tr>");
            }
            sb.Append("</table>");
        }

        foreach (var g in plan.Gpos)
        {
            sb.Append("<h2>").Append(g.Kind == GpoKind.Rollback ? "Reversão: " : "").Append(H(g.ProfileTitle)).Append(" — ").Append(H(g.DisplayName)).Append("</h2>");
            var statusCls = g.Status == GpoPlanStatus.Skipped ? "warn" : "ok";
            var statusText = g.Status switch { GpoPlanStatus.New => "Será criada", GpoPlanStatus.Revision => "Será criada como nova revisão", _ => "Ignorada" };
            sb.Append("<p><span class=\"").Append(statusCls).Append("\">").Append(statusText).Append("</span> · onde vincular (depois, por você): <b>").Append(H(g.LinkTarget)).Append("</b>");
            sb.Append(" · ").Append(g.Bundle.RegistryValueCount).Append(" valores de registro, ").Append(g.Bundle.SecurityOptionCount).Append(" Security Options, ").Append(g.Bundle.AuditSubcategoryCount).Append(" subcategorias de auditoria</p>");
            if (!string.IsNullOrEmpty(g.Reason)) sb.Append("<p class=\"mut\">").Append(H(g.Reason)).Append("</p>");
            foreach (var w in g.Warnings) sb.Append("<p class=\"warn\">⚠ ").Append(H(w)).Append("</p>");
            if (g.NoAutomaticRevert.Count > 0)
                sb.Append("<p class=\"mut\">Sem reversão automática na GPO [ROLLBACK] (volte ao valor anterior manualmente): ").Append(H(string.Join("; ", g.NoAutomaticRevert))).Append("</p>");

            if (g.Kind == GpoKind.Main && g.Status != GpoPlanStatus.Skipped)
            {
                sb.Append("<table><tr><th>Configuração</th><th>Risco</th><th>Tatua?</th><th>Por quê</th><th>Impacto / cuidados</th><th>Referência</th></tr>");
                foreach (var ps in g.Settings)
                {
                    var s = ps.Setting;
                    var riskCls = s.Risk == "high" ? "bad" : s.Risk == "medium" ? "warn" : "ok";
                    sb.Append("<tr><td><b>").Append(H(s.Title)).Append("</b><br><code>").Append(H(s.Id)).Append("</code>").Append(ps.AutoIncluded ? "<br><span class=\"mut\">(incluída por dependência)</span>" : "").Append("</td>");
                    sb.Append("<td class=\"").Append(riskCls).Append("\">").Append(RiskLabel(s.Risk)).Append("</td><td>").Append(ps.Tattoos ? "Sim" : "Não").Append("</td>");
                    sb.Append("<td>").Append(H(s.Rationale)).Append("</td><td>").Append(H(s.Impact));
                    if (!string.IsNullOrWhiteSpace(s.Prerequisite)) sb.Append("<br><b>Pré-requisito:</b> ").Append(H(s.Prerequisite));
                    sb.Append("</td><td>");
                    foreach (var r in s.References) sb.Append("<a href=\"").Append(H(r)).Append("\">Microsoft Learn</a><br>");
                    sb.Append("</td></tr>");
                }
                sb.Append("</table>");
            }
        }

        if (plan.AccountPolicy.Count > 0)
        {
            sb.Append("<h2>Senha e bloqueio de conta do domínio</h2>");
            sb.Append("<p class=\"mut\">Esta política só vale pela <b>Default Domain Policy</b> ou por um <b>PSO</b> (Fine-Grained Password Policy). Uma GPO em OU não a altera para contas de domínio. Esta ferramenta <b>não altera</b> a Default Domain Policy: use a tabela abaixo para editá-la no GPMC ou crie um PSO.</p>");
            sb.Append("<table><tr><th>Item</th><th>Atual</th><th>Referência</th><th>Situação</th><th>Observação</th></tr>");
            foreach (var r in plan.AccountPolicy)
            {
                var cls = r.Status == PolicyStatus.Compliant ? "ok" : r.Status == PolicyStatus.Gap ? "bad" : "mut";
                var text = r.Status == PolicyStatus.Compliant ? "Conforme" : r.Status == PolicyStatus.Gap ? "Lacuna" : "Não se aplica";
                sb.Append("<tr><td>").Append(H(r.Label)).Append("</td><td>").Append(H(r.Current)).Append("</td><td>").Append(H(r.Recommended)).Append("</td><td class=\"").Append(cls).Append("\">").Append(text)
                  .Append("</td><td>").Append(H(r.Note)).Append(" <a href=\"").Append(H(r.Reference)).Append("\">Learn</a></td></tr>");
            }
            sb.Append("</table>");
            if (psos is { Count: > 0 })
            {
                sb.Append("<p>PSOs existentes (têm precedência sobre a Default Domain Policy para os alvos deles): ");
                sb.Append(H(string.Join("; ", psos.Select(p => $"{p.Name} (precedência {p.Precedence}, mínimo {p.MinLength}, bloqueio {p.LockoutThreshold})")))).Append("</p>");
            }
        }

        sb.Append("<h2>Próximos passos (manuais, por você)</h2><ol>");
        sb.Append("<li>Crie uma OU piloto com poucos computadores representativos (e um DC de teste, se houver) e vincule a GPO correspondente <b>somente a ela</b>.</li>");
        sb.Append("<li>Execute <code>gpupdate /force</code> nos pilotos, confira com <code>gpresult /h</code> e observe os logs (NTLM/Operational, Directory Service 2889, SMB) por alguns dias.</li>");
        sb.Append("<li>Amplie por ondas. Itens de alto risco só depois de analisar a auditoria correspondente.</li>");
        sb.Append("<li>Para reverter: vincule a GPO <code>[ROLLBACK]</code> ao mesmo alvo com precedência maior; remover só o vínculo da principal não desfaz Security Options nem auditoria.</li></ol>");
        sb.Append("<p class=\"mut\">Este relatório pode conter nomes de objetos do seu ambiente; trate-o como confidencial.</p></body></html>");
        return sb.ToString();
    }

    public static string ToJson(HardeningPlan plan, ApplyResult? applied = null)
    {
        var dto = new
        {
            tool = "ADSecurityAssessment.Hardening",
            catalogVersion = plan.CatalogVersion,
            domain = plan.DomainName,
            createdAt = plan.CreatedAt,
            warnings = plan.Warnings,
            gpos = plan.Gpos.Select(g => new
            {
                profile = g.ProfileId, kind = g.Kind.ToString(), name = g.DisplayName, status = g.Status.ToString(), reason = g.Reason,
                linkTarget = g.LinkTarget, warnings = g.Warnings, noAutomaticRevert = g.NoAutomaticRevert,
                counts = new { registry = g.Bundle.RegistryValueCount, securityOptions = g.Bundle.SecurityOptionCount, audit = g.Bundle.AuditSubcategoryCount },
                settings = g.Settings.Select(s => new { id = s.Setting.Id, title = s.Setting.Title, risk = s.Setting.Risk, tattoos = s.Tattoos, autoIncluded = s.AutoIncluded })
            }),
            accountPolicy = plan.AccountPolicy.Select(r => new { id = r.Id, label = r.Label, current = r.Current, recommended = r.Recommended, status = r.Status.ToString() }),
            applied = applied?.Results.Select(r => new { name = r.DisplayName, outcome = r.Outcome.ToString(), message = r.Message, id = r.Id })
        };
        return JsonSerializer.Serialize(dto, new JsonSerializerOptions { WriteIndented = true });
    }
}
