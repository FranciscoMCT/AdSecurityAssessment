using ADSecurityAssessment.Hardening.Model;

namespace ADSecurityAssessment.Hardening.Policy;

/// <summary>Política de senha/bloqueio efetiva do domínio (Default Domain Policy), lida do objeto do domínio.</summary>
public sealed record DomainPasswordPolicy(int MinLength, int PwdProperties, int MinAgeDays, int HistoryLength, int LockoutThreshold, int LockoutDurationMinutes, int LockoutObservationMinutes);

public sealed record PsoInfo(string Name, int Precedence, int MinLength, int LockoutThreshold);

public enum PolicyStatus { Compliant, Gap, NotApplicable }

public sealed record AccountPolicyRow(string Id, string Label, string Current, string Recommended, PolicyStatus Status, string Note, string Reference);

public static class AccountPolicyEvaluator
{
    public static int Value(DomainPasswordPolicy p, string attribute) => attribute switch
    {
        "minPwdLength" => p.MinLength,
        "pwdProperties" => p.PwdProperties,
        "minPwdAgeDays" => p.MinAgeDays,
        "pwdHistoryLength" => p.HistoryLength,
        "lockoutThreshold" => p.LockoutThreshold,
        "lockoutDurationMinutes" => p.LockoutDurationMinutes,
        "lockoutObservationMinutes" => p.LockoutObservationMinutes,
        _ => throw new ArgumentException("atributo desconhecido: " + attribute)
    };

    public static List<AccountPolicyRow> Evaluate(IEnumerable<AccountPolicyDef> defs, DomainPasswordPolicy policy)
    {
        var rows = new List<AccountPolicyRow>();
        foreach (var d in defs)
        {
            var v = Value(policy, d.Attribute);
            var lockoutOff = policy.LockoutThreshold == 0;
            string current;
            string recommended;
            PolicyStatus status;

            switch (d.Comparison)
            {
                case "bit1":
                    current = (v & 1) == 1 ? "Habilitada" : "Desabilitada";
                    recommended = "Habilitada";
                    status = (v & 1) == 1 ? PolicyStatus.Compliant : PolicyStatus.Gap;
                    break;
                case "range1-10":
                    current = v == 0 ? "0 (bloqueio desligado)" : $"{v} {d.Unit}".Trim();
                    recommended = $"1 a {d.Recommended} {d.Unit}".Trim();
                    status = v >= 1 && v <= d.Recommended ? PolicyStatus.Compliant : PolicyStatus.Gap;
                    break;
                default:
                    current = $"{v} {d.Unit}".Trim();
                    recommended = $"{d.Recommended} ou mais {d.Unit}".Trim();
                    status = v >= d.Recommended ? PolicyStatus.Compliant : PolicyStatus.Gap;
                    break;
            }

            // Duração/janela de bloqueio só importam quando o bloqueio está ligado.
            if (lockoutOff && d.Attribute is "lockoutDurationMinutes" or "lockoutObservationMinutes")
                status = PolicyStatus.NotApplicable;

            rows.Add(new AccountPolicyRow(d.Id, d.Label, current, recommended, status, d.Note, d.Reference));
        }
        return rows;
    }
}
