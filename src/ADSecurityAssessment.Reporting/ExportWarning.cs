namespace ADSecurityAssessment.Reporting;

/// <summary>Texto do aviso de privacidade exibido ANTES de qualquer exportação e repetido dentro do relatório.</summary>
public static class ExportWarning
{
    public const string Title = "Sensitive data warning";

    public const string Message =
        "This report may contain sensitive Active Directory information: account names, group memberships, domain controller names, " +
        "configuration weaknesses and attack-relevant details. Store it in a protected location, share it only with authorized people " +
        "and delete it when it is no longer needed. The tool never uploads reports or any directory data to the Internet — " +
        "all processing and exports are local.";

    public const string DemoMessage =
        "DEMO DATA — this report was generated from fictitious data and does not describe any real environment.";
}
