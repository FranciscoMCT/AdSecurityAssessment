using System.Net;
using System.Security;
using System.Text.Json.Serialization;

namespace ADSecurityAssessment.Core.Abstractions;

/// <summary>
/// Dados de conexão. A senha existe APENAS em memória como SecureString, nunca é serializada, logada ou gravada.
/// </summary>
public sealed class ConnectionInfo
{
    public bool UseCurrentCredentials { get; init; } = true;
    public string? Domain { get; init; }
    public string? DomainController { get; init; }
    public string? Username { get; init; }

    [JsonIgnore]
    public SecureString? Password { get; init; }

    public string TargetDescription =>
        UseCurrentCredentials
            ? (string.IsNullOrWhiteSpace(Domain) ? "Current domain (integrated Windows authentication)" : $"{Domain} (integrated Windows authentication)")
            : $"{Domain}{(string.IsNullOrWhiteSpace(DomainController) ? "" : " via " + DomainController)} as {Username}";

    /// <summary>Cria uma credencial de vida curta. Retorna null para autenticação integrada.</summary>
    public NetworkCredential? CreateCredential()
    {
        if (UseCurrentCredentials || string.IsNullOrWhiteSpace(Username)) return null;
        var user = Username!.Trim();
        string? domain = null;
        var slash = user.IndexOf('\\');
        if (slash > 0) { domain = user[..slash]; user = user[(slash + 1)..]; }
        var cred = new NetworkCredential(user, Password ?? new SecureString(), domain ?? string.Empty);
        return cred;
    }

    // Redigido de propósito: nunca expor a senha em logs/diagnósticos.
    public override string ToString() =>
        $"ConnectionInfo {{ Integrated={UseCurrentCredentials}, Domain={Domain}, DC={DomainController}, User={Username}, Password=<redacted> }}";
}
