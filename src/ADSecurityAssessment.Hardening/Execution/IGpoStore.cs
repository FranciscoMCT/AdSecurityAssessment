using ADSecurityAssessment.Hardening.Gpo;
using ADSecurityAssessment.Hardening.Policy;

namespace ADSecurityAssessment.Hardening.Execution;

public sealed record DomainContextInfo(string DnsName, string DistinguishedName, string Server, string ConfigurationDn);
public sealed record GpoInfo(Guid Id, string DisplayName, string DistinguishedName);
public sealed record GpoLink(string ContainerDn, bool Enabled, bool Enforced);
public sealed record CreatedGpo(Guid Id, string DisplayName, string DistinguishedName, string SysvolPath);
public sealed record GpoVerification(bool Ok, IReadOnlyList<string> Issues, IReadOnlyList<string> Notes);

/// <summary>
/// Fronteira com o AD/SYSVOL. Propositalmente NÃO tem operação de vínculo (gPLink), nem de edição de GPO existente:
/// a ferramenta só cria GPOs novas (desvinculadas) e remove as que ela mesma criou. Vincular é decisão do administrador.
/// </summary>
public interface IGpoStore
{
    DomainContextInfo Domain { get; }
    IReadOnlyList<GpoInfo> ListGpos();
    IReadOnlyList<GpoLink> FindLinks(Guid id);
    CreatedGpo Create(GpoBundle bundle);
    GpoVerification Verify(GpoBundle bundle, CreatedGpo created);
    /// <summary>Remove o GPC e a pasta do SYSVOL de uma GPO. O chamador (executor) já garantiu que ela é da ferramenta e não está vinculada.</summary>
    void Delete(CreatedGpo gpo);
    DomainPasswordPolicy ReadPasswordPolicy();
    IReadOnlyList<PsoInfo> ListPsos();
}

public interface IHardeningLog
{
    void Info(string message);
    void Warn(string message);
    void Error(string message);
}

public sealed class NullHardeningLog : IHardeningLog
{
    public static readonly NullHardeningLog Instance = new();
    public void Info(string message) { }
    public void Warn(string message) { }
    public void Error(string message) { }
}

/// <summary>Log em memória + arquivo opcional. Nunca recebe segredos (a ferramenta não manipula senhas).</summary>
public sealed class HardeningLog : IHardeningLog
{
    private readonly string? _file;
    private readonly object _gate = new();
    public event Action<string>? LineAdded;
    public List<string> Lines { get; } = new();

    public HardeningLog(string? file = null) { _file = file; }

    public void Info(string message) => Write("INFO ", message);
    public void Warn(string message) => Write("WARN ", message);
    public void Error(string message) => Write("ERROR", message);

    private void Write(string level, string message)
    {
        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {level} {message}";
        lock (_gate)
        {
            Lines.Add(line);
            if (_file is not null)
            {
                try { File.AppendAllText(_file, line + Environment.NewLine); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
        LineAdded?.Invoke(line);
    }
}
