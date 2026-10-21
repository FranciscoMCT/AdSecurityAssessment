using System.Threading;
using System.Threading.Tasks;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;
using ADSecurityAssessment.Core.Pipeline;

namespace ADSecurityAssessment.App.Services;

/// <summary>Executa o assessment (live ou demo). A UI depende desta interface, não da infraestrutura LDAP.</summary>
public interface IAssessmentService
{
    int RuleCount { get; }
    IReadOnlyList<string> RuleLoadErrors { get; }
    Task<AssessmentResult> RunLiveAsync(ConnectionInfo connection, IProgress<AssessmentProgress> progress, CancellationToken ct);
    AssessmentResult RunDemo(IProgress<AssessmentProgress>? progress);
}

/// <summary>Marshaling para a thread de UI.</summary>
public interface IUiContext
{
    void Post(Action action);
}

public interface IDialogService
{
    /// <summary>Aviso de dados sensíveis antes da exportação. Retorna true se o usuário confirmou.</summary>
    bool ConfirmExport(string title, string message);
    void ShowInfo(string title, string message);
    void ShowError(string title, string message);
    void OpenFolder(string path);
    /// <summary>Seletor de pasta; retorna null se cancelado.</summary>
    string? PickFolder(string title, string? initialFolder);
    void OpenUrl(string url);
}

public interface IThemeService
{
    bool IsDark { get; }
    void Apply(bool dark);
}
