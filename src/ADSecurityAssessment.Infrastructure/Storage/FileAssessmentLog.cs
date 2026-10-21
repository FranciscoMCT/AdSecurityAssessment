using System.Text.RegularExpressions;
using ADSecurityAssessment.Core.Abstractions;

namespace ADSecurityAssessment.Infrastructure.Storage;

/// <summary>Log em arquivo (logs/assessment-AAAAMMDD.log) com redação defensiva de segredos. Nunca lança exceção para quem loga.</summary>
public sealed class FileAssessmentLog : IAssessmentLog
{
    private const long MaxFileBytes = 10 * 1024 * 1024;
    private static readonly Regex Secret = new(@"(?i)\b(password|passwd|pwd|secret|token)\b\s*[=:]\s*\S+", RegexOptions.Compiled);
    private readonly object _gate = new();
    private readonly string _directory;
    private readonly LogLevel _minimum;

    public FileAssessmentLog(string directory, LogLevel minimum = LogLevel.Info)
    {
        _directory = directory;
        _minimum = minimum;
    }

    public string CurrentFile => Path.Combine(_directory, $"assessment-{DateTime.Now:yyyyMMdd}.log");

    public void Debug(string message) => Write(LogLevel.Debug, message, null);
    public void Info(string message) => Write(LogLevel.Info, message, null);
    public void Warn(string message) => Write(LogLevel.Warn, message, null);
    public void Error(string message, Exception? exception = null) => Write(LogLevel.Error, message, exception);

    public static string Redact(string text) => Secret.Replace(text, m => m.Groups[1].Value + "=<redacted>");

    private void Write(LogLevel level, string message, Exception? ex)
    {
        if (level < _minimum) return;
        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{level.ToString().ToUpperInvariant(),-5}] {Redact(message)}" +
                   (ex is null ? "" : $" :: {ex.GetType().Name}: {Redact(ex.Message)}");
        try
        {
            lock (_gate)
            {
                Directory.CreateDirectory(_directory);
                var file = CurrentFile;
                if (File.Exists(file) && new FileInfo(file).Length > MaxFileBytes)
                    File.Move(file, Path.ChangeExtension(file, $".{DateTime.Now:HHmmss}.log"), overwrite: true);
                File.AppendAllText(file, line + Environment.NewLine);
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { /* log é best-effort */ }
    }
}
