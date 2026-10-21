namespace ADSecurityAssessment.Core.Abstractions;

public enum LogLevel { Debug, Info, Warn, Error }

public interface IAssessmentLog
{
    void Debug(string message);
    void Info(string message);
    void Warn(string message);
    void Error(string message, Exception? exception = null);
}

public sealed class NullAssessmentLog : IAssessmentLog
{
    public static readonly NullAssessmentLog Instance = new();
    public void Debug(string message) { }
    public void Info(string message) { }
    public void Warn(string message) { }
    public void Error(string message, Exception? exception = null) { }
}

/// <summary>Envia o log para vários destinos (arquivo + UI) e mantém um buffer circular em memória.</summary>
public sealed class CompositeLog : IAssessmentLog
{
    private readonly IAssessmentLog[] _targets;
    private readonly Queue<string> _buffer = new();
    private readonly object _gate = new();
    private readonly int _capacity;

    public event Action<string>? LineWritten;

    public CompositeLog(int bufferCapacity = 2000, params IAssessmentLog[] targets)
    {
        _capacity = bufferCapacity;
        _targets = targets;
    }

    public IReadOnlyList<string> Snapshot() { lock (_gate) return _buffer.ToArray(); }

    private void Write(LogLevel level, string message, Exception? ex)
    {
        var line = $"{DateTime.Now:HH:mm:ss} [{level.ToString().ToUpperInvariant(),-5}] {message}" + (ex is null ? "" : $" :: {ex.GetType().Name}: {ex.Message}");
        lock (_gate)
        {
            _buffer.Enqueue(line);
            while (_buffer.Count > _capacity) _buffer.Dequeue();
        }
        try { LineWritten?.Invoke(line); } catch { /* UI nunca derruba a coleta */ }
    }

    public void Debug(string message) { Write(LogLevel.Debug, message, null); foreach (var t in _targets) t.Debug(message); }
    public void Info(string message) { Write(LogLevel.Info, message, null); foreach (var t in _targets) t.Info(message); }
    public void Warn(string message) { Write(LogLevel.Warn, message, null); foreach (var t in _targets) t.Warn(message); }
    public void Error(string message, Exception? exception = null) { Write(LogLevel.Error, message, exception); foreach (var t in _targets) t.Error(message, exception); }
}
