namespace ADSecurityAssessment.Infrastructure.Storage;

/// <summary>
/// Layout portátil: tudo fica ao lado do executável (config, rules, reports, logs, data, templates). Se a pasta do aplicativo
/// não for gravável (por exemplo, executado de um local somente leitura), as pastas de ESCRITA (reports, logs, data) passam a
/// %LOCALAPPDATA%\ADSecurityAssessment; as pastas de leitura continuam ao lado do executável. Nada é gravado no registro.
/// </summary>
public sealed class PortablePaths
{
    public string Root { get; }
    public string Config { get; }
    public string Rules { get; }
    public string Templates { get; }
    public string Reports { get; }
    public string Logs { get; }
    public string Data { get; }
    public bool UsingFallbackForWrites { get; }

    private PortablePaths(string root, string writableRoot, bool fallback)
    {
        Root = root;
        Config = Path.Combine(root, "config");
        Rules = Path.Combine(root, "rules");
        Templates = Path.Combine(root, "templates");
        Reports = Path.Combine(writableRoot, "reports");
        Logs = Path.Combine(writableRoot, "logs");
        Data = Path.Combine(writableRoot, "data");
        UsingFallbackForWrites = fallback;
    }

    public static PortablePaths Resolve(string? appDirectory = null)
    {
        var root = appDirectory
                   ?? (Environment.ProcessPath is { } p && Path.GetDirectoryName(p) is { Length: > 0 } d ? d : AppContext.BaseDirectory);
        root = Path.GetFullPath(root);

        var writable = root;
        var fallback = false;
        if (!CanWrite(root))
        {
            writable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ADSecurityAssessment");
            fallback = true;
        }
        var paths = new PortablePaths(root, writable, fallback);
        paths.EnsureWritableFolders();
        return paths;
    }

    public void EnsureWritableFolders()
    {
        foreach (var dir in new[] { Reports, Logs, Data })
        {
            try { Directory.CreateDirectory(dir); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* o log informará; o app continua */ }
        }
    }

    private static bool CanWrite(string directory)
    {
        try
        {
            Directory.CreateDirectory(directory);
            var probe = Path.Combine(directory, $".write-test-{Guid.NewGuid():N}.tmp");
            File.WriteAllText(probe, "x");
            File.Delete(probe);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }
}
