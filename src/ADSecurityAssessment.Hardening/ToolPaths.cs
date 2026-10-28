namespace ADSecurityAssessment.Hardening;

/// <summary>Pastas de trabalho ao lado do executável (portátil). Se a pasta for somente leitura, usa %LOCALAPPDATA%.</summary>
public sealed class ToolPaths
{
    public string Root { get; }
    public string Config => Path.Combine(Root, "config");
    public string Reports => Path.Combine(Root, "reports");
    public string Logs => Path.Combine(Root, "logs");
    public string Data => Path.Combine(Root, "data");
    public string LedgerFile => Path.Combine(Data, "created-gpos.json");

    public ToolPaths(string root) { Root = root; }

    public static ToolPaths Resolve(string baseDirectory)
    {
        if (CanWrite(baseDirectory)) return Create(baseDirectory);
        var fallback = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ADSecurityHardening");
        return Create(fallback);
    }

    private static ToolPaths Create(string root)
    {
        var p = new ToolPaths(root);
        foreach (var d in new[] { p.Config, p.Reports, p.Logs, p.Data }) Directory.CreateDirectory(d);
        return p;
    }

    private static bool CanWrite(string dir)
    {
        try
        {
            Directory.CreateDirectory(dir);
            var probe = Path.Combine(dir, ".write-test-" + Guid.NewGuid().ToString("N"));
            File.WriteAllBytes(probe, Array.Empty<byte>());
            File.Delete(probe);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }
}
