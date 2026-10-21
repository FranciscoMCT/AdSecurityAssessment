using System.Text;

namespace ADSecurityAssessment.Reporting;

internal static class ReportFiles
{
    public static readonly UTF8Encoding Utf8NoBom = new(false);
    public static readonly UTF8Encoding Utf8Bom = new(true);

    /// <summary>Grava em arquivo temporário e move: nunca deixa um relatório pela metade no destino.</summary>
    public static async Task WriteTextAtomicAsync(string path, string content, CancellationToken ct, Encoding? encoding = null)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".";
        Directory.CreateDirectory(directory);
        var temp = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await File.WriteAllTextAsync(temp, content, encoding ?? Utf8NoBom, ct).ConfigureAwait(false);
            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp)) { try { File.Delete(temp); } catch (IOException) { } }
        }
    }
}
