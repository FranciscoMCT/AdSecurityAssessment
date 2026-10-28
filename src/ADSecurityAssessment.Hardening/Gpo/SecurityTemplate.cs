using System.Globalization;
using System.Text;
using ADSecurityAssessment.Hardening.Model;

namespace ADSecurityAssessment.Hardening.Gpo;

/// <summary>GptTmpl.inf (Security Settings): somente a seção [Registry Values] ("Security Options").</summary>
public static class SecurityTemplate
{
    public static byte[] Build(IEnumerable<TemplateEntry> entries)
    {
        var sb = new StringBuilder();
        sb.Append("[Unicode]\r\nUnicode=yes\r\n[Version]\r\nsignature=\"$CHICAGO$\"\r\nRevision=1\r\n[Registry Values]\r\n");
        foreach (var e in entries.GroupBy(x => x.Path, StringComparer.OrdinalIgnoreCase).Select(g => g.Last()))
            sb.Append(e.Path).Append('=').Append(Format(e)).Append("\r\n");
        // UTF-16LE com BOM, como o editor de Security Settings grava.
        return Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes(sb.ToString())).ToArray();
    }

    public static string Format(TemplateEntry e) => e.Type switch
    {
        RegType.Dword => "4," + Convert.ToUInt32(e.Data, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture),
        RegType.String => "1,\"" + ((string)e.Data).Replace("\"", "\"\"") + "\"",    // REG_SZ vai entre aspas, como nos baselines da Microsoft
        _ => "7," + string.Join(",", (string[])e.Data)
    };

    /// <summary>Leitura simples de [Registry Values] (verificação/testes).</summary>
    public static IReadOnlyDictionary<string, string> ParseRegistryValues(byte[] bytes)
    {
        var text = Encoding.Unicode.GetString(bytes).TrimStart('﻿');
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var inSection = false;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line.StartsWith('[')) { inSection = line.Equals("[Registry Values]", StringComparison.OrdinalIgnoreCase); continue; }
            if (!inSection || line.Length == 0) continue;
            var i = line.IndexOf('=');
            if (i > 0) map[line[..i]] = line[(i + 1)..];
        }
        return map;
    }
}
