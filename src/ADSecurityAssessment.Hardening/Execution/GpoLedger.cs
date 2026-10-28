using System.Text.Json;

namespace ADSecurityAssessment.Hardening.Execution;

public sealed class LedgerEntry
{
    public Guid Id { get; set; }
    public string DisplayName { get; set; } = "";
    public string DistinguishedName { get; set; } = "";
    public string SysvolPath { get; set; } = "";
    public string Profile { get; set; } = "";
    public string Kind { get; set; } = "";
    public string CatalogVersion { get; set; } = "";
    public string CreatedBy { get; set; } = "";
    public DateTimeOffset CreatedAtUtc { get; set; }
    public string Domain { get; set; } = "";
}

/// <summary>
/// Registro das GPOs criadas por esta ferramenta (arquivo JSON ao lado do executável). É a ÚNICA autorização para remover uma GPO:
/// a ferramenta nunca apaga uma GPO que não esteja neste registro.
/// </summary>
public sealed class GpoLedger
{
    private static readonly JsonSerializerOptions Opts = new() { WriteIndented = true };
    private readonly string _path;
    private readonly object _gate = new();
    private List<LedgerEntry> _entries = new();

    public GpoLedger(string path)
    {
        _path = path;
        if (File.Exists(path))
        {
            try { _entries = JsonSerializer.Deserialize<List<LedgerEntry>>(File.ReadAllText(path)) ?? new(); }
            catch (JsonException) { throw new InvalidDataException($"O registro de GPOs criadas está corrompido: {path}. Não será sobrescrito."); }
        }
    }

    public IReadOnlyList<LedgerEntry> Entries { get { lock (_gate) return _entries.ToList(); } }

    public LedgerEntry? Find(Guid id) { lock (_gate) return _entries.FirstOrDefault(e => e.Id == id); }

    public void Add(LedgerEntry entry) { lock (_gate) { _entries.Add(entry); Save(); } }

    public bool Remove(Guid id)
    {
        lock (_gate)
        {
            var n = _entries.RemoveAll(e => e.Id == id);
            if (n > 0) Save();
            return n > 0;
        }
    }

    private void Save()
    {
        var dir = Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(_entries, Opts));
        File.Move(tmp, _path, overwrite: true);
    }
}
