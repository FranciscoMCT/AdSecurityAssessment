using ADSecurityAssessment.Hardening.Catalog;
using ADSecurityAssessment.Hardening.Execution;
using ADSecurityAssessment.Hardening.Gpo;
using ADSecurityAssessment.Hardening.Policy;

namespace ADSecurityAssessment.Tests.Hardening;

internal static class HCat
{
    public static HardeningCatalog Embedded() => HardeningCatalog.LoadEmbedded();

    /// <summary>Catálogo mínimo válido para testes de validação (modifique o texto e espere recusa).</summary>
    public const string Minimal = """
    {
      "catalogVersion": "t",
      "profiles": [ { "id": "dc", "kind": "gpo", "title": "DC", "gpoName": "G", "linkTarget": "x", "description": "d" } ],
      "settings": [
        { "id": "a.one", "category": "c", "title": "t", "scopes": ["dc"], "risk": "low", "defaultOn": true, "rationale": "r", "impact": "i",
          "references": ["https://learn.microsoft.com/x"],
          "entries": [ { "via": "pol", "key": "SOFTWARE\\Policies\\X", "name": "V", "type": "dword", "value": 1, "revertDelete": true } ] }
      ],
      "accountPolicy": []
    }
    """;
}

/// <summary>Armazenamento em memória que simula o AD/SYSVOL, para testar o executor sem domínio.</summary>
internal sealed class FakeGpoStore : IGpoStore
{
    public Dictionary<Guid, (CreatedGpo Gpo, GpoBundle Bundle)> Gpos { get; } = new();
    public List<GpoInfo> Preexisting { get; } = new();
    public Dictionary<Guid, List<GpoLink>> Links { get; } = new();
    public bool FailVerify { get; set; }
    public bool FailCreate { get; set; }
    public List<string> Deleted { get; } = new();

    public DomainContextInfo Domain { get; } = new("corp.test", "DC=corp,DC=test", "dc01.corp.test", "CN=Configuration,DC=corp,DC=test");

    public IReadOnlyList<GpoInfo> ListGpos() =>
        Preexisting.Concat(Gpos.Values.Select(v => new GpoInfo(v.Gpo.Id, v.Gpo.DisplayName, v.Gpo.DistinguishedName))).ToList();

    public IReadOnlyList<GpoLink> FindLinks(Guid id) => Links.TryGetValue(id, out var l) ? l : new List<GpoLink>();

    public CreatedGpo Create(GpoBundle bundle)
    {
        if (FailCreate) throw new IOException("falha simulada");
        var id = Guid.NewGuid();
        var c = new CreatedGpo(id, bundle.DisplayName, $"CN={{{id}}},CN=Policies,CN=System,DC=corp,DC=test", $@"\\dc01\SYSVOL\corp.test\Policies\{{{id}}}");
        Gpos[id] = (c, bundle);
        return c;
    }

    public GpoVerification Verify(GpoBundle bundle, CreatedGpo created) =>
        FailVerify ? new GpoVerification(false, new[] { "arquivo divergente" }, Array.Empty<string>()) : new GpoVerification(true, Array.Empty<string>(), new[] { "nota" });

    public void Delete(CreatedGpo gpo) { Gpos.Remove(gpo.Id); Deleted.Add(gpo.DisplayName); }

    public DomainPasswordPolicy ReadPasswordPolicy() => new(7, 1, 0, 24, 0, 30, 30);
    public IReadOnlyList<PsoInfo> ListPsos() => Array.Empty<PsoInfo>();
}
