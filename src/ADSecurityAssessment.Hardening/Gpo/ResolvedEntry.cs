using ADSecurityAssessment.Hardening.Model;

namespace ADSecurityAssessment.Hardening.Gpo;

/// <summary>Escrita concreta já validada e tipada, pronta para ser serializada nos arquivos da GPO.</summary>
public abstract record ResolvedEntry(string SettingId);

/// <summary>GptTmpl.inf [Registry Values]: Path inclui o prefixo MACHINE\.</summary>
public sealed record TemplateEntry(string SettingId, string Path, RegType Type, object Data) : ResolvedEntry(SettingId);

/// <summary>registry.pol (Computer). Delete=true grava "**del.Nome".</summary>
public sealed record PolEntry(string SettingId, string Key, string Name, RegType Type, object? Data, bool Delete) : ResolvedEntry(SettingId);

public sealed record AuditEntry(string SettingId, string SubcategoryKey, bool Success, bool Failure) : ResolvedEntry(SettingId);
