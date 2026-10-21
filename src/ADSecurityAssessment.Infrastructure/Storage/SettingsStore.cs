using System.Text.Json;
using System.Text.Json.Serialization;
using ADSecurityAssessment.Core.Abstractions;
using ADSecurityAssessment.Core.Model;

namespace ADSecurityAssessment.Infrastructure.Storage;

/// <summary>Carrega config/settings.json e config/scoring.json. Arquivo ausente → padrões; arquivo inválido → padrões + aviso (nunca derruba o app).</summary>
public static class SettingsStore
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    public static AssessmentSettings Load(string configDirectory, IAssessmentLog? log = null)
    {
        log ??= NullAssessmentLog.Instance;
        var settings = new AssessmentSettings();

        var settingsFile = Path.Combine(configDirectory, "settings.json");
        if (File.Exists(settingsFile))
        {
            try
            {
                settings = JsonSerializer.Deserialize<AssessmentSettings>(File.ReadAllText(settingsFile), Options) ?? new AssessmentSettings();
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
            {
                log.Warn($"settings.json is invalid or unreadable ({ex.Message}); using defaults.");
                settings = new AssessmentSettings();
            }
        }

        var scoringFile = Path.Combine(configDirectory, "scoring.json");
        if (File.Exists(scoringFile))
        {
            try
            {
                settings.Scoring = JsonSerializer.Deserialize<ScoringSettings>(File.ReadAllText(scoringFile), Options) ?? settings.Scoring;
            }
            catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
            {
                log.Warn($"scoring.json is invalid or unreadable ({ex.Message}); using default scoring.");
            }
        }
        return Sanitize(settings);
    }

    /// <summary>Garante limites sensatos, para que uma configuração errada não gere comportamento inseguro ou travado.</summary>
    public static AssessmentSettings Sanitize(AssessmentSettings s)
    {
        s.LdapPageSize = Math.Clamp(s.LdapPageSize, 50, 5000);
        s.QueryTimeoutSeconds = Math.Clamp(s.QueryTimeoutSeconds, 5, 600);
        s.CollectorTimeoutSeconds = Math.Clamp(s.CollectorTimeoutSeconds, 30, 7200);
        s.MaxObjectsPerQuery = Math.Clamp(s.MaxObjectsPerQuery, 1000, 5_000_000);
        s.DnsResolutionTimeoutSeconds = Math.Clamp(s.DnsResolutionTimeoutSeconds, 1, 60);
        s.MaxGpoFilesToScan = Math.Clamp(s.MaxGpoFilesToScan, 100, 200_000);
        s.StaleAccountDays = Math.Clamp(s.StaleAccountDays, 30, 3650);
        s.KrbtgtMaxPasswordAgeDays = Math.Clamp(s.KrbtgtMaxPasswordAgeDays, 30, 3650);
        s.MinPasswordLength = Math.Clamp(s.MinPasswordLength, 1, 128);
        s.MinLockoutDurationMinutes = Math.Clamp(s.MinLockoutDurationMinutes, 1, 99999);
        s.MaxClockSkewMinutes = Math.Clamp(s.MaxClockSkewMinutes, 1, 60);
        s.SeamlessSsoKeyRollDays = Math.Clamp(s.SeamlessSsoKeyRollDays, 1, 365);
        s.MaxAffectedObjectsPerFinding = Math.Clamp(s.MaxAffectedObjectsPerFinding, 10, 100_000);
        return s;
    }

    /// <summary>Grava os padrões em config/ (somente se ainda não existirem) para que o usuário possa editá-los.</summary>
    public static void WriteDefaultsIfMissing(string configDirectory, IAssessmentLog? log = null)
    {
        try
        {
            Directory.CreateDirectory(configDirectory);
            var defaults = new AssessmentSettings();
            var settingsFile = Path.Combine(configDirectory, "settings.json");
            if (!File.Exists(settingsFile))
            {
                var copy = JsonSerializer.Deserialize<AssessmentSettings>(JsonSerializer.Serialize(defaults, Options), Options)!;
                copy.Scoring = new ScoringSettings();
                File.WriteAllText(settingsFile, JsonSerializer.Serialize(new SettingsFile(copy), Options));
            }
            var scoringFile = Path.Combine(configDirectory, "scoring.json");
            if (!File.Exists(scoringFile)) File.WriteAllText(scoringFile, JsonSerializer.Serialize(new ScoringSettings(), Options));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            log?.Warn($"Could not write the default configuration files: {ex.Message}");
        }
    }

    // settings.json não repete o bloco de scoring (fica em scoring.json).
    private sealed class SettingsFile
    {
        public SettingsFile(AssessmentSettings s)
        {
            LdapPageSize = s.LdapPageSize; QueryTimeoutSeconds = s.QueryTimeoutSeconds; CollectorTimeoutSeconds = s.CollectorTimeoutSeconds;
            MaxObjectsPerQuery = s.MaxObjectsPerQuery; DnsResolutionTimeoutSeconds = s.DnsResolutionTimeoutSeconds;
            ScanSysvolForGppPasswords = s.ScanSysvolForGppPasswords; MaxGpoFilesToScan = s.MaxGpoFilesToScan;
            StaleAccountDays = s.StaleAccountDays; KrbtgtMaxPasswordAgeDays = s.KrbtgtMaxPasswordAgeDays;
            MinPasswordLength = s.MinPasswordLength; MinLockoutDurationMinutes = s.MinLockoutDurationMinutes;
            MaxClockSkewMinutes = s.MaxClockSkewMinutes; SeamlessSsoKeyRollDays = s.SeamlessSsoKeyRollDays;
            MaxAffectedObjectsPerFinding = s.MaxAffectedObjectsPerFinding;
        }
        public int LdapPageSize { get; }
        public int QueryTimeoutSeconds { get; }
        public int CollectorTimeoutSeconds { get; }
        public int MaxObjectsPerQuery { get; }
        public int DnsResolutionTimeoutSeconds { get; }
        public bool ScanSysvolForGppPasswords { get; }
        public int MaxGpoFilesToScan { get; }
        public int StaleAccountDays { get; }
        public int KrbtgtMaxPasswordAgeDays { get; }
        public int MinPasswordLength { get; }
        public int MinLockoutDurationMinutes { get; }
        public int MaxClockSkewMinutes { get; }
        public int SeamlessSsoKeyRollDays { get; }
        public int MaxAffectedObjectsPerFinding { get; }
    }
}
