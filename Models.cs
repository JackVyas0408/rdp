namespace V3Guard;

public enum Stage
{
    None = 0,
    S1 = 1,
    S2 = 2,
    S3 = 3,
    Permanent = 4,
}

/// <summary>Why a logon attempt was rejected, drives which threshold applies.</summary>
public enum FailureKind
{
    /// <summary>Account exists and is enabled - a real brute-force attempt.</summary>
    Real = 0,
    /// <summary>Account does not exist - username enumeration.</summary>
    NonReal = 1,
    /// <summary>Account exists but is disabled.</summary>
    Disabled = 2,
}

public enum NoticeKind
{
    Block = 0,
    StartupActive = 1,
    ProtectionLost = 2,
    ProtectionRestored = 3,
    Tamper = 4,
    Whitelisted = 5,
    Released = 6,
}

public sealed record AuthEvent(
    string Timestamp,
    string Ip,
    string User,
    string SubStatus,
    FailureKind Kind,
    bool Real,
    bool Blocked);

/// <summary>
/// One observed logon attempt, kept for the dashboard feed. Persisted so the
/// feed is not empty after a restart.
/// </summary>
public sealed class AttemptRecord
{
    /// <summary>Unix seconds.</summary>
    public long Ts { get; set; }
    public string Ip { get; set; } = "";
    public string User { get; set; } = "";
    /// <summary>NTSTATUS SubStatus, e.g. 0xc000006a.</summary>
    public string Sub { get; set; } = "";
    public int Kind { get; set; }
    /// <summary>True when the source address was already blocked at the time.</summary>
    public bool Blocked { get; set; }
    /// <summary>True when the attempt was inside the whitelist and ignored.</summary>
    public bool Allowed { get; set; }
    public bool Success { get; set; }
    /// <summary>Running failure count for this address at the time.</summary>
    public int Failures { get; set; }
    /// <summary>Windows logon type (2 interactive, 3 network, 5 service, 10 remote).</summary>
    public int LogonType { get; set; }
}

public sealed record TrackedIp(
    string Ip,
    int Failures,
    Stage Stage,
    bool HasRealAttempt,
    long FirstSeen,
    long LastSeen);

public sealed record BlockEntry(
    string Ip,
    string User,
    string Reason,
    Stage Stage,
    ushort Attempts,
    FailureKind Kind,
    bool Permanent,
    /// <summary>Unix seconds. 0 means permanent.</summary>
    long ExpiresAt,
    long BlockedAt);

public sealed record WhitelistEntry(
    string Ip,
    int PrefixLength,
    string Note,
    long AddedAt);

/// <summary>IP threat intelligence, cached so external APIs are not hammered.</summary>
public sealed class ReputationRecord
{
    public string Ip { get; set; } = "";
    public string Country { get; set; } = "";
    public string CountryCode { get; set; } = "";
    public string City { get; set; } = "";
    public double Lat { get; set; }
    public double Lon { get; set; }
    public string Timezone { get; set; } = "";
    public string Isp { get; set; } = "";
    public string Org { get; set; } = "";
    public string As { get; set; } = "";
    public bool IsProxy { get; set; }
    public bool IsHosting { get; set; }
    public bool IsBlacklisted { get; set; }
    public string DnsblInfo { get; set; } = "";
    public int AbuseScore { get; set; }
    public int AbuseReports { get; set; }
    public string AbuseLastReported { get; set; } = "";
    public int RiskScore { get; set; }
    public string ThreatLevel { get; set; } = "Low";
    public string Source { get; set; } = "";
    public long CachedAt { get; set; }
}

public sealed class AppSettings
{
    public int RdpPort { get; set; } = 3389;
    public bool AutoDetectRdp { get; set; } = true;
    public int DashboardPort { get; set; } = 8787;

    /// <summary>
    /// Comma-separated list of local ports that get filtered when an address is
    /// blocked, so a single bad source is cut off from RDP, WinRM, SMB, etc.
    /// instead of only from RDP. Empty falls back to RdpPort.
    /// </summary>
    public string ProtectedPorts { get; set; } = "3389";

    /// <summary>
    /// When true, an address that reaches the threshold is blocked permanently
    /// on the first offence instead of going through the staged escalation.
    /// </summary>
    public bool AutoBlockPermanent { get; set; }

    public int RealUserFails { get; set; } = 3;
    public int RealUserWindowSeconds { get; set; } = 10;
    public int NonRealUserFails { get; set; } = 5;
    public int NonRealUserWindowSeconds { get; set; } = 300;
    public int DisabledFails { get; set; } = 5;

    public int Stage1Seconds { get; set; } = 1800;
    public int Stage2Seconds { get; set; } = 1800;
    public int Stage3Seconds { get; set; } = 3600;
    public bool Stage4Permanent { get; set; } = true;

    public bool ToastEnabled { get; set; } = true;
    public int ToastCooldownSeconds { get; set; } = 60;
    public int ToastMinGapSeconds { get; set; } = 5;
    public int ToastDisplaySeconds { get; set; } = 12;

    /// <summary>
    /// Alert delivery. No credentials in source/binary – defaults are blank so
    /// a fresh install must be configured via dashboard (config.ini) or
    /// NPAV_SMTP_* env vars. Operator can still harden by setting env vars
    /// and removing config.ini plain-text entry.
    /// </summary>
    public bool MailEnabled { get; set; } = true;
    public string SmtpHost { get; set; } = "";
    public int SmtpPort { get; set; } = 587;
    public string SmtpUser { get; set; } = "";
    public string SmtpPassword { get; set; } = "";
    public bool SmtpTls { get; set; } = true;
    public string MailFrom { get; set; } = "";
    public string MailTo { get; set; } = "";
    public string MailCc { get; set; } = "";
    public string MailBcc { get; set; } = "";

    public int AuditReassertSeconds { get; set; } = 900;
    public bool DebugConsole { get; set; }

    /// <summary>Raw value of the legacy build-1609 "allowlist=" config key.
    /// Consumed once by LegacyImport, never shown or applied in any other way.</summary>
    public string LegacyAllowlist { get; set; } = "";

    public int RetentionDays { get; set; } = 30;
    public int MaxBlocked { get; set; } = 512;
    public int MaxTracked { get; set; } = 512;
    public int MaxEvents { get; set; } = 2048;
    /// <summary>Attempts retained for the dashboard feed. Bounds feed RAM.</summary>
    public int MaxAttempts { get; set; } = 2000;

    /// <summary>Seconds. 0 disables the rolling window and counts cumulatively.</summary>
    public int TrackWindowSeconds { get; set; }

    public int StageSeconds(Stage s) => s switch
    {
        Stage.S1 => Stage1Seconds,
        Stage.S2 => Stage2Seconds,
        Stage.S3 => Stage3Seconds,
        _ => 0,
    };

    public int ThresholdFor(FailureKind k) => k switch
    {
        FailureKind.Real => RealUserFails,
        FailureKind.NonReal => NonRealUserFails,
        _ => DisabledFails,
    };

    public int WindowFor(FailureKind k) => k switch
    {
        FailureKind.Real => RealUserWindowSeconds,
        FailureKind.NonReal => NonRealUserWindowSeconds,
        _ => 0,
    };

    /// <summary>Parses ProtectedPorts into a de-duplicated list of valid ports.</summary>
    public List<int> ProtectedPortList()
    {
        var set = new HashSet<int>();
        foreach (var part in (ProtectedPorts ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (int.TryParse(part, out var p) && p is >= 1 and <= 65535) set.Add(p);
        }
        if (set.Count == 0) set.Add(RdpPort > 0 ? RdpPort : 3389);
        return set.ToList();
    }

    public static Stage NextStage(Stage s, AppSettings c) => s switch
    {
        Stage.None => Stage.S1,
        Stage.S1 => Stage.S2,
        Stage.S2 => Stage.S3,
        Stage.S3 => c.Stage4Permanent ? Stage.Permanent : Stage.S3,
        _ => c.Stage4Permanent ? Stage.Permanent : Stage.S3,
    };
}