namespace V3Guard;

public sealed record Decision(bool Blocked, Stage Stage, int Failures, string Reason);

/// <summary>
/// Pure decision logic: given an event and the tracked state, decide whether to block.
/// Kept free of Win32 so the escalation rules stay testable and obvious.
/// </summary>
public sealed class PolicyEngine
{
    private readonly Store _store;
    private readonly AppSettings _cfg;
    private volatile int _rdpPort = 3389;

    public PolicyEngine(Store store, AppSettings cfg)
    {
        _store = store;
        _cfg = cfg;
    }

    public int RdpPort
    {
        get => _rdpPort;
        set => _rdpPort = value;
    }

    /// <summary>
    /// Maps a failed logon to a category using the SubStatus reported by Windows.
    /// This is what separates a real brute-force from username enumeration.
    /// Windows writes the NTSTATUS as hex and is inconsistent about case, so the
    /// comparison is case-insensitive.
    /// </summary>
    public static FailureKind Classify(string subStatus)
    {
        string s = (subStatus ?? "").Trim().ToLowerInvariant();
        return s switch
        {
            // 0xC000006A = wrong password (account valid), 0xC0000064 = no such user.
            "0xc000006a" => FailureKind.Real,
            "0xc0000064" or "0xc000006f" => FailureKind.NonReal,
            // 0xC0000072 = account disabled, 0xC0000071 = password expired.
            "0xc0000072" or "0xc0000071" => FailureKind.Disabled,
            // Anything else (including an empty status) is treated as a genuine
            // attempt: failing closed here risks ignoring real attacks.
            _ => FailureKind.Real,
        };
    }

    public static string KindName(FailureKind k) => k switch
    {
        FailureKind.Real => "real user",
        FailureKind.NonReal => "unknown user",
        _ => "disabled account",
    };

    public Decision OnFailure(LogonEvent e)
    {
        string ip = e.Ip;
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // Whitelist is checked first: a trusted address is never tracked, never
        // escalated and never counted toward the charts - but it is still shown
        // in the feed, so the operator can see what is being ignored.
        if (_store.IsWhitelisted(ip))
        {
            Log.Allow(ip, e.User);
            _store.RecordAttempt(new AttemptRecord
            {
                Ts = now,
                Ip = ip,
                User = Sanitize.SingleLine(e.User, 63),
                Sub = e.SubStatus,
                Kind = (int)Classify(e.SubStatus),
                Allowed = true,
                Failures = 0,
                LogonType = e.LogonType,
            });
            return new Decision(false, Stage.None, 0, "whitelisted");
        }

        FailureKind kind = Classify(e.SubStatus);
        var t = _store.GetOrCreate(ip, now);

        // Sliding window: prune failures older than the effective window before counting.
        var (threshold, window) = EffectiveThreshold(t, kind);
        if (window > 0)
        {
            long cutoff = now - window;
            t.FailTs.RemoveAll(ts => ts < cutoff);
        }
        // Keep Failures in sync with the windowed list.
        t.Failures = t.FailTs.Count;
        t.Failures++;
        t.FailTs.Add(now);
        if (t.FailTs.Count > 64) t.FailTs.RemoveRange(0, t.FailTs.Count - 64);
        t.LastSeen = now;
        if (kind == FailureKind.Real) t.HasReal = true;
        _store.CountFailure(ip);
        if (t.Failures < threshold)
        {
            _store.RecordAttempt(new AttemptRecord
            {
                Ts = now,
                Ip = ip,
                User = Sanitize.SingleLine(e.User, 63),
                Sub = e.SubStatus,
                Kind = (int)kind,
                Blocked = _store.FindBlock(ip) is not null,
                Failures = t.Failures,
                LogonType = e.LogonType,
            });
            _store.Touch();
            return new Decision(false, (Stage)t.Stage, t.Failures,
                $"{t.Failures}/{threshold} {KindName(kind)} failures");
        }

        var stage = _cfg.AutoBlockPermanent ? Stage.Permanent : AppSettings.NextStage((Stage)t.Stage, _cfg);
        t.Stage = (int)stage;

        bool permanent = stage == Stage.Permanent || _cfg.StageSeconds(stage) <= 0;
        int secs = permanent ? 0 : _cfg.StageSeconds(stage);
        long expiresAt = permanent ? 0 : now + secs;

        _store.RecordAttempt(new AttemptRecord
        {
            Ts = now,
            Ip = ip,
            User = Sanitize.SingleLine(e.User, 63),
            Sub = e.SubStatus,
            Kind = (int)kind,
            Blocked = true,
            Failures = t.Failures,
            LogonType = e.LogonType,
        });

        _store.AddBlock(new BlockRecord
        {
            Ip = ip,
            User = Sanitize.SingleLine(e.User, 63),
            Reason = $"{t.Failures} failures ({KindName(kind)})",
            Stage = (int)stage,
            Attempts = (ushort)Math.Min(t.Failures, ushort.MaxValue),
            Kind = (int)kind,
            Permanent = permanent,
            ExpiresAt = expiresAt,
            BlockedAt = now,
            Port = 0,
        });

        return new Decision(true, stage, t.Failures, "threshold reached");
    }

    /// <summary>
    /// Once an address has produced a real-user failure the stricter real-user
    /// threshold applies to it, regardless of what kind the latest attempt was.
    /// </summary>
    private (int threshold, int window) EffectiveThreshold(TrackedRecord t, FailureKind kind)
    {
        if (t.HasReal) return (_cfg.RealUserFails, _cfg.RealUserWindowSeconds);
        return (kind switch
        {
            FailureKind.NonReal => _cfg.NonRealUserFails,
            FailureKind.Disabled => _cfg.DisabledFails,
            _ => _cfg.RealUserFails,
        }, _cfg.WindowFor(kind));
    }

    public void OnSuccess(LogonEvent e)
    {
        if (_store.IsWhitelisted(e.Ip)) return;
        _store.CountSuccess();
        _store.RecordAttempt(new AttemptRecord
        {
            Ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Ip = e.Ip,
            User = Sanitize.SingleLine(e.User, 63),
            Sub = "-",
            Success = true,
            LogonType = e.LogonType,
        });
        // Clears the window count but keeps the escalation ladder, so a single
        // correct guess cannot erase the record of an ongoing attack.
        _store.ResetTracked(e.Ip);
    }

    public void OnTamper(int eventId)
    {
        Log.Warn($"security log tampering detected EventID={eventId} - re-asserting audit policy");
        Audit.EnsureLogonAuditing();
    }
}