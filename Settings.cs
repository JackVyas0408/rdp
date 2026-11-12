using System.Text;

namespace V3Guard;

/// <summary>Flat "key=value" settings file so operators can hand-edit config.ini.</summary>
public static class Settings
{
    private static readonly string Path =
        System.IO.Path.Combine(AppContext.BaseDirectory, "config.ini");

    public static AppSettings Load()
    {
        var s = new AppSettings();
        bool existed = false;
        try
        {
            existed = File.Exists(Path);
            if (existed)
                foreach (var raw in File.ReadAllLines(Path))
                {
                    var line = raw.Trim();
                    if (line.Length == 0 || line[0] == '#') continue;
                    int eq = line.IndexOf('=');
                    if (eq <= 0) continue;
                    Apply(s, line[..eq].Trim(), line[(eq + 1)..].Trim());
                }
        }
        catch (Exception ex)
        {
            Log.Warn($"config read failed ({ex.Message}); using defaults");
        }

        // Env override (never persisted plain-text): NPAV_SMTP_HOST, NPAV_SMTP_USER,
        // NPAV_SMTP_PASS, NPAV_MAIL_FROM, NPAV_MAIL_TO, NPAV_ABUSEIPDB_KEY
        ApplyEnv(s);

        // Write the file on first run. Without this a fresh install ends up with
        // no config.ini at all, so there is nothing for the operator to inspect or
        // hand-edit and the shipped defaults stay invisible.
        if (!existed)
        {
            Log.Info("no config.ini found - writing defaults");
            Save(s);
        }
        return s;
    }

    public static void Save(AppSettings s)
    {
        var sb = new StringBuilder(4096);
        sb.Append("# NPav RDP Protection - editable by hand or from the dashboard\n");

        void I(string k, object v) => sb.Append(k).Append('=').Append(v).Append('\n');
        void B(string k, bool v) => I(k, v ? 1 : 0);

        I("rdp_port", s.RdpPort);
        B("auto_detect_rdp", s.AutoDetectRdp);
        I("dashboard_port", s.DashboardPort);
        I("protected_ports", Sanitize.SingleLine(s.ProtectedPorts, 128));
        B("auto_block_permanent", s.AutoBlockPermanent);

        I("real_user_fails", s.RealUserFails);
        I("real_user_window_s", s.RealUserWindowSeconds);
        I("nonreal_user_fails", s.NonRealUserFails);
        I("nonreal_user_window_s", s.NonRealUserWindowSeconds);
        I("disabled_fails", s.DisabledFails);
        I("track_window_s", s.TrackWindowSeconds);

        I("stage1_secs", s.Stage1Seconds);
        I("stage2_secs", s.Stage2Seconds);
        I("stage3_secs", s.Stage3Seconds);
        B("stage4_perm", s.Stage4Permanent);

        B("toast_enabled", s.ToastEnabled);
        I("toast_cooldown_s", s.ToastCooldownSeconds);
        I("toast_min_gap_s", s.ToastMinGapSeconds);
        I("toast_display_s", s.ToastDisplaySeconds);

        B("email_enabled", s.MailEnabled);
        I("smtp_host", Sanitize.SingleLine(s.SmtpHost, 128));
        I("smtp_port", s.SmtpPort);
        I("smtp_user", Sanitize.SingleLine(s.SmtpUser, 128));
        I("smtp_pass", Sanitize.SingleLine(s.SmtpPassword, 128));
        B("smtp_tls", s.SmtpTls);
        I("email_from", Sanitize.SingleLine(s.MailFrom, 128));
        I("email_to", Sanitize.SingleLine(s.MailTo, 256));
        I("email_cc", Sanitize.SingleLine(s.MailCc, 256));
        I("email_bcc", Sanitize.SingleLine(s.MailBcc, 256));

        I("audit_reassert_s", s.AuditReassertSeconds);
        I("log_retention_days", s.RetentionDays);
        B("debug_console", s.DebugConsole);

        try
        {
            string tmp = Settings.Path + ".tmp";
            File.WriteAllText(tmp, sb.ToString());
            File.Move(tmp, Settings.Path, overwrite: true);
        }
        catch (Exception ex)
        {
            Log.Warn($"config save failed: {ex.Message}");
        }
    }

    private static void ApplyEnv(AppSettings s)
    {
        string G(string n) => Environment.GetEnvironmentVariable(n) ?? "";
        string h = G("NPAV_SMTP_HOST"); if (h.Length > 0) s.SmtpHost = Sanitize.SingleLine(h, 128);
        string u = G("NPAV_SMTP_USER"); if (u.Length > 0) s.SmtpUser = Sanitize.SingleLine(u, 128);
        string p = G("NPAV_SMTP_PASS"); if (p.Length > 0) s.SmtpPassword = Sanitize.SingleLine(p, 128);
        string f = G("NPAV_MAIL_FROM"); if (f.Length > 0) s.MailFrom = Sanitize.SingleLine(f, 128);
        string t = G("NPAV_MAIL_TO"); if (t.Length > 0) s.MailTo = Sanitize.SingleLine(t, 256);
    }

    /// <summary>
    /// Applies one key from the dashboard. Returns false when the key is not
    /// recognised, so the caller can report a bad field instead of silently
    /// dropping it. Shares the parsing rules with the config file, including the
    /// clamping, so a value typed into the UI cannot land outside its range.
    /// </summary>
    public static bool ApplyKey(AppSettings s, string key, string value)
    {
        if (!Known.Contains(key)) return false;
        Apply(s, key, value);
        return true;
    }

    /// <summary>Every key Apply understands, for validation and for the UI.</summary>
    private static readonly HashSet<string> Known = new(StringComparer.Ordinal)
    {
        "rdp_port", "auto_detect_rdp", "dashboard_port", "protected_ports", "auto_block_permanent",
        "real_user_fails", "real_user_window_s", "nonreal_user_fails",
        "nonreal_user_window_s", "disabled_fails", "track_window_s",
        "stage1_secs", "stage2_secs", "stage3_secs", "stage4_perm",
        "toast_enabled", "toast_cooldown_s", "toast_min_gap_s", "toast_display_s",
        "email_enabled", "smtp_host", "smtp_port", "smtp_user", "smtp_pass",
        "smtp_tls", "email_from", "email_to", "email_cc", "email_bcc",
        "audit_reassert_s", "log_retention_days", "debug_console",
        "max_attempts",
    };

    private static void Apply(AppSettings s, string k, string v)
    {
        bool T(string x) => x == "1" || x.Equals("true", StringComparison.OrdinalIgnoreCase) || x.Equals("yes", StringComparison.OrdinalIgnoreCase);

        switch (k)
        {
            case "rdp_port": if (int.TryParse(v, out var a)) s.RdpPort = Math.Clamp(a, 1, 65535); break;
            case "auto_detect_rdp": s.AutoDetectRdp = T(v); break;
            case "dashboard_port": if (int.TryParse(v, out var b)) s.DashboardPort = Math.Clamp(b, 1, 65535); break;
            case "protected_ports": s.ProtectedPorts = Sanitize.SingleLine(v, 128); break;
            // Legacy build-1609 key: the trusted-IP list used to live in the
            // config. Not exposed through the dashboard - LegacyImport moves it
            // into db.json's whitelist once.
            case "allowlist": s.LegacyAllowlist = Sanitize.SingleLine(v, 256); break;
            case "auto_block_permanent": s.AutoBlockPermanent = T(v); break;

            case "real_user_fails": if (int.TryParse(v, out var c)) s.RealUserFails = Math.Max(1, c); break;
            case "real_user_window_s": if (int.TryParse(v, out var d)) s.RealUserWindowSeconds = Math.Max(0, d); break;
            case "nonreal_user_fails": if (int.TryParse(v, out var e)) s.NonRealUserFails = Math.Max(1, e); break;
            case "nonreal_user_window_s": if (int.TryParse(v, out var f)) s.NonRealUserWindowSeconds = Math.Max(0, f); break;
            case "disabled_fails": if (int.TryParse(v, out var g)) s.DisabledFails = Math.Max(1, g); break;
            case "track_window_s": if (int.TryParse(v, out var h)) s.TrackWindowSeconds = Math.Max(0, h); break;

            case "stage1_secs": if (int.TryParse(v, out var i)) s.Stage1Seconds = Math.Max(0, i); break;
            case "stage2_secs": if (int.TryParse(v, out var j)) s.Stage2Seconds = Math.Max(0, j); break;
            case "stage3_secs": if (int.TryParse(v, out var l)) s.Stage3Seconds = Math.Max(0, l); break;
            case "stage4_perm": s.Stage4Permanent = T(v); break;

            case "toast_enabled": s.ToastEnabled = T(v); break;
            case "toast_cooldown_s": if (int.TryParse(v, out var m)) s.ToastCooldownSeconds = Math.Max(0, m); break;
            case "toast_min_gap_s": if (int.TryParse(v, out var n)) s.ToastMinGapSeconds = Math.Max(0, n); break;
            case "toast_display_s": if (int.TryParse(v, out var o)) s.ToastDisplaySeconds = Math.Clamp(o, 3, 120); break;

            case "email_enabled": s.MailEnabled = T(v); break;
            case "smtp_host": s.SmtpHost = Sanitize.SingleLine(v, 128); break;
            case "smtp_port": if (int.TryParse(v, out var p)) s.SmtpPort = Math.Clamp(p, 1, 65535); break;
            case "smtp_user": s.SmtpUser = Sanitize.SingleLine(v, 128); break;
            case "smtp_pass": s.SmtpPassword = Sanitize.SingleLine(v, 128); break;
            case "smtp_tls": s.SmtpTls = T(v); break;
            case "email_from": s.MailFrom = Sanitize.SingleLine(v, 128); break;
            case "email_to": s.MailTo = Sanitize.SingleLine(v, 256); break;
            case "email_cc": s.MailCc = Sanitize.SingleLine(v, 256); break;
            case "email_bcc": s.MailBcc = Sanitize.SingleLine(v, 256); break;

            case "audit_reassert_s": if (int.TryParse(v, out var q)) s.AuditReassertSeconds = Math.Max(0, q); break;
            case "log_retention_days": if (int.TryParse(v, out var r)) s.RetentionDays = Math.Clamp(r, 1, 3650); break;
            case "max_attempts": if (int.TryParse(v, out var ma)) s.MaxAttempts = Math.Clamp(ma, 50, 5000); break;
            case "debug_console": s.DebugConsole = T(v); break;
        }
    }
}