namespace V3Guard;

/// <summary>
/// Toast showcase (<c>v3.exe --demo</c>).
///
/// Renders every notice style in sequence so the appearance can be reviewed
/// without waiting for a real attack. Touches nothing - no WFP, no database, no
/// dashboard - so it is safe to run any time, elevated or not.
/// </summary>
public static class Demo
{
    /// <summary>Synthetic notices, in the order they would occur in real life.</summary>
    private static readonly (NoticeKind Kind, string Title, string L1, string L2, string L3, string Accent)[] Script =
    [
        (NoticeKind.StartupActive, "Protection active",
            "RDP port 3389 is guarded", "0 existing block(s) restored", "", "#2f9e6f"),

        (NoticeKind.Block, "Blocked 203.0.113.77",
            "203.0.113.77 - 3 failed attempts", "User administrator blocked: permanent",
            "", "#e0483d"),

        (NoticeKind.Block, "Blocked 198.51.100.4",
            "198.51.100.4 - 7 failed attempts", "User root blocked: permanent",
            "", "#e0483d"),

        (NoticeKind.Whitelisted, "Ignored trusted address",
            "10.0.0.14 - 2 failed attempts", "User svc-backup is whitelisted",
            "", "#2f9e6f"),

        (NoticeKind.ProtectionLost, "Detection offline",
            "Lost the Security log subscription", "Blocked addresses stay blocked. Retrying.",
            "", "#d29922"),

        (NoticeKind.ProtectionRestored, "Protection restored",
            "Event log subscription is active again", "", "", "#2f9e6f"),

        (NoticeKind.Tamper, "Security warning",
            "The audit log or policy was changed", "Protection re-asserted. Check the console.",
            "", "#d29922"),

        (NoticeKind.Released, "Address released",
            "203.0.113.77", "Block removed by operator", "", "#2f9e6f"),
    ];

    public static int Run(string[] args)
    {
        Log.Init();

        // A dedicated config so the showcase is not suppressed by the live
        // cooldown and min-gap settings in config.ini.
        var cfg = new AppSettings
        {
            ToastEnabled = true,
            ToastCooldownSeconds = 0,
            ToastMinGapSeconds = 0,
            ToastDisplaySeconds = DemoSeconds(args),
        };

        int seconds = cfg.ToastDisplaySeconds;
        Console.WriteLine("NPav RDP Protection - toast demo");
        Console.WriteLine($"showing {Script.Length} notices, {seconds}s each");
        Console.WriteLine("(no WFP, no database, no dashboard - safe to run any time)");
        Console.WriteLine();

        using var host = new ToastHost(cfg);
        Thread.Sleep(400); // let the window class register and the thread start

        int shown = 0;
        foreach (var (kind, title, l1, l2, l3, accent) in Script)
        {
            Console.WriteLine($"  {kind,-20} {title,-28} {l1}");
            host.Notify(kind, title, l1, l2, l3, accent);
            shown++;

            // Report whether pointer messages actually reach the toast window. If
            // these stay at zero while the mouse is over it, Windows is not routing
            // cursor messages to us and the busy cursor comes from elsewhere.
            Thread.Sleep(700);
            Console.WriteLine($"      pointer msgs: WM_SETCURSOR={ToastHost.SetCursorMessages} "
                            + $"WM_MOUSEMOVE={ToastHost.MouseMoveMessages} "
                            + $"btn={ToastHost.ButtonMessages} close={ToastHost.CloseClicks}");

            // Wait for the toast to finish before queueing the next, otherwise
            // they would collapse into the queue and only some would be seen.
            Thread.Sleep((seconds + 1) * 1000);
        }

        Console.WriteLine();
        Console.WriteLine($"demo complete - {shown} notices dispatched");
        Console.WriteLine("check logs\\ for any 'toast' errors or window-creation failures.");
        return 0;
    }

    private static int DemoSeconds(string[] args)
    {
        // --demo=5 or --demo 5 sets the per-toast dwell time.
        foreach (var a in args)
        {
            if (a.StartsWith("--demo=", StringComparison.OrdinalIgnoreCase) &&
                int.TryParse(a["--demo=".Length..], out var v))
                return Math.Clamp(v, 3, 120);
        }
        int idx = Array.FindIndex(args, a => a.Equals("--demo", StringComparison.OrdinalIgnoreCase));
        if (idx >= 0 && idx + 1 < args.Length && int.TryParse(args[idx + 1], out var w))
            return Math.Clamp(w, 3, 120);
        return 5;
    }
}