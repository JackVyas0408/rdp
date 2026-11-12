namespace V3Guard;

public static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        // Must happen before any window exists, otherwise Windows keeps
        // bitmap-stretching our windows and the toast stays soft on a scaled
        // display. Applies to the CLI modes too since --demo shows toasts.
        Dpi.Enable();

        // Diagnostic mode must not touch WFP, the dashboard or the db - it only
        // reports what the guard can and cannot see. Needs a console for output.
        if (args.Any(a => a.Equals("--diag", StringComparison.OrdinalIgnoreCase)
                       || a.Equals("-diag", StringComparison.OrdinalIgnoreCase)))
        {
            Log.AttachParentConsole();
            Diag.Run();
            Console.Out.Flush();
            return;
        }

        // Toast showcase: renders every notice style so the appearance can be
        // checked without waiting for a real attack. Touches nothing else.
        if (args.Any(a => a.Equals("--demo", StringComparison.OrdinalIgnoreCase)
                       || a.Equals("-demo", StringComparison.OrdinalIgnoreCase)))
        {
            // This is a GUI-subsystem binary, so it starts with no console and the
            // shell returns immediately without waiting. Attaching to the parent
            // console is what makes the progress text visible at all.
            Log.AttachParentConsole();
            Demo.Run(args);
            Console.Out.Flush();
            return;
        }

        // End-to-end WFP check: installs a filter and verifies traffic is actually
        // refused, rather than trusting that the install call succeeded.
        if (args.Any(a => a.StartsWith("--wfp-test", StringComparison.OrdinalIgnoreCase)))
        {
            int rc = WfpTest.Run(args);
            Console.Out.Flush();
            Environment.ExitCode = rc;
            return;
        }

        // Activation is handled via the dashboard web page (see below).

    AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            Log.Error($"fatal: {e.ExceptionObject}");

        var cfg = Settings.Load();
        Log.Init();
        Log.Prune(cfg.RetentionDays);

        // The license is always verified at startup - and re-verified every
        // minute in the maintenance loop below - so an expired or hand-edited
        // license.lic takes the product back to the asking-code page, wherever
        // in its lifetime that happens.
        var lic = License.GetInfo();
        Log.Info("license check: " + (lic.Valid
            ? $"valid, {License.DaysLeft()} day(s) left (expires {lic.Expiry:yyyy-MM-dd})"
            : lic.Signed ? $"EXPIRED {lic.Expiry:yyyy-MM-dd} - activation required"
            : lic.Tampered ? "TAMPERED - signature mismatch, activation required"
            : "not activated"));

        var store = new Store(AppContext.BaseDirectory, cfg);
        store.Load();

        // Upgrade path: pull build-1609 state.dat / rule.json / config allowlist
        // into the new db.json so old blocks, history and trusted IPs keep
        // showing. One-shot and silent apart from a log line; must run before
        // the restore below so imported blocks get their filters installed.
        LegacyImport.Run(store, cfg);

        // Single instance: two guards would fight over the WFP filters and the db.
        using var mutex = new Mutex(true, @"Local\NPAV_RDP_GUARD_V3_SINGLE", out bool isFirst);
        if (!isFirst)
        {
            Log.Error("another v3 instance is already running");
            return;
        }

        using var toast = new ToastHost(cfg);

        if (!Wfp.Open())
        {
            toast.Notify(NoticeKind.ProtectionLost, "Administrator rights required",
                "The WFP engine could not be opened.",
                "Right-click v3.exe and choose Run as administrator.",
                "", "#d29922");
            Log.Error("WFP engine unavailable - this program must run elevated");
            return;
        }

        // Resolve the port before restoring, so persisted filters are re-installed
        // on the port that is actually being watched.
        var policy = new PolicyEngine(store, cfg);
        policy.RdpPort = cfg.AutoDetectRdp ? Audit.DetectRdpPort() : cfg.RdpPort;
        Log.Info($"protecting RDP port {policy.RdpPort}");

        // Filters live only as long as the process: the WFP session is dynamic, so
        // everything this guard added is dropped by Windows the moment it exits.
        // Re-install from the persisted db so a restart resumes guarding the same
        // addresses instead of silently forgetting them.
        int restored = 0, restoreFailed = 0;
        foreach (var b in store.BlocksSnapshot())
        {
            var ports = b.Port > 0 ? new List<int> { b.Port } : cfg.ProtectedPortList();
            bool any = false;
            foreach (var port in ports)
            {
                if (Wfp.Block(b.Ip, port, out _)) { restored++; any = true; }
                else restoreFailed++;
            }
            if (any) b.Port = b.Port > 0 ? b.Port : 0;
        }
        Log.Info($"restored {restored} block filter(s) from db"
               + (restoreFailed > 0 ? $" ({restoreFailed} failed)" : ""));
        if (restored > 0) store.Flush(force: true);

        // Resolve reputation for every already-blocked address – bounded to 4
        // concurrent lookups so a fresh boot with 500 blocks doesn't spawn 500
        // sockets (NetGate in Reputation still caps at 8).
        var repGate = new SemaphoreSlim(4);
        foreach (var b in store.BlocksSnapshot())
        {
            string rip = b.Ip;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                repGate.Wait();
                try { Reputation.Get(store, rip); } catch { }
                finally { repGate.Release(); }
            });
        }

        var source = new EventLogSource();
        var mailer = new Mailer(cfg);

        void OnEvent(LogonEvent e)
        {
            switch (e.EventId)
            {
                case EventLogSource.LogonFailure:
                {
                    var d = policy.OnFailure(e);

                    // Log every counted attempt with its running total. Without
                    // this there is no way to tell the difference between "the
                    // attacker sent fewer attempts than the operator thought" and
                    // "the guard missed some", which is exactly the question that
                    // arises when a block lands later than the threshold suggests.
                    Log.Info($"4625 ip={e.Ip} user={e.User} sub={e.SubStatus} "
                           + $"-> counted {d.Failures} ({PolicyEngine.KindName(PolicyEngine.Classify(e.SubStatus))})");

                    // First failure from an address: start a background reputation lookup so
// the threat map and block details have intelligence ready before it lands.
                    if (d.Failures == 1)
                    {
                        ThreadPool.QueueUserWorkItem(_ =>
                        {
                            try { Reputation.Get(store, e.Ip); } catch { }
                        });
                    }

                    if (!d.Blocked) return;

                    // License gate: an expired or tampered license must not keep
                    // issuing WFP blocks. Detection/feed still runs so the
                    // operator sees the attempts, enforcement resumes on renewal.
                    if (!License.IsLicensed())
                    {
                        Log.Warn($"auto-block for {e.Ip} suppressed - license invalid, activation required");
                        return;
                    }

                    // Enforce it. Recording a block without installing the filter
                    // is exactly how the dashboard showed "active block" while the
                    // attacker kept connecting.
                    bool anyFailed = false;
                    foreach (var port in cfg.ProtectedPortList())
                    {
                        if (!Wfp.Block(e.Ip, port, out ulong filterId))
                        {
                            anyFailed = true;
                            Log.Error($"WFP block FAILED for {e.Ip} on port {port}");
                        }
                        else
                        {
                            Log.Info($"WFP filter {filterId} installed for {e.Ip} on port {port}");
                        }
                    }
                    if (anyFailed)
                    {
                        toast.Notify(NoticeKind.ProtectionLost, "Block failed",
                            $"{e.Ip} could not be blocked on some ports",
                            "The filter was refused. Run as Administrator.",
                            "", "#d29922");
                    }

                    // Populate threat intel in the background so the dashboard's
                    // threat map and reputation panel have data without blocking.
                    ThreadPool.QueueUserWorkItem(_ =>
                    {
                        try { Reputation.Get(store, e.Ip); } catch { }
                    });

                    toast.Notify(NoticeKind.Block,
                        $"Blocked {e.Ip}",
                        $"{e.Ip} - {d.Failures} failed attempts",
                        $"User {e.User} blocked: {(d.Stage == Stage.Permanent ? "permanent" : "timed")}",
                        "", "#e0483d");
                    // Email the alert. Sent on a pool thread so a slow relay cannot
                    // hold up the detection worker.
                    if (cfg.MailEnabled && !string.IsNullOrWhiteSpace(cfg.SmtpHost)
                        && !string.IsNullOrWhiteSpace(cfg.MailTo))
                    {
                        string subject = $"[{Brand.ShortName}] Blocked {e.Ip} after {d.Failures} attempts";
                        string body = BuildBlockEmail(e, d, policy.RdpPort, store, cfg);
                        ThreadPool.UnsafeQueueUserWorkItem(_ =>
                        {
                            var res = mailer.Send(subject, body);
                            if (res.Ok)
                                Log.Info($"alert email sent to {cfg.MailTo} for {e.Ip}");
                            else
                                Log.Error($"alert email for {e.Ip} NOT sent - {res.Summary}"
                                        + (res.Hint.Length > 0 ? $" | {res.Hint}" : ""));
                        }, null);
                    }
                    store.Flush(force: true);
                    break;
                }

                case EventLogSource.LogonSuccess:
                    policy.OnSuccess(e);
                    break;

                case EventLogSource.AuditLogCleared:
                case EventLogSource.AuditPolicyChanged:
                case EventLogSource.AuditPolicyAssigned:
                    policy.OnTamper(e.EventId);
                    toast.Notify(NoticeKind.Tamper, "Security warning",
                        "The audit log or policy was changed",
                        "Protection re-asserted. Check the console.", "", "#d29922");
                    store.Flush(force: true);
                    break;
            }
        }

        var dash = new Dashboard(store, cfg, policy, toast, mailer, source);
        dash.Start();

        // Activation gate: until a valid 1-year license exists, serve the
        // activation page and wait. The guard does not enforce or detect yet.
        if (!License.IsLicensed())
        {
            try
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
                    $"http://127.0.0.1:{cfg.DashboardPort}/#t={dash.Token}")
                { UseShellExecute = true });
            }
            catch { }
            while (!License.IsLicensed()) Thread.Sleep(1000);
        }

        source.Event += OnEvent;
        source.Start();

        toast.Notify(NoticeKind.StartupActive, "Protection active",
            $"RDP port {policy.RdpPort} is guarded",
            source.IsHealthy
                ? $"{restored} existing block(s) restored"
                : "Detection offline - could not read the Security log",
            "", "#2f9e6f");

        // Enable logon failure auditing - without it Windows never writes 4625, and
        // the guard would sit silently detecting nothing.
        if (!Audit.EnsureLogonAuditing())
            Log.Error("WARNING: 4625 events will not be generated until failure auditing is enabled");

        // Maintenance loop: expire blocks, persist, re-assert policy, keep filters
        // aligned with the current RDP port.
        var lastReassert = DateTime.UtcNow;
        var lastPortCheck = DateTime.UtcNow;
        var lastHealth = DateTime.UtcNow;
        var lastLicCheck = DateTime.UtcNow;
        bool wasHealthy = source.IsHealthy;
        bool wasLicensed = License.IsLicensed();
        bool hadToast = false;

        using var shutdown = new ManualResetEventSlim(false);
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; shutdown.Set(); };
        void Loop()
        {
        while (!shutdown.Wait(5000))
        {

            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            foreach (var dead in store.TakeExpired(now))
            {
                Wfp.Unblock(dead.Ip);
                Log.Unblock(dead.Ip, "expired");
            }

            store.Flush();

            if (cfg.AutoDetectRdp && (DateTime.UtcNow - lastPortCheck).TotalSeconds > 30)
            {
                lastPortCheck = DateTime.UtcNow;
                int p = Audit.DetectRdpPort();
                if (p != policy.RdpPort)
                {
                    Log.Warn($"RDP port changed {policy.RdpPort} -> {p}, migrating filters");
                    foreach (var b in store.BlocksSnapshot())
                    {
                        Wfp.UnblockPort(b.Ip, policy.RdpPort);
                        Wfp.Block(b.Ip, p, out _);
                    }
                    policy.RdpPort = p;
                }
            }

            // The subscription is push-based; Maintain() only re-establishes it after a
            // drop and checkpoints the resume bookmark. Cheap when all is well.
            bool healthy = source.IsHealthy;
            source.Maintain();

            if (healthy != wasHealthy)
            {
                wasHealthy = healthy;
                if (healthy)
                {
                    toast.Notify(NoticeKind.ProtectionRestored, "Protection restored",
                        "Event log subscription is active again", "", "", "#2f9e6f");
                }
                else
                {
                    toast.Notify(NoticeKind.ProtectionLost, "Detection offline",
                        "Lost the Security log subscription",
                        "Blocked addresses stay blocked. Retrying.", "", "#d29922");
                }
            }

            // License guard: the signature is re-verified every minute. If the
            // file is deleted, expires mid-run, or a single byte is changed the
            // guard goes back to the asking-code page and stops installing new
            // blocks until the license is valid again.
            if ((DateTime.UtcNow - lastLicCheck).TotalSeconds >= 60)
            {
                lastLicCheck = DateTime.UtcNow;
                bool ok = License.IsLicensed();
                if (ok != wasLicensed)
                {
                    wasLicensed = ok;
                    string detail = License.StatusText();
                    if (ok)
                    {
                        Log.Info("license re-validated: " + detail);
                        toast.Notify(NoticeKind.ProtectionRestored, "License valid",
                            $"Enforcement resumed ({detail})", "", "", "#2f9e6f");
                    }
                    else
                    {
                        Log.Warn("license check FAILED (" + detail + ") - new blocks are suppressed");
                        toast.Notify(NoticeKind.ProtectionLost, "License invalid",
                            "The license file is expired, modified or missing",
                            "The dashboard will ask for the asking code again. Existing blocks stay in place until they expire.", "", "#d29922");
                    }
                }
            }

            if (cfg.AuditReassertSeconds > 0 &&
                (DateTime.UtcNow - lastReassert).TotalSeconds >= cfg.AuditReassertSeconds)
            {
                lastReassert = DateTime.UtcNow;
                Audit.EnsureLogonAuditing();
            }

            if (toast.Suppressed > 0 && !hadToast && DateTime.UtcNow.Second % 30 < 5)
            {
                hadToast = true;
                Log.Info($"{toast.Suppressed} toast(s) suppressed by cooldown");
            }
            // Reset so the next suppression burst is reported too - previously
            // this only ever logged once per process run.
            if (toast.Suppressed == 0) hadToast = false;

            // Periodic visibility: without this, "detector broken" and "quiet
            // day" look identical from the outside.
            if ((DateTime.UtcNow - lastHealth).TotalMinutes >= 5)
            {
                lastHealth = DateTime.UtcNow;
                store.SnapshotCounts(out long tf, out long ts, out long tb);
                Log.Info($"health: listening={source.IsHealthy} parsed={source.Delivered} "
                       + $"skipped={source.Skipped} blocks={store.BlocksSnapshot().Count} "
                       + $"failures={tf} successes={ts} total_blocks={tb} "
                       + $"ram_priv_kb={Log.PrivateBytesKb()} ram_ws_kb={Log.WorkingSetKb()}"
                       + (source.LastSkipReason.Length > 0 ? $" last_skip='{source.LastSkipReason}'" : ""));
            }

            // The guard is idle almost all the time, so returning resident pages
            // costs nothing and keeps the reported footprint tiny.
            Log.TrimWorkingSet();
        }
        } // Loop()
        try { Loop(); }
        finally
        {
            Log.Info("shutting down – flushing state");
            store.Flush(force: true);
            try { source.Dispose(); } catch { }
            try { dash.Dispose(); } catch { }
            Wfp.Close();
        }
    }

    /// <summary>
    /// HTML alert sent when an address is blocked. Carries the details an
    /// operator needs to judge the event without opening the console: who, from
    /// where, how hard, for how long, and whether it is still in force.
    /// </summary>
    private static string BuildBlockEmail(LogonEvent e, Decision d, int port, Store store, AppSettings cfg)
    {
        static string H(string s) => System.Net.WebUtility.HtmlEncode(s);

        string kind = PolicyEngine.KindName(PolicyEngine.Classify(e.SubStatus));
        bool permanent = d.Stage == Stage.Permanent;
        string length = permanent ? "Permanent" : HumanSeconds(cfg.StageSeconds(d.Stage));
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        int active = store.BlocksSnapshot().Count;
        var rep = store.FindReputation(e.Ip);
        string risk = rep is null
            ? "not looked up"
            : $"{rep.RiskScore}/100 ({rep.ThreatLevel})";
        string geo = rep is null || string.IsNullOrEmpty(rep.Country)
            ? "-"
            : $"{rep.City}, {rep.Country}".Trim(' ', ',');
        string net = rep is null || string.IsNullOrEmpty(rep.Isp) ? "-" : rep.Isp;

        string row(string k, string v) =>
            $"<tr><td style=\"padding:6px 14px 6px 0;color:#6b7785\">{k}</td>" +
            $"<td style=\"padding:6px 0;font-weight:600\">{v}</td></tr>";

        return $"""
        <div style="font-family:Segoe UI,Helvetica,Arial,sans-serif;font-size:14px;color:#1a2027">
          <div style="border-left:4px solid #c9312b;padding-left:12px;margin-bottom:16px">
            <div style="font-size:11px;letter-spacing:.08em;color:#c9312b;font-weight:700">
              {Brand.ProductNameUpper}</div>
            <div style="font-size:18px;font-weight:700;margin-top:2px">
              Blocked {H(e.Ip)}</div>
          </div>

          <table style="border-collapse:collapse;font-size:14px">
            {row("Source IP", H(e.Ip))}
            {row("Username tried", H(e.User))}
            {row("Failed attempts", d.Failures.ToString())}
            {row("Failure type", H(kind))}
            {row("Blocked on port", port.ToString())}
            {row("Location", H(geo))}
            {row("Network", H(net))}
            {row("Threat risk", H(risk))}
            {row("Block length", length)}
            {row("Time (UTC)", DateTimeOffset.FromUnixTimeSeconds(now).ToString("yyyy-MM-dd HH:mm:ss"))}
            {row("Active blocks now", active.ToString())}
          </table>

          <p style="color:#6b7785;font-size:12px;margin-top:18px">
            The address is filtered at the Windows Filtering Platform and stays blocked
            until it expires or an operator releases it from the console.
          </p>
        </div>
        """;
    }

    /// <summary>Rounds a duration to something a person reads at a glance.</summary>
    private static string HumanSeconds(int seconds)
    {
        if (seconds <= 0) return "Permanent";
        if (seconds >= 86400) return $"{seconds / 86400}d {seconds % 86400 / 3600}h";
        if (seconds >= 3600) return $"{seconds / 3600}h {seconds % 3600 / 60}m";
        if (seconds >= 60) return $"{seconds / 60}m";
        return $"{seconds}s";
    }
}