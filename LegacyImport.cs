using System.Text;
using System.Text.Json;

namespace V3Guard;

/// <summary>
/// One-shot import of build-1609 data after an upgrade. The previous version
/// kept its state in three places the new dashboard cannot read:
///   state.dat   - INI-ish sections: [STATS] totals, [BLOCKS], [TRACKED], [EVENTS]
///   rule.json   - persisted block rules {"rules":[{ip,user,stage,reason,...}]}
///   config.ini  - "allowlist=" key holding the trusted-IP list
/// The new build persists everything in db.json, so without this migration the
/// operator's old blocks, history and trusted IPs would simply vanish from the
/// dashboard. Runs before any worker is started, is silent apart from one log
/// line, and never runs twice: the database is version-stamped (Version >= 4)
/// and the legacy files are renamed with a .migrated suffix afterwards.
///
/// The old license.dat (encrypted blob) cannot be converted; the product asks
/// once for an activation key, and from then on the signed license.lic applies.
/// </summary>
public static class LegacyImport
{
    public static void Run(Store store, AppSettings cfg)
    {
        string dir = AppContext.BaseDirectory;

        // Version stamp: a db already carrying >= 4 was imported before.
        // (store.Data is safe to read here - nothing else has started yet.)
        if (store.Data.Version >= 4) return;

        var blocks = new List<BlockRecord>();
        var tracked = new List<TrackedRecord>();
        var attempts = new List<AttemptRecord>();
        var whitelist = new List<(string, int)>();
        long totalBlocks = 0, totalFailures = 0;
        bool any = false;

        // ---- rule.json: persisted block rules --------------------------------
        string rulePath = System.IO.Path.Combine(dir, "rule.json");
        if (File.Exists(rulePath))
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(rulePath));
                if (doc.RootElement.TryGetProperty("rules", out var arr) && arr.ValueKind == JsonValueKind.Array)
                {
                    long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    foreach (var r in arr.EnumerateArray())
                    {
                        string ip = r.TryGetProperty("ip", out var ipEl) ? ipEl.GetString() ?? "" : "";
                        if (!Net.TryParseIpv4(ip, out _)) continue;

                        int stage = r.TryGetProperty("stage", out var stEl) && stEl.TryGetInt32(out var s0)
                            ? Math.Clamp(s0, 1, 4) : 1;
                        ushort att = r.TryGetProperty("attempts", out var atEl) && atEl.TryGetInt32(out var a0)
                            ? (ushort)Math.Clamp(a0, 0, 9999) : (ushort)0;
                        string reason = r.TryGetProperty("reason", out var rsEl)
                            ? Sanitize.SingleLine(rsEl.GetString() ?? "", 60) : "";
                        long expires = 0;
                        if (r.TryGetProperty("expires", out var exEl) && exEl.TryGetInt64(out var e0))
                        {
                            if (e0 >= 1_000_000_000) expires = e0;                 // absolute unix time
                            else if (e0 > 0) expires = now + Math.Min(e0, 86400 * 30); // remaining seconds
                        }
                        int kind = 0;
                        if (r.TryGetProperty("verdict", out var vdEl) && vdEl.TryGetInt32(out var v0))
                            kind = Math.Clamp(v0, 0, 2);

                        blocks.Add(new BlockRecord
                        {
                            Ip = ip,
                            User = Sanitize.SingleLine(r.TryGetProperty("user", out var uEl) ? uEl.GetString() ?? "" : "", 63),
                            Reason = reason.Length > 0 ? reason : "migrated",
                            Stage = stage,
                            Attempts = att,
                            Kind = kind,
                            Permanent = stage >= 4 && expires == 0,
                            ExpiresAt = expires,
                            BlockedAt = now,
                        });
                    }
                    any |= blocks.Count > 0;
                }
            }
            catch (Exception ex)
            {
                Log.Warn($"legacy rule.json unreadable - skipping ({ex.Message})");
            }
        }

        // ---- state.dat: totals, blocks, tracked, event history ---------------
        string statePath = System.IO.Path.Combine(dir, "state.dat");
        if (File.Exists(statePath))
        {
            try
            {
                string section = "";
                long stBlocks = 0;
                long seenFailures = 0;
                var runFail = new Dictionary<string, int>(StringComparer.Ordinal);
                var today = DateTime.Today;

                foreach (var raw in File.ReadAllLines(statePath, Encoding.UTF8))
                {
                    string line = raw.Trim();
                    if (line.Length == 0) continue;
                    if (line[0] == '[')
                    {
                        section = line.Trim('[', ']').ToUpperInvariant();
                        continue;
                    }

                    if (section == "STATS")
                    {
                        int eq = line.IndexOf('=');
                        if (eq <= 0) continue;
                        string k = line[..eq].Trim(), v = line[(eq + 1)..].Trim();
                        if (k == "blocks_total" && long.TryParse(v, out var bt)) stBlocks = Math.Max(0, bt);
                    }
                    else if (section == "BLOCKS")
                    {
                        var p = line.Split('|');
                        if (p.Length >= 1 && Net.TryParseIpv4(p[0], out _))
                        {
                            string ip = p[0];
                            string user = p.Length > 1 && !int.TryParse(p[1], out _) ? p[1] : "";
                            int stage = p.Length > 2 && int.TryParse(p[2], out var sg) ? Math.Clamp(sg, 1, 4) : 1;
                            ushort att = p.Length > 3 && ushort.TryParse(p[3], out var at) ? at : (ushort)0;
                            long exp = 0;
                            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                            if (p.Length > 4 && long.TryParse(p[4], out var ev))
                                exp = ev >= 1_000_000_000 ? ev : (ev > 0 ? now + Math.Min(ev, 86400L * 30) : 0);
                            string reason = p.Length > 5 ? string.Join('|', p.Skip(5)) : "";
                            blocks.Add(new BlockRecord
                            {
                                Ip = ip,
                                User = Sanitize.SingleLine(user, 63),
                                Reason = Sanitize.SingleLine(reason, 60) is { Length: > 0 } rr ? rr : "migrated",
                                Stage = stage,
                                Attempts = att,
                                Kind = 0,
                                Permanent = stage >= 4 && exp == 0,
                                ExpiresAt = exp,
                                BlockedAt = now,
                            });
                        }
                    }
                    else if (section == "TRACKED")
                    {
                        var p = line.Split('|');
                        if (p.Length >= 4 && Net.TryParseIpv4(p[0], out _))
                        {
                            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                            tracked.Add(new TrackedRecord
                            {
                                Ip = p[0],
                                Failures = int.TryParse(p[1], out var f) ? Math.Max(0, f) : 0,
                                Stage = int.TryParse(p[2], out var s) ? Math.Clamp(s, 0, 4) : 0,
                                HasReal = p[3] == "1",
                                FirstSeen = now,
                                LastSeen = now,
                            });
                        }
                    }
                    else if (section == "EVENTS")
                    {
                        // HH:mm:ss|ip|user|substatus|kind|flag
                        var p = line.Split('|');
                        if (p.Length >= 6 && Net.TryParseIpv4(p[1], out _))
                        {
                            long ts;
                            try
                            {
                                var tod = TimeSpan.ParseExact(p[0], "hh\\:mm\\:ss",
                                    System.Globalization.CultureInfo.InvariantCulture);
                                // The old file stored time-of-day only; anchor to
                                // today's (local) date so the history shows up.
                                ts = new DateTimeOffset(today.Add(tod), TimeZoneInfo.Local.GetUtcOffset(today))
                                    .ToUnixTimeSeconds();
                            }
                            catch { ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds(); }

                            string sub = Sanitize.SingleLine(p[3], 20);
                            bool success = sub.Length == 0 || sub == "0x0";
                            if (!success)
                            {
                                seenFailures++;
                                runFail[p[1]] = runFail.TryGetValue(p[1], out var c) ? c + 1 : 1;
                            }
                            int kind = int.TryParse(p[4], out var kd) ? Math.Clamp(kd, 0, 2) : 0;
                            attempts.Add(new AttemptRecord
                            {
                                Ts = ts,
                                Ip = p[1],
                                User = Sanitize.SingleLine(p[2], 63),
                                Sub = sub,
                                Kind = kind,
                                Blocked = p[5] == "1",
                                Allowed = false,
                                Success = success,
                                Failures = runFail.GetValueOrDefault(p[1]),
                                LogonType = 10, // remote - the old source only watched RDP
                            });
                        }
                    }
                }

                if (stBlocks > 0 || tracked.Count > 0 || attempts.Count > 0)
                {
                    totalBlocks = stBlocks;
                    totalFailures = seenFailures;
                    any = true;
                }
            }
            catch (Exception ex)
            {
                Log.Warn($"legacy state.dat unreadable - skipping ({ex.Message})");
            }
        }

        // ---- allowlist key from the old config.ini ---------------------------
        if (!string.IsNullOrWhiteSpace(cfg.LegacyAllowlist))
        {
            foreach (var tok in cfg.LegacyAllowlist.Split(new[] { ',', ';', ' ' },
                         StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (Net.TryParseCidr(tok, out string ip, out int prefix))
                    whitelist.Add((ip, prefix));
            }
            any |= whitelist.Count > 0;
        }

        if (!any) return;

        store.ImportLegacy(blocks, tracked, attempts, whitelist, totalBlocks, totalFailures);
        store.Flush(force: true);
        Log.Info($"legacy import: {blocks.Count} block(s), {tracked.Count} tracked address(es), " +
                 $"{attempts.Count} feed event(s), {whitelist.Count} allowlist entr(ies)" +
                 (totalBlocks > 0 ? $", {totalBlocks} lifetime block(s)" : ""));

        // Rename so a wiped db.json never silently re-imports stale blocks.
        TryMigrate(statePath);
        TryMigrate(rulePath);
    }

    private static void TryMigrate(string path)
    {
        try
        {
            if (File.Exists(path)) File.Move(path, path + ".migrated", overwrite: true);
        }
        catch (Exception ex)
        {
            Log.Warn($"could not rename {System.IO.Path.GetFileName(path)} after import ({ex.Message})");
        }
    }
}
