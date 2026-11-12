using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace V3Guard;

/// <summary>
/// Loopback dashboard. Bound to 127.0.0.1 only, and guarded by a random session
/// token generated at startup: without it, any web page the operator visits could
/// drive the guard through the browser. The token is embedded in the page URL that
/// is opened on launch.
/// </summary>
public sealed class Dashboard : IDisposable
{
    private readonly Store _store;
    private readonly AppSettings _cfg;
    private readonly PolicyEngine _policy;
    private readonly ToastHost _toast;
    private readonly Mailer _mail;
    private readonly EventLogSource _source;
    private readonly string _token;
    private string _askingCode = "";
    private HttpListener? _listener;
    private CancellationTokenSource? _cts;

    // ---- polled-JSON cache (byte[]) -------------------------------------
    // Every dashboard tab re-fetches its feeds every 3 s. Rebuilding eight JSON
    // payloads per tick each time costs real CPU; keyed by the store version,
    // an unchanged state is answered straight from cached UTF-8 bytes.
    // Caching bytes (not strings) avoids re-encoding the same payload on every
    // poll, and keeps the hot path allocation-free.

    private readonly Dictionary<string, (long V, byte[] B)> _pollCache = new(StringComparer.Ordinal);

    /// <summary>
    /// Answers a polling endpoint from the JSON cache when the store version
    /// has not changed: no snapshotting, no serialization, almost no CPU.
    /// `timeBucket` seconds re-verifies at least that often for endpoints that
    /// fold in readings which can move without a state change (system meters).
    /// </summary>
    private void ReplyPolled(HttpListenerContext ctx, string key, int timeBucket, Func<string> build)
    {
        long ver = _store.DataVersion;
        long tick = timeBucket > 0 ? DateTimeOffset.UtcNow.ToUnixTimeSeconds() / timeBucket : 0;
        string ck = key + (ctx.Request.Url?.Query ?? "");
        if (_pollCache.TryGetValue(ck, out var hit) && hit.V == ver + tick)
        {
            ReplyBytes(ctx, 200, "application/json", hit.B);
            return;
        }
        string body = build();
        byte[] bytes = Encoding.UTF8.GetBytes(body);
        if (_pollCache.Count > 32) _pollCache.Clear();
        _pollCache[ck] = (ver + tick, bytes);
        ReplyBytes(ctx, 200, "application/json", bytes);
    }

    // ---- system meters (cached, sampled every 5s) -------------------------
    // Process.Refresh() every 3s poll is expensive (kernel query). Cache the
    // values and recompute at most once every 5s; StatsJson then costs ~0.

    private System.Diagnostics.Process? _proc;
    private TimeSpan _procCpuTime = TimeSpan.Zero;
    private DateTime _procStamp = DateTime.UtcNow;
    private double _cachedRssMb, _cachedPrivMb, _cachedCpuPct;
    private DateTime _lastMeterUtc = DateTime.MinValue;
    private readonly object _meterGate = new();

    private void RefreshMeters()
    {
        var p = _proc ??= System.Diagnostics.Process.GetCurrentProcess();
        p.Refresh();
        var now = p.TotalProcessorTime;
        double secs = (DateTime.UtcNow - _procStamp).TotalSeconds;
        double pct = 0;
        if (secs > 0.5 && _procCpuTime != TimeSpan.Zero)
            pct = (now - _procCpuTime).TotalSeconds / secs / Math.Max(1, Environment.ProcessorCount) * 100.0;
        _procCpuTime = now;
        _procStamp = DateTime.UtcNow;
        _cachedRssMb = p.WorkingSet64 / (1024.0 * 1024.0);
        _cachedPrivMb = p.PrivateMemorySize64 / (1024.0 * 1024.0);
        _cachedCpuPct = pct;
        _lastMeterUtc = DateTime.UtcNow;
    }

    private void EnsureMeters()
    {
        if ((DateTime.UtcNow - _lastMeterUtc).TotalSeconds < 5) return;
        lock (_meterGate)
        {
            if ((DateTime.UtcNow - _lastMeterUtc).TotalSeconds >= 5)
                RefreshMeters();
        }
    }

    private double ProcRssMb() { EnsureMeters(); return _cachedRssMb; }
    private double ProcPrivMb() { EnsureMeters(); return _cachedPrivMb; }
    private double ProcCpuPct() { EnsureMeters(); return _cachedCpuPct; }


    /// <summary>
    /// Activation brute-force throttle. The activation key space plus the master
    /// password are small enough that an attacker with dashboard access could
    /// try unlimited guesses; after 5 failures from one address the endpoint
    /// goes into an escalating cooldown (30 s base, up to +2 min per repeat).
    /// In-memory only, resets on restart - the point is slowing down a script,
    /// not forensic tracking.
    /// </summary>
    private readonly object _authGate = new();
    private readonly Dictionary<string, (int Fails, DateTime Until)> _authFails = new(StringComparer.Ordinal);

    private string RemoteOf(HttpListenerContext ctx) =>
        ctx.Request.RemoteEndPoint?.Address.ToString() ?? "?";

    private (int Fails, DateTime Until) AuthState(HttpListenerContext ctx)
    {
        lock (_authGate)
        {
            if (_authFails.TryGetValue(RemoteOf(ctx), out var t) && t.Until > DateTime.UtcNow)
                return t;
            return (0, DateTime.MinValue);
        }
    }

    private void AuthNote(HttpListenerContext ctx, bool failed)
    {
        lock (_authGate)
        {
            string ip = RemoteOf(ctx);
            if (!failed) { _authFails.Remove(ip); return; }
            int f = _authFails.TryGetValue(ip, out var t) ? t.Fails + 1 : 1;
            DateTime until = f >= 5
                ? DateTime.UtcNow.AddSeconds(30 + Math.Min(120, (f - 5) * 10))
                : DateTime.MinValue;
            if (f >= 5) Log.Warn($"dashboard auth: {f} failed activation tries from {ip} - throttling");
            _authFails[ip] = (f, until);
        }
    }

    private static string GuardMsg((int Fails, DateTime Until) t)
    {
        int left = Math.Max(1, (int)Math.Ceiling((t.Until - DateTime.UtcNow).TotalSeconds));
        return $"too many failed attempts - try again in {left}s";
    }

    public Dashboard(Store store, AppSettings cfg, PolicyEngine policy, ToastHost toast, Mailer mail, EventLogSource source)
    {
        _store = store;
        _cfg = cfg;
        _policy = policy;
        _toast = toast;
        _mail = mail;
        _source = source;
        _token = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
    }

    public string Token => _token;

    public void Start()
    {
        _cts = new CancellationTokenSource();
        var token = _cts.Token;

        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://127.0.0.1:{_cfg.DashboardPort}/");
        try
        {
            _listener.Start();
        }
        catch (Exception ex)
        {
            Log.Error($"dashboard bind failed on port {_cfg.DashboardPort}: {ex.Message}");
            return;
        }

        // Never log the token – truncate for operator identification only.
        Log.Info($"dashboard: http://127.0.0.1:{_cfg.DashboardPort}/#t=<token:{_token.AsSpan(0, 8)}...>");
        _ = Task.Run(() => AcceptLoop(token), token);
    }

    private async Task AcceptLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener?.IsListening == true)
        {
            HttpListenerContext ctx;
            try
            {
                ctx = await _listener.GetContextAsync().ConfigureAwait(false);
            }
            catch
            {
                if (ct.IsCancellationRequested) return;
                await Task.Delay(200).ConfigureAwait(false);
                continue;
            }

            _ = Task.Run(() =>
            {
                try { Handle(ctx); }
                catch (Exception ex) { Log.Warn($"http handler: {ex.Message}"); }
                finally
                {
                    try { ctx.Response.Close(); } catch { }
                }
            });
        }
    }

    private void Handle(HttpListenerContext ctx)
    {
        var req = ctx.Request;
        var path = req.Url?.AbsolutePath ?? "/";
        var method = req.HttpMethod;

        // Everything except the static shell requires the session token. The icon
        // must be exempt: browsers request /favicon.ico with no query string, so
        // guarding it returned 403 and the tab showed a broken image.
        if (path is not ("/" or "/index.html" or "/favicon.ico" or "/@1.ico"
                        or "/static/leaflet.js" or "/static/leaflet.css"
                        or "/app.js" or "/app.css"))
        {
            string supplied = req.QueryString["t"] ?? req.Headers["X-Guard-Token"] ?? "";
            if (!CryptographicEquals(supplied, _token))
            {
                Reply(ctx, 403, "text/plain", "forbidden");
                return;
            }
        }

        switch (path)
        {
            case "/":
            case "/index.html":
                if (!License.IsLicensed())
                    Reply(ctx, 200, "text/html; charset=utf-8", Ui.ActivationHtml(_token));
                else
                    Reply(ctx, 200, "text/html; charset=utf-8", Ui.Html(_token));
                return;

            case "/favicon.ico":
            case "/@1.ico":
            {
                // Served from the loose @1.ico beside the exe, so the browser tab
                // and the exe show the same branding. 204 when absent rather than a
                // 404, which keeps the console free of noise.
                var bytes = Brand.IconBytes();
                if (bytes is null) { Reply(ctx, 204, "image/x-icon", ""); return; }
                ReplyBytes(ctx, 200, "image/x-icon", bytes);
                return;
            }

            case "/static/leaflet.js":
            {
                var bytes = EmbeddedResource("leaflet.js");
                if (bytes is null) { Reply(ctx, 404, "text/plain", "missing"); return; }
                ReplyCached(ctx, "application/javascript; charset=utf-8", bytes);
                return;
            }

            case "/static/leaflet.css":
            {
                var bytes = EmbeddedResource("leaflet.css");
                if (bytes is null) { Reply(ctx, 404, "text/plain", "missing"); return; }
                ReplyCached(ctx, "text/css; charset=utf-8", bytes);
                return;
            }

            // Compiled Svelte dashboard bundle (SvelteProject/www). The token
            // check above is bypassed because these files carry no secrets:
            // the session token is fetched from window.GUARD_TOKEN injected
            // into the boot page, and every /api/* call stays guarded.
            case "/app.js":
            {
                var bytes = EmbeddedResource("app.js");
                if (bytes is null) { Reply(ctx, 404, "text/plain", "missing"); return; }
                ReplyCached(ctx, "application/javascript; charset=utf-8", bytes);
                return;
            }

            case "/app.css":
            {
                var bytes = EmbeddedResource("app.css");
                if (bytes is null) { Reply(ctx, 404, "text/plain", "missing"); return; }
                ReplyCached(ctx, "text/css; charset=utf-8", bytes);
                return;
            }

            case "/api/stats":
                ReplyPolled(ctx, "s", 4, StatsJson);
                return;

            case "/api/blocked":
                ReplyPolled(ctx, "b", 0, () =>
                    Json.Serialize(_store.BlocksSnapshot(), V3JsonContext.Default.BlockRecordArray));
                return;

            case "/api/whitelist":
                ReplyPolled(ctx, "w", 0, () =>
                    Json.Serialize(_store.WhitelistSnapshot(), V3JsonContext.Default.WhitelistRecordArray));
                return;

            case "/api/tracked":
                ReplyPolled(ctx, "t", 0, () =>
                    Json.Serialize(_store.TrackedSnapshot(), V3JsonContext.Default.TrackedRecordArray));
                return;

            case "/api/chart":
                ReplyPolled(ctx, "c", 0, ChartJson);
                return;

            case "/api/attempts":
                ReplyPolled(ctx, "a", 0, AttemptsJson);
                return;

            case "/api/top":
                ReplyPolled(ctx, "r", 0, TopJson);
                return;

            case "/api/daily":
                ReplyPolled(ctx, "d", 0, DailyJson);
                return;

            // Day drill-down behind the date-wise report (Svelte modal).
            case "/api/day":
                ReplyPolled(ctx, "dd", 0, () => DayJson(req.QueryString["day"] ?? ""));
                return;

            // Finished blocks (expired or released), newest first.
            case "/api/blockhistory":
                ReplyPolled(ctx, "bh", 0, () =>
                    Json.Serialize(_store.BlockHistorySnapshot(200), V3JsonContext.Default.BlockRecordArray));
                return;

            case "/api/settings":
                if (method == "POST")
                {
                    WithBody(req, body => ApplySettings(body), ctx);
                    return;
                }
                Reply(ctx, 200, "application/json", SettingsJson());
                return;

            case "/api/export":
                Reply(ctx, 200, "text/csv; charset=utf-8", ExportCsv());
                return;

            case "/api/allow":
                if (method != "POST") break;
                WithBody(req, body =>
                {
                    string ip = Field(body, "ip");
                    if (!Net.TryParseIpv4(ip, out _)) return "invalid ip";
                    // Whitelisting should also lift any block already in force,
                    // otherwise the address stays filtered while claiming trusted.
                    if (_store.FindBlock(ip) is not null)
                    {
                        _store.RemoveBlock(ip);
                        Wfp.Unblock(ip);
                    }
                    return _store.AddWhitelist(ip, Sanitize.Note(Field(body, "note")))
                        ? "allowed" : "already whitelisted";
                }, ctx);
                return;

            case "/api/block":
                if (method != "POST") break;
                WithBody(req, body =>
                {
                    string ip = Field(body, "ip");
                    if (!Net.TryParseIpv4(ip, out _)) return "invalid ip";
                    if (_store.FindBlock(ip) is not null) return "already blocked";
                    var ports = ResolvePorts(Field(body, "port"));
                    bool ok = true;
                    foreach (var p in ports) if (!Wfp.Block(ip, p, out _)) ok = false;
                    if (!ok) return "wfp refused the filter";
                    _store.AddBlock(new BlockRecord
                    {
                        Ip = ip,
                        User = Sanitize.SingleLine(Field(body, "user"), 63),
                        Reason = Sanitize.SingleLine(Field(body, "reason"), 60) is { Length: > 0 } r
                            ? r : "operator",
                        Stage = (int)Stage.Permanent,
                        Permanent = true,
                        BlockedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                        Port = ports.Count == 1 ? ports[0] : 0,
                    });
                    Log.Block(ip, "operator", "manual", "permanent");
                    _store.Flush(force: true);
                    ThreadPool.QueueUserWorkItem(_ => { try { Reputation.Get(_store, ip); } catch { } });
                    return "blocked";
                }, ctx);
                return;

            case "/api/clear":
                if (method != "POST") break;
                WithBody(req, _ =>
                {
                    foreach (var b in _store.BlocksSnapshot()) Wfp.Unblock(b.Ip);
                    _store.RemoveAllBlocks();
                    _store.Flush(force: true);
                    return "all blocks released";
                }, ctx);
                return;

            case "/api/unblock":
                if (method != "POST") break;
                WithBody(req, body =>
                {
                    string ip = Field(body, "ip");
                    if (!Net.TryParseIpv4(ip, out _)) return "invalid ip";
                    if (!_store.RemoveBlock(ip)) return "not blocked";
                    Wfp.Unblock(ip);
                    Log.Unblock(ip, "manual release");
                    _toast.Notify(NoticeKind.Released, "Address released", ip, "Block removed by operator", "", "#2f9e6f");
                    _store.Flush(force: true);
                    return "released";
                }, ctx);
                return;

            case "/api/whitelist/add":
                if (method != "POST") break;
                WithBody(req, body =>
                {
                    string cidr = Field(body, "cidr");
                    string note = Field(body, "note");
                    return _store.AddWhitelist(cidr, note) ? "added" : "invalid or duplicate";
                }, ctx);
                return;

            case "/api/whitelist/remove":
                if (method != "POST") break;
                WithBody(req, body =>
                {
                    string cidr = Field(body, "cidr");
                    if (!Net.TryParseCidr(cidr, out string ip, out int prefix)) return "invalid";
                    return _store.RemoveWhitelist(ip, prefix) ? "removed" : "not found";
                }, ctx);
                return;

            case "/api/manual":
                if (method != "POST") break;
                WithBody(req, body =>
                {
                    string ip = Field(body, "ip");
                    if (!Net.TryParseIpv4(ip, out _)) return "invalid ip";
                    if (_store.FindBlock(ip) is not null) return "already blocked";
                    var ports = ResolvePorts(Field(body, "port"));
                    var rec = new BlockRecord
                    {
                        Ip = ip,
                        User = "operator",
                        Reason = Sanitize.SingleLine(Field(body, "reason"), 60),
                        Stage = (int)Stage.Permanent,
                        Permanent = true,
                        BlockedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                        Port = ports.Count == 1 ? ports[0] : 0,
                    };
                    bool ok = true;
                    foreach (var p in ports) if (!Wfp.Block(ip, p, out _)) ok = false;
                    if (!ok) return "wfp refused the filter";
                    _store.AddBlock(rec);
                    _store.Flush(force: true);
                    ThreadPool.QueueUserWorkItem(_ => { try { Reputation.Get(_store, ip); } catch { } });
                    return "blocked";
                }, ctx);
                return;

            case "/api/whitelist-block":
                if (method != "POST") break;
                WithBody(req, body =>
                {
                    if (!_store.RemoveBlock(Field(body, "ip"))) return "not blocked";
                    Wfp.Unblock(Field(body, "ip"));
                    return "cleared";
                }, ctx);
                return;

            case "/api/mail/test":
                if (method != "POST") break;
                WithBody(req, _ =>
                {
                    var r = _mail.Send($"[{Brand.ShortName}] Test notification",
                        "<div style='font-family:Segoe UI,sans-serif'>" +
                        $"<h2>{Brand.ProductName}</h2>" +
                        "<p>SMTP is configured correctly. Block alerts will be delivered here.</p></div>");
                    // The dashboard shows the reason, not just that it failed.
                    return r.Ok ? "sent" : $"{r.Summary}{(r.Hint.Length > 0 ? " - " + r.Hint : "")}";
                }, ctx);
                return;

            case "/api/rescan":
                Reply(ctx, 200, "text/plain", _source.IsHealthy ? "already running" : "starting");
                return;

            case "/api/reputation":
            {
                string ip = req.QueryString["ip"] ?? "";
                if (!Net.TryParseIpv4(ip, out _)) { Reply(ctx, 400, "text/plain", "invalid ip"); return; }
                var rep = Reputation.Get(_store, ip);
                // serialize manually
                var sb = new System.Text.StringBuilder(512);
                sb.Append("{\"ip\":\"").Append(Esc(rep.Ip))
                  .Append("\",\"country\":\"").Append(Esc(rep.Country))
                  .Append("\",\"countryCode\":\"").Append(Esc(rep.CountryCode))
                  .Append("\",\"city\":\"").Append(Esc(rep.City))
                  .Append("\",\"lat\":").Append(rep.Lat.ToString(System.Globalization.CultureInfo.InvariantCulture))
                  .Append(",\"lon\":").Append(rep.Lon.ToString(System.Globalization.CultureInfo.InvariantCulture))
                  .Append(",\"isp\":\"").Append(Esc(rep.Isp))
                  .Append("\",\"org\":\"").Append(Esc(rep.Org))
                  .Append("\",\"proxy\":").Append(rep.IsProxy ? "true" : "false")
                  .Append(",\"hosting\":").Append(rep.IsHosting ? "true" : "false")
                  .Append(",\"blacklisted\":").Append(rep.IsBlacklisted ? "true" : "false")
                  .Append(",\"dnsbl\":\"").Append(Esc(rep.DnsblInfo))
                  .Append("\",\"abuseScore\":").Append(rep.AbuseScore)
                  .Append(",\"abuseReports\":").Append(rep.AbuseReports)
                  .Append(",\"riskScore\":").Append(rep.RiskScore)
                  .Append(",\"threatLevel\":\"").Append(Esc(rep.ThreatLevel))
                  .Append("\",\"timezone\":\"").Append(Esc(rep.Timezone))
                  .Append("\"}");
                Reply(ctx, 200, "application/json", sb.ToString());
                return;
            }

            case "/api/threatmap":
            {
                var sb = new System.Text.StringBuilder(4096);
                sb.Append('[');
                bool first = true;
                // include blocked + tracked IPs
                var ips = new HashSet<string>(StringComparer.Ordinal);
                foreach (var b in _store.BlocksSnapshot()) ips.Add(b.Ip);
                foreach (var t in _store.TrackedSnapshot()) if (t.Failures > 0) ips.Add(t.Ip);
                foreach (var ip in ips)
                {
                    // Use the cache; if this IP has not been resolved yet, kick a
                    // background lookup so the next poll can plot it.
                    var rep = _store.FindReputation(ip);
                    if (rep == null)
                    {
                        string lookupIp = ip;
                        ThreadPool.QueueUserWorkItem(_ =>
                        {
                            try { Reputation.Get(_store, lookupIp); } catch { }
                        });
                        continue;
                    }
                    if (rep.Lat == 0 && rep.Lon == 0) continue;
                    if (!first) sb.Append(',');
                    first = false;
                    sb.Append("{\"ip\":\"").Append(Esc(rep.Ip))
                      .Append("\",\"lat\":").Append(rep.Lat.ToString(System.Globalization.CultureInfo.InvariantCulture))
                      .Append(",\"lon\":").Append(rep.Lon.ToString(System.Globalization.CultureInfo.InvariantCulture))
                      .Append(",\"risk\":").Append(rep.RiskScore)
                      .Append(",\"threat\":\"").Append(Esc(rep.ThreatLevel))
                      .Append("\",\"country\":\"").Append(Esc(rep.Country))
                      .Append("\",\"cc\":\"").Append(Esc(rep.CountryCode))
                      .Append("\"}");
                }
                sb.Append(']');
                Reply(ctx, 200, "application/json", sb.ToString());
                return;
            }

            case "/api/activate/asking":
            {
                // POST asks for a fresh code (shuffle). Regenerating keeps the
                // activation and extend flows consistent: whichever code is
                // served last is the one the key must be derived from.
                if (method == "POST") _askingCode = License.GenerateAskingCode();
                if (string.IsNullOrEmpty(_askingCode)) _askingCode = License.GenerateAskingCode();
                Reply(ctx, 200, "application/json", "{\"asking\":\"" + _askingCode + "\"}");
                return;
            }

            case "/api/activate/verify":
                if (method != "POST") break;
            {
                var gt = AuthState(ctx);
                if (gt.Until > DateTime.UtcNow) { Reply(ctx, 429, "text/plain", GuardMsg(gt)); return; }
                WithBody(req, body =>
                {
                    string key = Field(body, "key");
                    if (string.IsNullOrEmpty(_askingCode)) _askingCode = License.GenerateAskingCode();
                    if (License.IsKeyAuthorized(key, _askingCode))
                    {
                        AuthNote(ctx, false);
                        License.SaveLicense();
                        _askingCode = "";
                        return "activated";
                    }
                    AuthNote(ctx, true);
                    return "invalid";
                }, ctx);
                return;
            }

            // License status for the dashboard: subscription badge + management
            // panel. Works even when unlicensed so the UI can explain why the
            // activation page is serving.
            case "/api/license":
            {
                var li = License.GetInfo();
                string status = !li.Signed ? (li.Tampered ? "tampered" : "missing")
                    : (li.Expiry > DateTime.UtcNow ? "valid" : "expired");
                int daysLeft = li.Signed ? Math.Max(0, (int)Math.Floor((li.Expiry - DateTime.UtcNow).TotalDays)) : 0;
                string ex = li.Expiry == DateTime.MinValue ? "" : li.Expiry.ToString("yyyy-MM-dd HH:mm 'UTC'");
                string at = li.ActivatedAt == DateTime.MinValue ? "" : li.ActivatedAt.ToString("yyyy-MM-dd HH:mm 'UTC'");
                Reply(ctx, 200, "application/json",
                    "{\"licensed\":" + (li.Valid ? "true" : "false")
                    + ",\"status\":\"" + status + "\""
                    + ",\"daysLeft\":" + daysLeft
                    + ",\"expiry\":\"" + Esc(ex) + "\""
                    + ",\"activatedAt\":\"" + Esc(at) + "\"}");
                return;
            }

            // Extend the subscription. Requires the derived key for the current
            // asking code or the master password, and a license file whose
            // signature still verifies - a hand-edited file cannot be revived.
            // Shares the same throttle as activation.
            case "/api/license/extend":
                if (method != "POST") break;
            {
                var gt = AuthState(ctx);
                if (gt.Until > DateTime.UtcNow) { Reply(ctx, 429, "text/plain", GuardMsg(gt)); return; }
                WithBody(req, body =>
                {
                    if (!int.TryParse(Field(body, "days"), out int days)) return "invalid days (1..3650)";
                    string key = Field(body, "key");
                    if (string.IsNullOrEmpty(_askingCode)) _askingCode = License.GenerateAskingCode();
                    string r = License.Extend(days, key, _askingCode);
                    AuthNote(ctx, !r.StartsWith("extended", StringComparison.OrdinalIgnoreCase));
                    return r;
                }, ctx);
                return;
            }
        }

        Reply(ctx, 404, "text/plain", "not found");
    }

    private string StatsJson()
    {
        _store.SnapshotCounts(out long failures, out long successes, out long blocks);
        var (uniqueIps, uniqueUsers) = _store.DistinctCounts();
        var blocksList = _store.BlocksSnapshot();

        // Built by hand rather than via JsonNode: reflection-based APIs are trimmed
        // away under NativeAOT, and this is a handful of scalar fields.
        return "{\"rdpPort\":" + _policy.RdpPort
             + ",\"detectedRdpPort\":" + Audit.DetectRdpPort()
             + ",\"blocked\":" + blocksList.Count
             + ",\"tracked\":" + _store.TrackedSnapshot().Count(t => t.Failures > 0)
             + ",\"whitelisted\":" + _store.WhitelistSnapshot().Count
             + ",\"failures\":" + failures
             + ",\"successes\":" + successes
             + ",\"blocks\":" + blocks
             + ",\"uniqueIps\":" + uniqueIps
             + ",\"uniqueUsers\":" + uniqueUsers
             + ",\"attempts\":" + _store.AttemptsSnapshot(1).Count
             + ",\"listening\":" + (_source.IsHealthy ? "true" : "false")
             + ",\"source\":\"" + Esc(_source.Name) + "\""
             + ",\"mailEnabled\":" + (_cfg.MailEnabled ? "true" : "false")
             + ",\"permanent\":" + blocksList.Count(b => b.Permanent)
             + ",\"toastSuppressed\":" + _toast.Suppressed
             + ",\"lastBlock\":" + (blocksList.Count > 0 ? blocksList.Max(b => b.BlockedAt).ToString() : "0")
             + ",\"filters\":" + Wfp.InstalledFilterCount
             + ",\"wfpOpen\":" + (Wfp.IsOpen ? "true" : "false")
             + ",\"procRss\":" + ProcRssMb().ToString("0.#", System.Globalization.CultureInfo.InvariantCulture)
             + ",\"procCpu\":" + Math.Clamp(ProcCpuPct(), 0, 800).ToString("0.#", System.Globalization.CultureInfo.InvariantCulture)
             + ",\"procPriv\":" + ProcPrivMb().ToString("0.#", System.Globalization.CultureInfo.InvariantCulture)
             + ",\"version\":\"3\"}";
    }

    private string ChartJson()
    {
        var sb = new System.Text.StringBuilder(4096);
        sb.Append('[');
        bool first = true;
        foreach (var d in _store.DailySeries(30))
        {
            if (!first) sb.Append(',');
            first = false;
            // Day labels are a fixed short format, so only the quotes need escaping.
            string day = DateTimeOffset.FromUnixTimeSeconds(d.Day).ToString("MMM d").Replace("\"", "");
            sb.Append($"{{\"day\":\"{day}\",\"failures\":{d.Failures},\"successes\":{d.Successes},\"blocks\":{d.Blocks}}}");
        }
        sb.Append(']');
        return sb.ToString();
    }

    /// <summary>
    /// Recent attempts, newest first. Built by hand rather than through the
    /// serializer: the payload is a flat list of scalars and hand-writing it
    /// avoids reflection and keeps the response small.
    /// </summary>
    private string AttemptsJson()
    {
        var rows = _store.AttemptsSnapshot(1000);
        var sb = new System.Text.StringBuilder(rows.Count * 96 + 16);
        sb.Append('[');
        for (int i = 0; i < rows.Count; i++)
        {
            var a = rows[i];
            if (i > 0) sb.Append(',');
            sb.Append("{\"ts\":").Append(a.Ts)
              .Append(",\"ip\":\"").Append(Esc(a.Ip))
              .Append("\",\"user\":\"").Append(Esc(a.User))
              .Append("\",\"sub\":\"").Append(Esc(a.Sub))
              .Append("\",\"kind\":").Append(a.Kind)
              .Append(",\"blocked\":").Append(a.Blocked ? "true" : "false")
              .Append(",\"allowed\":").Append(a.Allowed ? "true" : "false")
              .Append(",\"ok\":").Append(a.Success ? "true" : "false")
              .Append(",\"fails\":").Append(a.Failures)
              .Append(",\"lt\":").Append(a.LogonType)
              .Append('}');
        }
        sb.Append(']');
        return sb.ToString();
    }

    private string TopJson()
    {
        var (ips, users) = _store.TopTalkers(10);
        var countries = _store.CountryStats(8);
        var sb = new System.Text.StringBuilder(1536);
        sb.Append("{\"ips\":");
        AppendRank(sb, ips);
        sb.Append(",\"users\":");
        AppendRank(sb, users);
        sb.Append(",\"countries\":[");
        bool fc = true;
        foreach (var (cc, name, n) in countries)
        {
            if (!fc) sb.Append(',');
            fc = false;
            sb.Append("{\"cc\":\"").Append(cc == "?" ? "" : Esc(cc))
              .Append("\",\"name\":\"").Append(Esc(name))
              .Append("\",\"n\":").Append(n).Append('}');
        }
        sb.Append("]}");
        return sb.ToString();
    }

    /// <summary>
    /// Day drill-down behind the date-wise report: everything the retained feed
    /// holds for one UTC day - per-IP and per-username try counts plus the raw
    /// event rows. The authoritative day totals come from the persisted daily
    /// counters, which survive restarts and feed trimming.
    /// </summary>
    private string DayJson(string dayQs)
    {
        if (!long.TryParse(dayQs, out long day) || day <= 0)
            return "{\"error\":\"bad day\"}";
        long from = day - day % 86400;
        long to = from + 86400;

        var (_, dFail, dOk, dBlocks) = _store.DailyFor(from);
        var rows = _store.AttemptsInWindow(from, to);
        var dayBlocks = _store.BlocksSnapshot()
            .Where(b => b.BlockedAt >= from && b.BlockedAt < to)
            .OrderByDescending(b => b.BlockedAt)
            .ToList();

        // Per-IP / per-username breakdown. The persisted day histogram is
        // authoritative (it covers the whole day even when the live feed has
        // been trimmed); the feed-derived lists are only a fallback for days
        // recorded before histograms existed.
        var agg = _store.DayAggFor(from);
        List<(string K, int Tries, int Fails, int Ok)> ipList;
        List<(string K, int Tries, int Fails, int Ok)> userList;
        if (agg is not null)
        {
            ipList = agg.Ips.OrderByDescending(k => k.N).ThenBy(k => k.K, StringComparer.Ordinal)
                .Take(40).Select(k => (k.K, k.N, k.Fails, k.N - k.Fails)).ToList();
            userList = agg.Users.OrderByDescending(k => k.N).ThenBy(k => k.K, StringComparer.Ordinal)
                .Take(40).Select(k => (k.K, k.N, k.Fails, k.N - k.Fails)).ToList();
        }
        else
        {
            var ipTries = new Dictionary<string, (int Tries, int Fails, int Ok)>(StringComparer.Ordinal);
            var userTries = new Dictionary<string, (int Tries, int Fails, int Ok)>(StringComparer.Ordinal);
            foreach (var a in rows)
            {
                var ti = ipTries.TryGetValue(a.Ip, out var x) ? x : (0, 0, 0);
                ipTries[a.Ip] = (ti.Item1 + 1, ti.Item2 + (a.Success ? 0 : 1), ti.Item3 + (a.Success ? 1 : 0));
                var tu = userTries.TryGetValue(a.User, out var u) ? u : (0, 0, 0);
                userTries[a.User] = (tu.Item1 + 1, tu.Item2 + (a.Success ? 0 : 1), tu.Item3 + (a.Success ? 1 : 0));
            }
            ipList = ipTries.OrderByDescending(kv => kv.Value.Item1).ThenBy(kv => kv.Key, StringComparer.Ordinal)
                .Take(40).Select(kv => (kv.Key, kv.Value.Item1, kv.Value.Item2, kv.Value.Item3)).ToList();
            userList = userTries.OrderByDescending(kv => kv.Value.Item1).ThenBy(kv => kv.Key, StringComparer.Ordinal)
                .Take(40).Select(kv => (kv.Key, kv.Value.Item1, kv.Value.Item2, kv.Value.Item3)).ToList();
        }

        var sb = new System.Text.StringBuilder(4096);
        sb.Append("{\"day\":").Append(from)
          .Append(",\"fails\":").Append(dFail)
          .Append(",\"success\":").Append(dOk)
          .Append(",\"blocks\":").Append(dBlocks)
          .Append(",\"rowsTotal\":").Append(rows.Count)
          .Append(",\"ips\":[");
        bool f = true;
        foreach (var (ip, t1, t2, t3) in ipList)
        {
            if (!f) sb.Append(',');
            f = false;
            sb.Append("{\"ip\":\"").Append(Esc(ip)).Append("\",\"tries\":").Append(t1)
              .Append(",\"fails\":").Append(t2).Append(",\"ok\":").Append(t3).Append('}');
        }
        sb.Append("],\"users\":[");
        f = true;
        foreach (var (user, t1, t2, t3) in userList)
        {
            if (!f) sb.Append(',');
            f = false;
            sb.Append("{\"user\":\"").Append(Esc(user)).Append("\",\"tries\":").Append(t1)
              .Append(",\"fails\":").Append(t2).Append(",\"ok\":").Append(t3).Append('}');
        }
        sb.Append("],\"blocks\":[");
        f = true;
        foreach (var b in dayBlocks)
        {
            if (!f) sb.Append(',');
            f = false;
            sb.Append("{\"ip\":\"").Append(Esc(b.Ip)).Append("\",\"user\":\"").Append(Esc(b.User))
              .Append("\",\"permanent\":").Append(b.Permanent ? "true" : "false")
              .Append(",\"expiresAt\":").Append(b.ExpiresAt).Append('}');
        }
        sb.Append("],\"rows\":[");
        // raw event rows, newest first, capped so the modal stays light
        var capped = rows.OrderByDescending(a => a.Ts).Take(200).ToList();
        f = true;
        foreach (var a in capped)
        {
            if (!f) sb.Append(',');
            f = false;
            sb.Append("{\"ts\":").Append(a.Ts)
              .Append(",\"ip\":\"").Append(Esc(a.Ip))
              .Append("\",\"user\":\"").Append(Esc(a.User))
              .Append("\",\"sub\":\"").Append(Esc(a.Sub))
              .Append("\",\"ok\":").Append(a.Success ? "true" : "false")
              .Append(",\"blocked\":").Append(a.Blocked ? "true" : "false")
              .Append('}');
        }
        sb.Append("]}");
        return sb.ToString();
    }

    /// <summary>Date-wise report, newest day first.</summary>
    private string DailyJson()
    {
        var rows = _store.DailyReport(30);
        var sb = new System.Text.StringBuilder(rows.Count * 96 + 16);
        sb.Append('[');
        for (int i = 0; i < rows.Count; i++)
        {
            var d = rows[i];
            if (i > 0) sb.Append(',');
            sb.Append("{\"day\":").Append(d.Day)
              .Append(",\"fails\":").Append(d.Failures)
              .Append(",\"ok\":").Append(d.Successes)
              .Append(",\"blocks\":").Append(d.Blocks)
              .Append(",\"ips\":").Append(d.UniqueIps)
              .Append(",\"users\":").Append(d.UniqueUsers)
              .Append('}');
        }
        sb.Append(']');
        return sb.ToString();
    }

    // ---- settings -----------------------------------------------------------

    /// <summary>Current detection settings, for the dashboard form.</summary>
    private string SettingsJson()
    {
        int I(int v) => v;
        return "{\"real_user_fails\":" + I(_cfg.RealUserFails)
             + ",\"nonreal_user_fails\":" + I(_cfg.NonRealUserFails)
             + ",\"disabled_fails\":" + I(_cfg.DisabledFails)
             + ",\"real_user_window_s\":" + I(_cfg.RealUserWindowSeconds)
             + ",\"nonreal_user_window_s\":" + I(_cfg.NonRealUserWindowSeconds)
             + ",\"stage1_secs\":" + I(_cfg.Stage1Seconds)
             + ",\"stage2_secs\":" + I(_cfg.Stage2Seconds)
             + ",\"stage3_secs\":" + I(_cfg.Stage3Seconds)
             + ",\"stage4_perm\":" + (_cfg.Stage4Permanent ? "true" : "false")
             + ",\"toast_enabled\":" + (_cfg.ToastEnabled ? "true" : "false")
             + ",\"toast_cooldown_s\":" + I(_cfg.ToastCooldownSeconds)
             + ",\"toast_min_gap_s\":" + I(_cfg.ToastMinGapSeconds)
             + ",\"toast_display_s\":" + I(_cfg.ToastDisplaySeconds)
             + ",\"audit_reassert_s\":" + I(_cfg.AuditReassertSeconds)
             + ",\"max_attempts\":" + I(_cfg.MaxAttempts)
             + ",\"log_retention_days\":" + I(_cfg.RetentionDays)
+ ",\"rdp_port\":" + I(_cfg.RdpPort)
              + ",\"auto_detect_rdp\":" + (_cfg.AutoDetectRdp ? "true" : "false")
              + ",\"protected_ports\":\"" + Esc(_cfg.ProtectedPorts) + "\""
              + ",\"auto_block_permanent\":" + (_cfg.AutoBlockPermanent ? "true" : "false")
             + ",\"dashboard_port\":" + I(_cfg.DashboardPort)
             + ",\"email_enabled\":" + (_cfg.MailEnabled ? "true" : "false")
             + ",\"smtp_host\":\"" + Esc(_cfg.SmtpHost) + "\""
             + ",\"smtp_port\":" + I(_cfg.SmtpPort)
             + ",\"smtp_user\":\"" + Esc(_cfg.SmtpUser) + "\""
             + ",\"smtp_pass\":\"" + (!string.IsNullOrEmpty(_cfg.SmtpPassword) ? "***" : "") + "\""
             + ",\"smtp_tls\":" + (_cfg.SmtpTls ? "true" : "false")
             + ",\"email_from\":\"" + Esc(_cfg.MailFrom) + "\""
             + ",\"email_to\":\"" + Esc(_cfg.MailTo) + "\""
             + ",\"email_cc\":\"" + Esc(_cfg.MailCc) + "\""
             + ",\"email_bcc\":\"" + Esc(_cfg.MailBcc) + "\"}";
    }

    /// <summary>
    /// Applies a settings form. Rejects unknown keys rather than ignoring them, so
    /// a typo in a field name is reported instead of quietly doing nothing.
    /// </summary>
    private string ApplySettings(string body)
    {
        var applied = new List<string>();
        var rejected = new List<string>();

        foreach (var pair in body.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=');
            if (eq <= 0) continue;
            string key = Uri.UnescapeDataString(pair[..eq]);
            string val = Uri.UnescapeDataString(pair[(eq + 1)..].Replace("+", " "));

            // *** means "keep existing password" – never overwrite with mask.
            if (key == "smtp_pass" && val == "***") continue;

            if (Settings.ApplyKey(_cfg, key, val)) applied.Add(key);
            else rejected.Add(key);
        }

        if (applied.Count == 0) return rejected.Count > 0
            ? "no valid fields: " + string.Join(", ", rejected)
            : "nothing to save";

        // The feed limit may have been lowered, so trim before saving.
        _store.TrimAttempts();
        Settings.Save(_cfg);
        Log.Info($"settings updated via dashboard: {string.Join(", ", applied)}" +
                 (rejected.Count > 0 ? $" (rejected: {string.Join(", ", rejected)})" : ""));
        return $"saved {applied.Count} setting(s)";
    }

    /// <summary>The retained feed + block lists as CSV, for offline analysis.</summary>
    private string ExportCsv()
    {
        var rows = _store.AttemptsSnapshot(100000);
        var sb = new System.Text.StringBuilder(rows.Count * 80 + 256);
        sb.Append("timestamp,iso,ip,username,substatus,class,result,failures\r\n");
        foreach (var a in rows)
        {
            string cls = a.Success ? "success"
                : a.Kind switch { 0 => "real user", 1 => "unknown user", 2 => "disabled", _ => "?" };
            string result = a.Success ? "success" : a.Allowed ? "whitelisted" : a.Blocked ? "blocked" : "failed";
            sb.Append(a.Ts).Append(',')
              .Append(DateTimeOffset.FromUnixTimeSeconds(a.Ts).ToString("yyyy-MM-dd HH:mm:ss")).Append(',')
              .Append(Csv(a.Ip)).Append(',')
              .Append(Csv(a.User)).Append(',')
              .Append(Csv(a.Sub)).Append(',')
              .Append(cls).Append(',')
              .Append(result).Append(',')
              .Append(a.Failures).Append("\r\n");
        }

        sb.Append("\r\nactive_blocks,ip,username,reason,stage,attempts,permanent,expires,blocked_at,ports\r\n");
        foreach (var b in _store.BlocksSnapshot())
        {
            sb.Append(Csv(b.Ip)).Append(',')
              .Append(Csv(b.User)).Append(',')
              .Append(Csv(b.Reason)).Append(',')
              .Append(b.Stage).Append(',')
              .Append(b.Attempts).Append(',')
              .Append(b.Permanent ? "permanent" : "staged").Append(',')
              .Append(b.ExpiresAt > 0 ? DateTimeOffset.FromUnixTimeSeconds(b.ExpiresAt).ToString("yyyy-MM-dd HH:mm:ss") : "").Append(',')
              .Append(DateTimeOffset.FromUnixTimeSeconds(b.BlockedAt).ToString("yyyy-MM-dd HH:mm:ss")).Append(',')
              .Append(b.Port > 0 ? b.Port.ToString() : "all").Append("\r\n");
        }

        sb.Append("\r\nblock_history,ip,username,reason,attempts,permanent,expires,blocked_at,ended,ended_as\r\n");
        foreach (var b in _store.BlockHistorySnapshot(100000))
        {
            sb.Append(Csv(b.Ip)).Append(',')
              .Append(Csv(b.User)).Append(',')
              .Append(Csv(b.Reason)).Append(',')
              .Append(b.Attempts).Append(',')
              .Append(b.Permanent ? "permanent" : "staged").Append(',')
              .Append(b.ExpiresAt > 0 ? DateTimeOffset.FromUnixTimeSeconds(b.ExpiresAt).ToString("yyyy-MM-dd HH:mm:ss") : "").Append(',')
              .Append(b.BlockedAt > 0 ? DateTimeOffset.FromUnixTimeSeconds(b.BlockedAt).ToString("yyyy-MM-dd HH:mm:ss") : "").Append(',')
              .Append(b.ReleasedAt > 0 ? DateTimeOffset.FromUnixTimeSeconds(b.ReleasedAt).ToString("yyyy-MM-dd HH:mm:ss") : "").Append(',')
              .Append(b.Released ? "released" : "expired").Append("\r\n");
        }
        return sb.ToString();
    }

    // Embedded resources are immutable for the process lifetime – cache the
    // bytes and ETag once so /app.js (often 400KB+) is served without
    // re-reading the assembly and re-hashing on every request.
    private static readonly Dictionary<string, (byte[] Bytes, string Etag)> _resourceCache =
        new(StringComparer.OrdinalIgnoreCase);
    private static readonly object _resourceGate = new();

    private static byte[]? EmbeddedResource(string suffix)
    {
        lock (_resourceGate)
        {
            if (_resourceCache.TryGetValue(suffix, out var hit)) return hit.Bytes;
        }
        byte[]? bytes = null;
        try
        {
            var asm = System.Reflection.Assembly.GetExecutingAssembly();
            string? name = null;
            foreach (var n in asm.GetManifestResourceNames())
                if (n.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) { name = n; break; }
            if (name is not null)
            {
                using var s = asm.GetManifestResourceStream(name);
                if (s is not null)
                {
                    using var ms = new MemoryStream();
                    s.CopyTo(ms);
                    bytes = ms.ToArray();
                }
            }
        }
        catch { bytes = null; }
        if (bytes is not null)
        {
            string etag = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes))[..16];
            lock (_resourceGate) _resourceCache[suffix] = (bytes, etag);
        }
        return bytes;
    }

    private static string? ResourceEtag(string suffix)
    {
        lock (_resourceGate)
        {
            return _resourceCache.TryGetValue(suffix, out var hit) ? hit.Etag : null;
        }
    }

    private List<int> ResolvePorts(string portField)
    {
        var ports = new List<int>();
        if (int.TryParse(portField.Trim(), out var p) && p is >= 1 and <= 65535)
        {
            ports.Add(p);
            return ports;
        }
        // blank or invalid -> all protected ports
        return _cfg.ProtectedPortList();
    }

    private static string Csv(string s)
    {
        if (s.Length == 0) return "";
        bool quote = s.Contains(',') || s.Contains('"') || s.Contains('\n');
        string v = s.Replace("\"", "\"\"");
        return quote ? "\"" + v + "\"" : v;
    }

    private static void AppendRank(System.Text.StringBuilder sb, List<(string Key, int Count)> rows)
    {
        sb.Append('[');
        for (int i = 0; i < rows.Count; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append("{\"k\":\"").Append(Esc(rows[i].Key))
              .Append("\",\"n\":").Append(rows[i].Count).Append('}');
        }
        sb.Append(']');
    }

    /// <summary>Minimal JSON string escaping for values that reach the page.</summary>
    private static string Esc(string s)
    {
        if (s.Length == 0) return "";
        var sb = new System.Text.StringBuilder(s.Length + 8);
        foreach (char c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) sb.Append(' ');
                    else sb.Append(c);
                    break;
            }
        }
        return sb.ToString();
    }

    // ---- request helpers ---------------------------------------------------

    private static void WithBody(HttpListenerRequest req, Func<string, string> handler, HttpListenerContext ctx)
    {
        string body = "";
        try
        {
            using var reader = new StreamReader(req.InputStream, Encoding.UTF8);
            body = reader.ReadToEnd();
        }
        catch { }
        Reply(ctx, 200, "text/plain", handler(body));
    }

    private static string Field(string body, string key)
    {
        foreach (var pair in body.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=');
            if (eq <= 0) continue;
            if (pair[..eq] != key) continue;
            return Uri.UnescapeDataString(pair[(eq + 1)..].Replace("+", " "));
        }
        return "";
    }

    private static void Reply(HttpListenerContext ctx, int status, string contentType, string body)
    {
        var bytes = Encoding.UTF8.GetBytes(body);
        ReplyBytes(ctx, status, contentType, bytes);
    }

    /// <summary>Writes raw bytes. Uses ContentLength64 + KeepAlive so the
    /// browser can pipeline the 3s polls without a new TCP handshake each time.</summary>
    private static void ReplyBytes(HttpListenerContext ctx, int status, string contentType, byte[] bytes)
    {
        var res = ctx.Response;
        res.StatusCode = status;
        res.ContentType = contentType;
        res.ContentLength64 = bytes.Length;
        res.KeepAlive = true;
        res.SendChunked = false;
        res.Headers.Add("Cache-Control", "no-store");
        res.Headers.Add("X-Content-Type-Options", "nosniff");
        if (bytes.Length > 0) res.OutputStream.Write(bytes, 0, bytes.Length);
    }

    /// <summary>
    /// Static dashboard assets (app.js/app.css/leaflet). ETag is cached once
    /// per immutable resource (see EmbeddedResource) so no SHA256 is computed
    /// per request. Browser keeps a cached copy and only re-downloads when the
    /// build changed.
    /// </summary>
    private static string ResourceEtagForBytes(byte[] bytes)
    {
        // Fast-path: return the cached ETag for this exact byte[] instance.
        // We do not hash here – hashing 400KB on every request was the bottleneck.
        lock (_resourceGate)
        {
            foreach (var kv in _resourceCache)
                if (ReferenceEquals(kv.Value.Bytes, bytes)) return kv.Value.Etag;
        }
        // Not cached (first call or fallback) – compute once.
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes))[..16];
    }

    private static void ReplyCached(HttpListenerContext ctx, string contentType, byte[] bytes)
    {
        string etag = ResourceEtagForBytes(bytes);
        var res = ctx.Response;
        string? inm = ctx.Request.Headers["If-None-Match"];
        res.Headers.Add("ETag", "\"" + etag + "\"");
        res.Headers.Add("Cache-Control", "max-age=0, must-revalidate");
        res.Headers.Add("X-Content-Type-Options", "nosniff");
        if (inm != null && inm.Contains(etag))
        {
            res.StatusCode = 304;
            res.Headers.Add("Content-Length", "0");
            return;
        }
        res.StatusCode = 200;
        res.ContentType = contentType;
        res.ContentLength64 = bytes.Length;
        if (bytes.Length > 0) res.OutputStream.Write(bytes, 0, bytes.Length);
    }

    /// <summary>Constant-time compare so the token cannot be recovered by timing.</summary>
    private static bool CryptographicEquals(string a, string b)
    {
        if (a.Length != b.Length || a.Length == 0) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    public void Dispose()
    {
        try { _cts?.Cancel(); } catch { }
        try { _listener?.Stop(); _listener?.Close(); } catch { }
    }
}