using System.Net;
using System.Net.Http;
using System.Text.Json;

namespace V3Guard;

/// <summary>
/// IP threat intelligence, mirroring the honeypot pipeline: AbuseIPDB for the
/// score/ISP/country, one ip-api call for geo, DroneBL DNSBL. Results are
/// cached in reputation.json so a repeat lookup never touches the network.
/// API key is from env NPAV_ABUSEIPDB_KEY (never in binary). Without it,
/// AbuseIPDB is skipped and the score falls back to DNSBL+geo.
/// </summary>
public static class Reputation
{
    private static readonly string AbuseIpDbKey =
        Environment.GetEnvironmentVariable("NPAV_ABUSEIPDB_KEY") ?? "";

    private static readonly HttpClient Client = CreateClient();

    private static HttpClient CreateClient()
    {
        var c = new HttpClient { Timeout = TimeSpan.FromSeconds(4) };
        try
        {
            c.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) NPavRDP/3.0");
            c.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        }
        catch { }
        return c;
    }

    private static bool IsPrivate(string ipStr)
    {
        if (!IPAddress.TryParse(ipStr, out var ip)) return false;
        if (IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal) return true;
        var b = ip.GetAddressBytes();
        if (b.Length != 4) return false;
        return b[0] == 10
            || (b[0] == 192 && b[1] == 168)
            || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
            || (b[0] == 169 && b[1] == 254)
            || b[0] == 127;
    }

    private static (bool listed, string info) CheckDnsbl(string ip)
    {
        var parts = ip.Split('.');
        if (parts.Length != 4) return (false, "");
        var reversed = $"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}";
        try
        {
            var addrs = Dns.GetHostAddresses($"{reversed}.dnsbl.dronebl.org");
            if (addrs.Length > 0) return (true, "DroneBL (Listed Bot/Exploit)");
        }
        catch { }
        return (false, "");
    }

    private static string S(JsonElement root, string name) =>
        root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static double D(JsonElement root, string name) =>
        root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetDouble() : 0;

    private static readonly object FlightGate = new();
    private static readonly HashSet<string> InFlight = new(StringComparer.Ordinal);
    private static readonly Dictionary<string, long> LastAttempt = new(StringComparer.Ordinal);
    // Global cap so 512 startup blocks don't spawn 512 simultaneous sockets.
    private static readonly SemaphoreSlim NetGate = new(8, 8);
    private const long RetrySeconds = 600;

    private static bool B(JsonElement root, string name) =>
        root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;

    private static (int score, int reports, string last, string isp, string country, bool ok)
        QueryAbuseIpDb(string ip)
    {
        if (string.IsNullOrEmpty(AbuseIpDbKey)) return (0, 0, "", "", "", false);
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get,
                $"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90");
            req.Headers.Add("Key", AbuseIpDbKey);
            req.Headers.Add("Accept", "application/json");
            using var resp = Client.Send(req);
            if (!resp.IsSuccessStatusCode) return (0, 0, "", "", "", false);
            using var doc = JsonDocument.Parse(resp.Content.ReadAsStream());
            var d = doc.RootElement.GetProperty("data");
            int score = d.GetProperty("abuseConfidenceScore").GetInt32();
            int reports = d.GetProperty("totalReports").GetInt32();
            string last = d.TryGetProperty("lastReportedAt", out var lr) ? lr.GetString() ?? "" : "";
            string isp = d.TryGetProperty("isp", out var ispp) ? ispp.GetString() ?? "" : "";
            string country = d.TryGetProperty("countryCode", out var cc) ? cc.GetString() ?? "" : "";
            return (score, reports, last, isp, country, true);
        }
        catch { return (0, 0, "", "", "", false); }
    }

    /// <summary>Single geo URL (ip-api, like the honeypot) + AbuseIPDB country.</summary>
    private static bool LookupGeo(string ip, ReputationRecord rep, string abuseIsp, string abuseCountry)
    {
        try
        {
            using var resp = Client.GetAsync(
                $"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,lat,lon,timezone,isp,org,as,proxy,hosting,query")
                .GetAwaiter().GetResult();
            if (resp.IsSuccessStatusCode)
            {
                using var doc = JsonDocument.Parse(resp.Content.ReadAsStream());
                var r = doc.RootElement;
                if (r.TryGetProperty("status", out var st) && st.GetString() == "success")
                {
                    rep.Country = S(r, "country");
                    rep.CountryCode = S(r, "countryCode");
                    rep.City = S(r, "city");
                    rep.Timezone = S(r, "timezone");
                    rep.Isp = S(r, "isp");
                    rep.Org = S(r, "org");
                    rep.As = S(r, "as");
                    rep.Lat = D(r, "lat");
                    rep.Lon = D(r, "lon");
                    rep.IsProxy = B(r, "proxy");
                    rep.IsHosting = B(r, "hosting");
                    if (rep.Lat != 0 || rep.Lon != 0) return true;
                }
            }
        }
        catch { }

        if (string.IsNullOrEmpty(rep.Country) && !string.IsNullOrEmpty(abuseCountry))
        {
            rep.Country = abuseCountry;
            rep.CountryCode = abuseCountry;
        }
        if (string.IsNullOrEmpty(rep.Isp) && !string.IsNullOrEmpty(abuseIsp)) rep.Isp = abuseIsp;

        // Country centroid so a dot always appears when only the country is known.
        if (!string.IsNullOrEmpty(rep.CountryCode) &&
            Centroids.TryGetValue(rep.CountryCode.ToUpperInvariant(), out var c))
        {
            rep.Lat = c[0]; rep.Lon = c[1];
            return true;
        }
        return false;
    }

    public static ReputationRecord Get(Store store, string ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) ip = "";
        if (IsPrivate(ip))
        {
            return new ReputationRecord
            {
                Ip = ip,
                Country = "Local Network",
                City = "Localhost",
                Isp = "Private / Local Network",
                ThreatLevel = "Safe",
                RiskScore = 0,
                Source = "local",
                CachedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            };
        }

        // One network lookup per IP per RetrySeconds, even across threads.
        // Stops the log spam and the per-attempt API hammering.
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        lock (FlightGate)
        {
            var cached = store.FindReputation(ip);
            if (cached != null) return cached;
            if (InFlight.Contains(ip)) return store.FindReputation(ip) ?? Fallback(ip);
            if (LastAttempt.TryGetValue(ip, out var last) && now - last < RetrySeconds)
                return store.FindReputation(ip) ?? Fallback(ip);
            LastAttempt[ip] = now;
            InFlight.Add(ip);
        }

        bool netTaken = false;
        try
        {
            // Bounded network concurrency – callers use ThreadPool, so cap
            // simultaneous sockets to 8 instead of one-per-block.
            netTaken = NetGate.Wait(TimeSpan.FromSeconds(3));
            if (!netTaken) return Fallback(ip);
            var cached = store.FindReputation(ip);
            if (cached != null) return cached;

                bool isBlacklisted = false;
                string dnsblInfo = "";
                try
                {
                    var t = Task.Run(() => CheckDnsbl(ip));
                    if (t.Wait(TimeSpan.FromSeconds(2))) { (isBlacklisted, dnsblInfo) = t.Result; }
                }
                catch { }

                var (abuseScore, abuseReports, abuseLast, abuseIsp, abuseCountry, abuseOk) = QueryAbuseIpDb(ip);

            var rep = new ReputationRecord { Ip = ip };
            bool geoOk = LookupGeo(ip, rep, abuseIsp, abuseCountry);

            int score = abuseScore;
            if (isBlacklisted && score < 90) score = 95;
            if (rep.IsHosting && score < 50) score += 35;
            if (rep.IsProxy && score < 60) score += 40;
            if (score > 100) score = 100;
            if (score == 0 && abuseOk) score = 5;
            if (score == 0) score = 15;

            string threatLevel = "Low";
            if (score >= 75 || isBlacklisted) threatLevel = "Critical";
            else if (score >= 50) threatLevel = "High";
            else if (score >= 25) threatLevel = "Medium";

            rep.IsBlacklisted = isBlacklisted;
            rep.DnsblInfo = dnsblInfo;
            rep.AbuseScore = abuseScore;
            rep.AbuseReports = abuseReports;
            rep.AbuseLastReported = abuseLast;
            rep.RiskScore = score;
            rep.ThreatLevel = threatLevel;
            rep.Source = "AbuseIPDB + DNSBL + ip-api";
            rep.CachedAt = now;

            bool hasGeo = geoOk || rep.Lat != 0 || rep.Lon != 0;
            if (hasGeo)
            {
                store.SaveReputation(rep);
                lock (FlightGate) LastAttempt.Remove(ip);
            }

            Log.Info($"reputation {ip}: {rep.Country}/{rep.City} {rep.Lat},{rep.Lon} "
                   + $"isp='{rep.Isp}' abuse={abuseScore} risk={rep.RiskScore} {threatLevel}"
                   + (hasGeo ? "" : " (no geo)"));
            return rep;
        }
        finally
        {
            if (netTaken) NetGate.Release();
            lock (FlightGate) InFlight.Remove(ip);
        }
    }

    private static ReputationRecord Fallback(string ip) => new()
    {
        Ip = ip,
        Country = "Unknown",
        City = "Unknown",
        ThreatLevel = "Medium",
        RiskScore = 30,
        Source = "pending",
        CachedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 82000,
    };

    private static readonly Dictionary<string, double[]> Centroids = new(StringComparer.OrdinalIgnoreCase)
    {
        ["US"] = [39.8, -98.6], ["CA"] = [56.1, -106.3], ["MX"] = [23.6, -102.6],
        ["BR"] = [-14.2, -51.9], ["AR"] = [-38.4, -63.6], ["CL"] = [-35.7, -71.5],
        ["CO"] = [4.6, -74.3], ["PE"] = [-9.2, -75.0], ["VE"] = [6.4, -66.6],
        ["GB"] = [55.4, -3.4], ["IE"] = [53.4, -8.2], ["FR"] = [46.2, 2.2],
        ["DE"] = [51.2, 10.5], ["NL"] = [52.1, 5.3], ["BE"] = [50.5, 4.5],
        ["ES"] = [40.5, -3.7], ["PT"] = [39.4, -8.2], ["IT"] = [41.9, 12.6],
        ["CH"] = [46.8, 8.2], ["AT"] = [47.5, 14.6], ["SE"] = [60.1, 18.6],
        ["NO"] = [60.5, 8.5], ["DK"] = [56.3, 9.5], ["FI"] = [61.9, 25.7],
        ["PL"] = [51.9, 19.1], ["CZ"] = [49.8, 15.5], ["SK"] = [48.7, 19.7],
        ["HU"] = [47.2, 19.5], ["RO"] = [45.9, 24.9], ["BG"] = [42.7, 25.5],
        ["GR"] = [39.1, 21.8], ["UA"] = [48.4, 31.2], ["RU"] = [61.5, 105.3],
        ["TR"] = [39.0, 35.2], ["IL"] = [31.0, 34.9], ["SA"] = [23.9, 45.1],
        ["AE"] = [23.4, 53.8], ["IR"] = [32.4, 53.7], ["IQ"] = [33.2, 43.7],
        ["PK"] = [30.4, 69.3], ["IN"] = [20.6, 79.0], ["BD"] = [23.7, 90.4],
        ["LK"] = [7.9, 80.8], ["NP"] = [28.4, 84.1], ["CN"] = [35.9, 104.2],
        ["HK"] = [22.3, 114.2], ["TW"] = [23.7, 121.0], ["JP"] = [36.2, 138.3],
        ["KR"] = [35.9, 127.8], ["TH"] = [15.9, 101.0], ["VN"] = [14.1, 108.3],
        ["MY"] = [4.2, 101.9], ["SG"] = [1.35, 103.8], ["ID"] = [-0.8, 113.9],
        ["PH"] = [12.9, 121.8], ["AU"] = [-25.3, 133.8], ["NZ"] = [-40.9, 174.9],
        ["ZA"] = [-30.6, 22.9], ["NG"] = [9.1, 8.7], ["KE"] = [-0.0, 37.9],
        ["EG"] = [26.8, 30.8], ["MA"] = [31.8, -7.1], ["DZ"] = [28.0, 1.7],
        ["TN"] = [33.9, 9.5], ["LY"] = [26.3, 17.2], ["GH"] = [7.9, -1.0],
        ["CI"] = [7.5, -5.5], ["SN"] = [14.5, -14.5], ["ET"] = [9.1, 40.5],
        ["TZ"] = [-6.4, 34.9], ["UG"] = [1.4, 32.3], ["ZW"] = [-19.0, 29.2],
        ["MZ"] = [-18.7, 35.5], ["AO"] = [-11.2, 17.9], ["CM"] = [7.4, 12.4],
    };
}