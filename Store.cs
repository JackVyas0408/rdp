using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace V3Guard;

public sealed class BlockRecord
{
    public string Ip { get; set; } = "";
    public string User { get; set; } = "";
    public string Reason { get; set; } = "";
    public int Stage { get; set; }
    public ushort Attempts { get; set; }
    public int Kind { get; set; }
    public bool Permanent { get; set; }
    public long ExpiresAt { get; set; }
    public long BlockedAt { get; set; }
    /// <summary>
    /// The local port this address is blocked on. Blocks are port-scoped: the
    /// operator only ever asked for RDP to be filtered, and blocking every port
    /// for a source address could cut off unrelated legitimate traffic.
    /// Persisted so a restart re-installs the filter on the same port.
    /// </summary>
    public int Port { get; set; }

    /// <summary>History flag: true when the block was lifted by an operator or
    /// a whitelist action rather than expiring. Only set on archived records.</summary>
    public bool Released { get; set; }
    /// <summary>When the block left the active list (expiry or release).</summary>
    public long ReleasedAt { get; set; }
}

public sealed class WhitelistRecord
{
    public string Ip { get; set; } = "";
    public int Prefix { get; set; } = 32;
    public string Note { get; set; } = "";
    public long AddedAt { get; set; }
}

public sealed class TrackedRecord
{
    public string Ip { get; set; } = "";
    public int Failures { get; set; }
    public int Stage { get; set; }
    public bool HasReal { get; set; }
    public long FirstSeen { get; set; }
    public long LastSeen { get; set; }
    /// <summary>Sliding-window timestamps for failures (unix seconds).
    /// Bounded by threshold*2 to avoid unbounded growth; pruned on each OnFailure.</summary>
    public List<long> FailTs { get; set; } = [];
}

/// <summary>One bucket of the rolling chart series.</summary>
public sealed class Bucket
{
    public long Ts { get; set; }
    public int Failures { get; set; }
    public int Successes { get; set; }
    public int Blocks { get; set; }
}

/// <summary>Aggregated per-day counters that survive restarts.</summary>
public sealed class DailyCounters
{
    public long Day { get; set; }
    public int Failures { get; set; }
    public int Successes { get; set; }
    public int Blocks { get; set; }
}

/// <summary>One address or username inside a day histogram.</summary>
public sealed class KeyCount
{
    public string K { get; set; } = "";
    /// <summary>Total tries recorded that day.</summary>
    public int N { get; set; }
    /// <summary>Of those, how many were failures.</summary>
    public int Fails { get; set; }
}

/// <summary>
/// Full-day breakdown that survives feed trimming. While the live attempt feed
/// holds only the most recent events, every attempt is also folded into a
/// per-day histogram (bounded top talkers) so reports and the day drill-down
/// keep showing complete data for older days.
/// </summary>
public sealed class DayAgg
{
    public long Day { get; set; }                       // midnight UTC, unix seconds
    public List<KeyCount> Ips { get; set; } = [];
    public List<KeyCount> Users { get; set; } = [];
}

/// <summary>One row of the date-wise report.</summary>
public sealed class DayReport
{
    /// <summary>Unix seconds at midnight UTC.</summary>
    public long Day { get; set; }
    public int Failures { get; set; }
    public int Successes { get; set; }
    public int Blocks { get; set; }
    /// <summary>Distinct source addresses seen that day.</summary>
    public int UniqueIps { get; set; }
    /// <summary>Distinct accounts attempted that day.</summary>
    public int UniqueUsers { get; set; }
    /// <summary>Attempts still held in the feed for that day.</summary>
    public int Retained { get; set; }
}

public sealed class Database
{
    public int Version { get; set; } = 3;
    public List<BlockRecord> Blocks { get; set; } = [];
    public List<WhitelistRecord> Whitelist { get; set; } = [];
    public List<TrackedRecord> Tracked { get; set; } = [];
    public List<DailyCounters> Daily { get; set; } = [];
    /// <summary>Most recent attempts, newest last. Bounded by AppSettings.MaxAttempts.</summary>
    public List<AttemptRecord> Attempts { get; set; } = [];
    /// <summary>Per-day IP/username histograms - the complete history the feed cannot hold.</summary>
    public List<DayAgg> DayAggs { get; set; } = [];
    /// <summary>Expired or released block records, newest approximately last. Bounded.</summary>
    public List<BlockRecord> BlockHistory { get; set; } = [];
    /// <summary>Cached IP reputation, keyed by IP.</summary>
    public List<ReputationRecord> Reputation { get; set; } = [];
    public long TotalFailures { get; set; }
    public long TotalSuccesses { get; set; }
    public long TotalBlocks { get; set; }
}

/// <summary>
/// Source-generated JSON metadata. Under NativeAOT the reflection-based serializer
/// is trimmed away, so every persisted type must be described ahead of time.
/// </summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(Database))]
[JsonSerializable(typeof(BlockRecord))]
[JsonSerializable(typeof(WhitelistRecord))]
[JsonSerializable(typeof(TrackedRecord))]
[JsonSerializable(typeof(DailyCounters))]
[JsonSerializable(typeof(ReputationRecord))]
[JsonSerializable(typeof(ReputationRecord[]))]
[JsonSerializable(typeof(BlockRecord[]))]
[JsonSerializable(typeof(WhitelistRecord[]))]
[JsonSerializable(typeof(TrackedRecord[]))]
internal sealed partial class V3JsonContext : JsonSerializerContext
{
}

public static class Json
{
    /// <summary>
    /// Write-to-temp then atomically replace. A crash mid-write leaves the old
    /// file intact rather than a half-written one.
    /// </summary>
    public static void WriteAtomic(string path, Database db)
    {
        string tmp = path + ".tmp";
        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(fs, db, V3JsonContext.Default.Database);
            fs.Flush(true);
        }
        File.Move(tmp, path, overwrite: true);
    }

    public static string Serialize<T>(T value, JsonTypeInfo<T> info) =>
        JsonSerializer.Serialize(value, info);

    /// <summary>List overload: the source-generated metadata is declared for arrays.</summary>
    public static string Serialize<T>(List<T> value, JsonTypeInfo<T[]> info) =>
        JsonSerializer.Serialize(value.ToArray(), info);

    public static Database? ReadDatabase(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return JsonSerializer.Deserialize(fs, V3JsonContext.Default.Database);
        }
        catch
        {
            // A corrupt file must never stop the guard from starting.
            return null;
        }
    }
}

/// <summary>Owns the on-disk state and all mutation of it.</summary>
public sealed class Store
{
    private readonly string _dir;
    private readonly string _path;
    private readonly object _gate = new();
    private readonly AppSettings _cfg;

    public Database Data { get; private set; } = new();
    private bool _dirty;
    /// <summary>Feed-only dirt (RecordAttempt). Coalesced on a longer interval
    /// than structural dirt: losing the tail of the feed on a hard crash is
    /// acceptable, losing blocks/whitelist state is not - so those keep the
    /// short flush interval.</summary>
    private bool _dirtyFeed;
    private DateTimeOffset _lastFlush = DateTimeOffset.MinValue;

    /// <summary>Monotonic version of the in-memory state. Bumped on every
    /// mutation, so the dashboard can cache JSON responses and skip rebuilding
    /// them while nothing has changed (idle polling costs no CPU).</summary>
    public long DataVersion { get; private set; }

    public event Action? Changed;

    // O(1) lookup indexes, kept in sync with Data.Blocks / Data.Tracked.
    private readonly Dictionary<string, BlockRecord> _blockIdx = new(StringComparer.Ordinal);
    private readonly Dictionary<string, TrackedRecord> _trackedIdx = new(StringComparer.Ordinal);

    private void RebuildIndexes()
    {
        _blockIdx.Clear();
        foreach (var b in Data.Blocks) _blockIdx[b.Ip] = b;
        _trackedIdx.Clear();
        foreach (var t in Data.Tracked) _trackedIdx[t.Ip] = t;
    }

    public Store(string dir, AppSettings cfg)
    {
        _dir = dir;
        _cfg = cfg;
        _path = Path.Combine(dir, "db.json");
    }

    public void Load()
    {
        Directory.CreateDirectory(_dir);
        ReputationDb.Init(_dir);
        lock (_gate)
        {
            Data = Json.ReadDatabase(_path) ?? new Database();
            RebuildIndexes();
            Changed?.Invoke();
        }
    }

    /// <summary>Mark dirty; the caller's periodic flush coalesces rapid changes.</summary>
    public void Touch()
    {
        lock (_gate) { _dirty = true; DataVersion++; }
    }

    /// <summary>Feed-only change (a new attempt row): bumps the visible version
    /// so the dashboard cache refreshes, but allows the disk flush to be
    /// deferred much longer than structural changes.</summary>
    public void TouchFeed()
    {
        lock (_gate) { _dirtyFeed = true; DataVersion++; }
    }

    /// <summary>Persist if anything changed since the last successful write.
    /// Structural changes flush within 3 s, feed-only changes within 12 s.</summary>
    public void Flush(bool force = false)
    {
        lock (_gate)
        {
            if (!_dirty && !_dirtyFeed && !force) return;
            if (!force)
            {
                double idle = (DateTimeOffset.UtcNow - _lastFlush).TotalSeconds;
                double threshold = _dirty ? 3 : 12;
                if (idle < threshold) return;
            }
            try
            {
                Json.WriteAtomic(_path, Data);
                _dirty = false;
                _dirtyFeed = false;
                _lastFlush = DateTimeOffset.UtcNow;
            }
            catch (Exception ex)
            {
                Log.Warn($"db save failed: {ex.Message}");
            }
        }
    }

    // ---- blocks -----------------------------------------------------------

    public BlockRecord? FindBlock(string ip)
    {
        lock (_gate)
            return _blockIdx.TryGetValue(ip, out var b) ? b : null;
    }

    public void AddBlock(BlockRecord rec)
    {
        lock (_gate)
        {
            if (_blockIdx.ContainsKey(rec.Ip)) Data.Blocks.RemoveAll(b => b.Ip == rec.Ip);
            Data.Blocks.Add(rec);
            _blockIdx[rec.Ip] = rec;
            if (Data.Blocks.Count > _cfg.MaxBlocked + 512)
            {
                // Oldest non-permanent first (keep recent blocks bounded).
                int over = Data.Blocks.Count - (_cfg.MaxBlocked + 512);
                for (int i = 0; i < over && Data.Blocks.Count > 0; i++)
                {
                    var old = Data.Blocks[0];
                    if (old.Permanent) break;
                    Data.Blocks.RemoveAt(0);
                    _blockIdx.Remove(old.Ip);
                    Archive(old);
                }
            }
            Data.TotalBlocks++;
            Touch();
            Changed?.Invoke();
        }
        Log.Block(rec.Ip, rec.User, rec.Reason, rec.Permanent ? "permanent" : FormatDur(rec.ExpiresAt));
    }

    public bool RemoveBlock(string ip)
    {
        lock (_gate)
        {
            if (!_blockIdx.TryGetValue(ip, out var b)) return false;
            Data.Blocks.Remove(b);
            _blockIdx.Remove(ip);
            b.Released = true;
            b.ReleasedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Archive(b);
            Touch();
            Changed?.Invoke();
            return true;
        }
    }

    /// <summary>Drops every block record. The caller must release the filters.</summary>
    public void RemoveAllBlocks()
    {
        lock (_gate)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            foreach (var b in Data.Blocks) { b.Released = true; b.ReleasedAt = now; Archive(b); }
            Data.Blocks.Clear();
            _blockIdx.Clear();
            foreach (var t in Data.Tracked) { t.Failures = 0; t.FailTs.Clear(); t.Stage = 0; }
            Touch();
            Changed?.Invoke();
        }
    }

    /// <summary>Moves a finished block into the bounded history list, so expired
    /// and released blocks remain visible in the dashboard instead of vanishing.</summary>
    private void Archive(BlockRecord b)
    {
        // Re-archiving the same ip (blocked again later) keeps both records.
        if (Data.BlockHistory.Count > 0 && Data.BlockHistory[^1].Ip == b.Ip &&
            Data.BlockHistory[^1].ReleasedAt == b.ReleasedAt) return;
        Data.BlockHistory.Add(b);
        if (Data.BlockHistory.Count > _cfg.MaxBlocked)
            Data.BlockHistory.RemoveRange(0, Data.BlockHistory.Count - _cfg.MaxBlocked);
    }

    /// <summary>Finished (expired / released) blocks, newest first.</summary>
    public List<BlockRecord> BlockHistorySnapshot(int limit)
    {
        lock (_gate)
        {
            int n = Math.Min(limit, Data.BlockHistory.Count);
            var outList = new List<BlockRecord>(n);
            for (int i = Data.BlockHistory.Count - 1; i >= 0 && outList.Count < n; i--)
                outList.Add(Data.BlockHistory[i]);
            return outList;
        }
    }

    /// <summary>Deep-copy snapshot – callers may mutate safely without touching Store.</summary>
    public List<BlockRecord> BlocksSnapshot()
    {
        lock (_gate)
        {
            var outList = new List<BlockRecord>(Data.Blocks.Count);
            foreach (var b in Data.Blocks)
            {
                outList.Add(new BlockRecord
                {
                    Ip = b.Ip, User = b.User, Reason = b.Reason, Stage = b.Stage,
                    Attempts = b.Attempts, Kind = b.Kind, Permanent = b.Permanent,
                    ExpiresAt = b.ExpiresAt, BlockedAt = b.BlockedAt, Port = b.Port,
                    Released = b.Released, ReleasedAt = b.ReleasedAt,
                });
            }
            return outList;
        }
    }

    /// <summary>Returns expired, non-permanent blocks so the caller can drop their filters.</summary>
    public List<BlockRecord> TakeExpired(long now)
    {
        lock (_gate)
        {
            var dead = Data.Blocks
                .Where(b => !b.Permanent && b.ExpiresAt > 0 && b.ExpiresAt <= now)
                .ToList();
            foreach (var b in dead)
            {
                Data.Blocks.Remove(b);
                _blockIdx.Remove(b.Ip);
                b.ReleasedAt = b.ExpiresAt;
                Archive(b);
            }
            if (dead.Count > 0) { Touch(); Changed?.Invoke(); }
            return dead;
        }
    }

    // ---- whitelist --------------------------------------------------------

    public List<WhitelistRecord> WhitelistSnapshot()
    {
        lock (_gate) return [.. Data.Whitelist];
    }

    /// <summary>True when ip falls inside any whitelist range. Used to skip all enforcement.</summary>
    public bool IsWhitelisted(string ip)
    {
        if (!Net.TryParseIpv4(ip, out uint target)) return false;
        lock (_gate)
        {
            foreach (var w in Data.Whitelist)
            {
                if (!Net.TryParseIpv4(w.Ip, out uint net)) continue;
                int bits = Math.Clamp(w.Prefix, 0, 32);
                uint mask = bits == 0 ? 0u : uint.MaxValue << (32 - bits);
                if ((target & mask) == (net & mask)) return true;
            }
        }
        return false;
    }

    public bool AddWhitelist(string ipOrCidr, string note)
    {
        if (!Net.TryParseCidr(ipOrCidr, out string ip, out int prefix)) return false;
        lock (_gate)
        {
            if (Data.Whitelist.Any(w => w.Ip == ip && w.Prefix == prefix)) return false;
            Data.Whitelist.Add(new WhitelistRecord
            {
                Ip = ip,
                Prefix = prefix,
                Note = Sanitize.Note(note),
                AddedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            });
            Touch();
            Changed?.Invoke();
        }
        return true;
    }

    public bool RemoveWhitelist(string ip, int prefix)
    {
        lock (_gate)
        {
            int n = Data.Whitelist.RemoveAll(w => w.Ip == ip && w.Prefix == prefix);
            if (n > 0) { Touch(); Changed?.Invoke(); }
            return n > 0;
        }
    }

    /// <summary>
    /// One-shot import of build-1609 data during the upgrade. Offline import
    /// path used only by LegacyImport before any worker or the dashboard runs:
    /// silent (no per-block log spam), de-duplicated, and stamps the database
    /// version so the import never runs twice for the same db.
    /// </summary>
    public void ImportLegacy(
        List<BlockRecord> blocks, List<TrackedRecord> tracked, List<AttemptRecord> attempts,
        List<(string Ip, int Prefix)> whitelist, long totalBlocks, long totalFailures)
    {
        lock (_gate)
        {
            foreach (var b in blocks)
            {
                if (_blockIdx.ContainsKey(b.Ip)) continue;   // live block wins
                if (string.IsNullOrEmpty(b.User)) b.User = "migrated";
                b.Port = 0;                                        // re-install on current ports
                Data.Blocks.Add(b);
                _blockIdx[b.Ip] = b;
            }
            foreach (var t in tracked)
                if (!_trackedIdx.ContainsKey(t.Ip)) { Data.Tracked.Add(t); _trackedIdx[t.Ip] = t; }
            foreach (var a in attempts)
                if (Data.Attempts.All(x => x.Ts != a.Ts || x.Ip != a.Ip)) Data.Attempts.Add(a);

            Data.Attempts.Sort((x, y) => x.Ts.CompareTo(y.Ts));
            int over = Data.Attempts.Count - _cfg.MaxAttempts;
            if (over > 0) Data.Attempts.RemoveRange(0, over);

            foreach (var (ip, prefix) in whitelist)
                if (Data.Whitelist.All(w => w.Ip != ip || w.Prefix != prefix))
                    Data.Whitelist.Add(new WhitelistRecord
                    {
                        Ip = ip, Prefix = prefix,
                        Note = "migrated from previous version",
                        AddedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                    });

            Data.TotalBlocks = Math.Max(Data.TotalBlocks, totalBlocks);
            Data.TotalFailures = Math.Max(Data.TotalFailures, totalFailures);
            Data.Version = Math.Max(Data.Version, 4);              // import stamp
            Touch();
            Changed?.Invoke();
        }
    }

    // ---- tracked ----------------------------------------------------------

    public TrackedRecord? FindTracked(string ip)
    {
        lock (_gate)
            return _trackedIdx.TryGetValue(ip, out var t) ? t : null;
    }

    /// <summary>
    /// Fetch or create the tracking row for ip. When the table is full the least
    /// valuable row is evicted: fewest failures, oldest last-seen. Entries owning
    /// a live block are never evicted so escalation state is preserved.
    /// </summary>
    public TrackedRecord GetOrCreate(string ip, long now)
    {
        lock (_gate)
        {
            if (_trackedIdx.TryGetValue(ip, out var existing)) return existing;

            var t = new TrackedRecord { Ip = ip, FirstSeen = now, LastSeen = now };
            Data.Tracked.Add(t);
            _trackedIdx[ip] = t;

            if (Data.Tracked.Count > _cfg.MaxTracked)
            {
                var victim = Data.Tracked
                    .Where(x => x.Ip != ip && !_blockIdx.ContainsKey(x.Ip))
                    .OrderBy(x => x.Failures)
                    .ThenBy(x => x.LastSeen)
                    .FirstOrDefault();
                if (victim != null) { Data.Tracked.Remove(victim); _trackedIdx.Remove(victim.Ip); }
            }
            Touch();
            return t;
        }
    }

    public void ResetTracked(string ip)
    {
        lock (_gate)
        {
            if (!_trackedIdx.TryGetValue(ip, out var t)) return;
            t.Failures = 0;
            t.FailTs.Clear();
            // The ladder deliberately survives a success: guessing the right
            // password once must not erase the history of an ongoing attack.
        }
        Touch();
    }

    public List<TrackedRecord> TrackedSnapshot()
    {
        lock (_gate) return [.. Data.Tracked];
    }

    // ---- attempts (dashboard feed) ----------------------------------------

    /// <summary>
    /// Records one observed attempt. The list is trimmed to
    /// <see cref="AppSettings.MaxAttempts"/> on every insert, so the feed cannot
    /// grow without bound no matter how heavy the attack is.
    /// </summary>
    public void RecordAttempt(AttemptRecord a)
    {
        lock (_gate)
        {
            Data.Attempts.Add(a);
            int over = Data.Attempts.Count - _cfg.MaxAttempts;
            if (over > 0) Data.Attempts.RemoveRange(0, over);
            // Full-day histograms live on independently of the feed trim, so no
            // data is ever lost to the rolling window; moreover the day
            // drill-down and reports stay complete for older days.
            AccumulateDayAgg(a);
            TouchFeed();
        }
    }

    private void AccumulateDayAgg(AttemptRecord a)
    {
        long day = a.Ts / 86400 * 86400;
        var agg = Data.DayAggs.FindLast(x => x.Day == day);
        if (agg is null)
        {
            agg = new DayAgg { Day = day };
            Data.DayAggs.Add(agg);
            // align to the log retention window
            long cutoff = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 86400 - _cfg.RetentionDays;
            Data.DayAggs.RemoveAll(x => x.Day / 86400 < cutoff);
        }
        AddKey(agg.Ips, a.Ip, a.Success);
        if (!string.IsNullOrEmpty(a.User)) AddKey(agg.Users, a.User, a.Success);
    }

    private static void AddKey(List<KeyCount> list, string k, bool success)
    {
        var it = list.Find(x => x.K == k);
        if (it is null)
        {
            it = new KeyCount { K = k, N = 1, Fails = success ? 0 : 1 };
            list.Add(it);
        }
        else { it.N++; if (!success) it.Fails++; }

        if (list.Count > 300)
        {
            var keep = list.OrderByDescending(x => x.N).Take(300).ToList();
            list.Clear(); list.AddRange(keep);
        }
    }

    /// <summary>
    /// Re-applies the feed cap. Called after the operator lowers the limit in the
    /// dashboard, so the change takes effect immediately rather than only as old
    /// entries age out.
    /// </summary>
    public void TrimAttempts()
    {
        lock (_gate)
        {
            int over = Data.Attempts.Count - _cfg.MaxAttempts;
            if (over > 0)
            {
                Data.Attempts.RemoveRange(0, over);
                Touch();
            }
        }
    }

    /// <summary>Newest-first slice of the feed, capped for the wire.</summary>
    public List<AttemptRecord> AttemptsSnapshot(int limit)
    {
        lock (_gate)
        {
            int n = Math.Min(limit, Data.Attempts.Count);
            var outList = new List<AttemptRecord>(n);
            for (int i = Data.Attempts.Count - 1; i >= 0 && outList.Count < n; i--)
                outList.Add(Data.Attempts[i]);
            return outList;
        }
    }

    /// <summary>Aggregates the feed into top-talker lists for the charts.</summary>
    public (List<(string Key, int Count)> Ips, List<(string Key, int Count)> Users) TopTalkers(int take)
    {
        lock (_gate)
        {
            var ips = new Dictionary<string, int>(StringComparer.Ordinal);
            var users = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var a in Data.Attempts)
            {
                if (a.Success) continue;
                ips[a.Ip] = ips.TryGetValue(a.Ip, out var c) ? c + 1 : 1;
                users[a.User] = users.TryGetValue(a.User, out var u) ? u + 1 : 1;
            }
            return (Rank(ips, take), Rank(users, take));
        }
    }

    private static List<(string, int)> Rank(Dictionary<string, int> src, int take) =>
        src.OrderByDescending(kv => kv.Value)
           .ThenBy(kv => kv.Key, StringComparer.Ordinal)
           .Take(take)
           .Select(kv => (kv.Key, kv.Value))
           .ToList();

    /// <summary>Distinct addresses and accounts seen in the feed.</summary>
    public (int UniqueIps, int UniqueUsers) DistinctCounts()
    {
        lock (_gate)
        {
            var ips = new HashSet<string>(StringComparer.Ordinal);
            var users = new HashSet<string>(StringComparer.Ordinal);
            foreach (var a in Data.Attempts) { ips.Add(a.Ip); users.Add(a.User); }
            return (ips.Count, users.Count);
        }
    }

    /// <summary>
    /// Top source countries, derived from the cached threat-intel lookups for
    /// the addresses in the feed. Unresolved addresses are counted as
    /// "Unknown" so the operator can see how much is not yet mapped.
    /// </summary>
    public List<(string Cc, string Name, int Count)> CountryStats(int take)
    {
        lock (_gate)
        {
            var byIp = new Dictionary<string, ReputationRecord>(StringComparer.Ordinal);
            foreach (var r in Data.Reputation) byIp[r.Ip] = r;

            var counts = new Dictionary<string, (string Name, int N)>(StringComparer.Ordinal);
            foreach (var a in Data.Attempts)
            {
                if (a.Success || a.Ip.Length == 0) continue;
                byIp.TryGetValue(a.Ip, out var rep);
                string cc = (rep?.CountryCode ?? "").Trim().ToUpperInvariant();
                if (cc.Length != 2)
                {
                    string unkName = rep != null && !string.IsNullOrEmpty(rep.Country) ? rep.Country : "Unknown";
                    counts["?"] = (unkName, counts.TryGetValue("?", out var unk) ? unk.N + 1 : 1);
                    continue;
                }
                string name = rep != null && !string.IsNullOrEmpty(rep.Country) ? rep.Country : cc;
                counts[cc] = (name, counts.TryGetValue(cc, out var c) ? c.N + 1 : 1);
            }
            return counts
                .OrderByDescending(kv => kv.Value.N)
                .ThenBy(kv => kv.Key, StringComparer.Ordinal)
                .Take(take)
                .Select(kv => (kv.Key, kv.Value.Name, kv.Value.N))
                .ToList();
        }
    }

    /// <summary>Every attempt inside [from, to), oldest first, for day drill-downs.</summary>
    public List<AttemptRecord> AttemptsInWindow(long from, long to)
    {
        lock (_gate) return Data.Attempts.Where(a => a.Ts >= from && a.Ts < to).ToList();
    }

    /// <summary>Day counters for one bucket; zeros when that day is not stored.</summary>
    public (long Day, int Failures, int Successes, int Blocks) DailyFor(long dayStart)
    {
        lock (_gate)
        {
            var d = Data.Daily.FirstOrDefault(x => x.Day == dayStart);
            return d is null ? (dayStart, 0, 0, 0) : (d.Day, d.Failures, d.Successes, d.Blocks);
        }
    }

    /// <summary>Complete-day IP/username histogram for one bucket, or null.</summary>
    public DayAgg? DayAggFor(long dayStart)
    {
        lock (_gate) return Data.DayAggs.FindLast(x => x.Day == dayStart);
    }

    public long LastAttemptTs()
    {
        lock (_gate) return Data.Attempts.Count > 0 ? Data.Attempts[^1].Ts : 0;
    }

    // ---- reputation cache --------------------------------------------------
    public ReputationRecord? FindReputation(string ip)
    {
        lock (_gate)
        {
            var r = Data.Reputation.FirstOrDefault(x => x.Ip == ip);
            if (r != null)
            {
                long age = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - r.CachedAt;
                if (age <= 86400) return r;
                Data.Reputation.Remove(r);
            }
        }
        // Fall back to the persistent SQLite cache.
        var fromDb = ReputationDb.Get(ip);
        if (fromDb != null)
        {
            lock (_gate) Data.Reputation.Add(fromDb);
        }
        return fromDb;
    }

    public void SaveReputation(ReputationRecord r)
    {
        lock (_gate)
        {
            Data.Reputation.RemoveAll(x => x.Ip == r.Ip);
            Data.Reputation.Add(r);
            if (Data.Reputation.Count > 2048)
                Data.Reputation.RemoveRange(0, Data.Reputation.Count - 2048);
            Touch();
        }
        ReputationDb.Save(r);
    }

    // ---- counters / charts ------------------------------------------------

    public void CountFailure(string ip)
    {
        lock (_gate)
        {
            Data.TotalFailures++;
            long day = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 86400 * 86400;
            var d = Data.Daily.FirstOrDefault(x => x.Day == day);
            if (d == null) { Data.Daily.Add(new DailyCounters { Day = day }); d = Data.Daily[^1]; }
            d.Failures++;
            Touch();
        }
    }

    public void CountSuccess()
    {
        lock (_gate)
        {
            Data.TotalSuccesses++;
            long day = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 86400 * 86400;
            var d = Data.Daily.FirstOrDefault(x => x.Day == day);
            if (d == null) { Data.Daily.Add(new DailyCounters { Day = day }); d = Data.Daily[^1]; }
            d.Successes++;
            Touch();
        }
    }

    public void SnapshotCounts(out long failures, out long successes, out long blocks)
    {
        lock (_gate)
        {
            failures = Data.TotalFailures;
            successes = Data.TotalSuccesses;
            blocks = Data.TotalBlocks;
        }
    }

    /// <summary>Dense per-day series over the last N days, zero-filled so charts have no gaps.</summary>
    public List<DailyCounters> DailySeries(int days)
    {
        lock (_gate)
        {
            long today = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 86400 * 86400;
            var byDay = Data.Daily.ToDictionary(x => x.Day, x => x);
            var series = new List<DailyCounters>(days);
            for (int i = days - 1; i >= 0; i--)
            {
                long d = today - (long)i * 86400;
                series.Add(byDay.TryGetValue(d, out var rec)
                    ? new DailyCounters { Day = d, Failures = rec.Failures, Successes = rec.Successes, Blocks = rec.Blocks }
                    : new DailyCounters { Day = d });
            }
            return series;
        }
    }

    /// <summary>
    /// Date-ordered report: newest day first, with the distinct addresses and
    /// accounts seen that day. Derived from the retained feed, so it only covers
    /// the window the feed holds.
    /// </summary>
    public List<DayReport> DailyReport(int days)
    {
        lock (_gate)
        {
            long today = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 86400 * 86400;

            var ips = new Dictionary<long, HashSet<string>>();
            var users = new Dictionary<long, HashSet<string>>();
            var hits = new Dictionary<long, int>();

            foreach (var a in Data.Attempts)
            {
                if (a.Success) continue;
                long day = a.Ts / 86400 * 86400;
                if (!ips.TryGetValue(day, out var set)) { set = new HashSet<string>(StringComparer.Ordinal); ips[day] = set; }
                set.Add(a.Ip);
                if (!users.TryGetValue(day, out var uset)) { uset = new HashSet<string>(StringComparer.Ordinal); users[day] = uset; }
                uset.Add(a.User);
                hits[day] = hits.TryGetValue(day, out var h) ? h + 1 : 1;
            }

            var byDay = Data.Daily.ToDictionary(x => x.Day, x => x);
            var rows = new List<DayReport>(days);
            for (int i = 0; i < days; i++)
            {
                long d = today - (long)i * 86400;
                byDay.TryGetValue(d, out var rec);
                rows.Add(new DayReport
                {
                    Day = d,
                    Failures = rec?.Failures ?? 0,
                    Successes = rec?.Successes ?? 0,
                    Blocks = rec?.Blocks ?? 0,
                    UniqueIps = ips.TryGetValue(d, out var s) ? s.Count : 0,
                    UniqueUsers = users.TryGetValue(d, out var u) ? u.Count : 0,
                    Retained = hits.TryGetValue(d, out var h) ? h : 0,
                });
            }
            return rows;
        }
    }

    private static string FormatDur(long expiresAt)
    {
        long s = Math.Max(0, expiresAt - DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        if (s >= 86400) return $"{s / 86400}d";
        if (s >= 3600) return $"{s / 3600}h";
        if (s >= 60) return $"{s / 60}m";
        return $"{s}s";
    }
}