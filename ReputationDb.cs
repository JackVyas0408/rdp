using System.Text;
using System.Text.Json;

namespace V3Guard;

/// <summary>
/// Ultra-lightweight, pure-C# persistent cache for scanned IP reputation.
/// No native library: the whole map is held in memory and written to
/// reputation.json atomically (temp + replace) so results survive restarts.
/// </summary>
public static class ReputationDb
{
    private static readonly object Gate = new();
    private static readonly Dictionary<string, ReputationRecord> Map = new(StringComparer.Ordinal);
    private static string _path = "";
    private static bool _ready;
    private static bool _dirty;
    private static DateTimeOffset _lastSave = DateTimeOffset.MinValue;

    public static void Init(string dir)
    {
        if (_ready) return;
        _path = System.IO.Path.Combine(dir, "reputation.json");
        try
        {
            if (File.Exists(_path))
            {
                using var fs = new FileStream(_path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var arr = JsonSerializer.Deserialize(fs, V3JsonContext.Default.ReputationRecordArray);
                if (arr != null)
                    foreach (var r in arr)
                        if (r.Ip.Length > 0) Map[r.Ip] = r;
            }
        }
        catch (Exception ex)
        {
            Log.Warn($"reputation store read failed: {ex.Message}");
        }
        _ready = true;
        Log.Info($"reputation store ready: {_path} ({Map.Count} cached)");
    }

    public static ReputationRecord? Get(string ip)
    {
        lock (Gate)
        {
            if (!Map.TryGetValue(ip, out var r)) return null;
            long age = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - r.CachedAt;
            if (age > 86400) { Map.Remove(ip); _dirty = true; return null; }
            return r;
        }
    }

    public static void Save(ReputationRecord rec)
    {
        lock (Gate)
        {
            Map[rec.Ip] = rec;
            _dirty = true;
            if (Map.Count > 4096)
            {
                // Drop the oldest quarter to keep the file bounded.
                foreach (var old in Map.Values.OrderBy(x => x.CachedAt).Take(Map.Count - 3072).ToList())
                    Map.Remove(old.Ip);
            }
        }
        Flush();
    }

    /// <summary>Writes the cache to disk if dirty; throttled to once every 3s.</summary>
    public static void Flush(bool force = false)
    {
        lock (Gate)
        {
            if (!_ready || !_dirty) return;
            if (!force && (DateTimeOffset.UtcNow - _lastSave).TotalSeconds < 3) return;

            try
            {
                var arr = Map.Values.ToArray();
                string json = JsonSerializer.Serialize(arr, V3JsonContext.Default.ReputationRecordArray);
                string tmp = _path + ".tmp";
                using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    var bytes = Encoding.UTF8.GetBytes(json);
                    fs.Write(bytes, 0, bytes.Length);
                    fs.Flush(true);
                }
                File.Move(tmp, _path, overwrite: true);
                _dirty = false;
                _lastSave = DateTimeOffset.UtcNow;
            }
            catch (Exception ex)
            {
                Log.Warn($"reputation store write failed: {ex.Message}");
            }
        }
    }

    public static long Count()
    {
        lock (Gate) return Map.Count;
    }
}