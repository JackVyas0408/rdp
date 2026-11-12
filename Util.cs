using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace V3Guard;

public static class Net
{
    public static bool TryParseIpv4(string s, out uint be)
    {
        be = 0;
        if (string.IsNullOrWhiteSpace(s)) return false;
        return IPAddress.TryParse(s.Trim(), out var ip)
            && ip.AddressFamily == AddressFamily.InterNetwork
            && (be = ToHostOrder(ip)) != 0 || TryParseRaw(s.Trim(), out be);
    }

    private static bool TryParseRaw(string s, out uint be)
    {
        be = 0;
        Span<byte> b = stackalloc byte[4];
        if (!IPAddress.TryParse(s, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork) return false;
        var raw = ip.GetAddressBytes();
        if (raw.Length != 4) return false;
        b = raw;
        be = (uint)((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
        return true;
    }

    /// <summary>Dotted quad to the host-order (big-endian) integer WFP expects.</summary>
    public static uint ToHostOrder(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return (uint)((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
    }

    public static uint ToHostOrder(string ip) =>
        IPAddress.TryParse(ip, out var a) ? ToHostOrder(a) : 0;

    public static bool TryParseCidr(string input, out string ip, out int prefix)
    {
        ip = "";
        prefix = 32;
        var s = input.Trim();
        int slash = s.IndexOf('/');
        if (slash < 0)
        {
            ip = s;
            return TryParseIpv4(s, out _);
        }
        ip = s[..slash];
        if (!int.TryParse(s[(slash + 1)..], out prefix) || prefix < 0 || prefix > 32) return false;
        return TryParseIpv4(ip, out _);
    }

    public static bool IsLoopbackOrLocal(string ip)
    {
        if (!TryParseIpv4(ip, out uint v)) return true; // unparsable: treat as untrusted-local, skip
        byte a = (byte)(v >> 24);
        byte b = (byte)(v >> 16);
        // 127/8 loopback, 0/8 "this host", 10/8, 172.16/12, 192.168/16 private,
        // 169.254/16 link-local. LAN noise should be reported, not WFP-blocked.
        return a is 127 or 0 or 10
            || (a == 172 && b is >= 16 and <= 31)
            || (a == 192 && b == 168)
            || (a == 169 && b == 254);
    }

    public static bool IsPrivateRfc1918(string ip) => IsLoopbackOrLocal(ip);
}

public static class Sanitize
{
    public static string Note(string s) => Clean(s, 120);

    /// <summary>Strips CR/LF so a value can never inject an extra SMTP header.</summary>
    public static string SingleLine(string s, int max) => Clean(s, max);

    private static string Clean(string s, int max)
    {
        if (string.IsNullOrEmpty(s)) return "";
        var sb = new StringBuilder(Math.Min(s.Length, max));
        foreach (char c in s)
        {
            if (c == '\r' || c == '\n' || c == '\0') continue;
            sb.Append(c);
            if (sb.Length >= max) break;
        }
        return sb.ToString().Trim();
    }

    public static string Html(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        var sb = new StringBuilder(s.Length + 16);
        foreach (char c in s)
        {
            switch (c)
            {
                case '&': sb.Append("&amp;"); break;
                case '<': sb.Append("&lt;"); break;
                case '>': sb.Append("&gt;"); break;
                case '"': sb.Append("&quot;"); break;
                case '\'': sb.Append("&#39;"); break;
                default: sb.Append(c); break;
            }
        }
        return sb.ToString();
    }

    /// <summary>Safe for embedding inside a single-quoted JS string literal.</summary>
    public static string Js(string s) =>
        Html(s).Replace("\\", "\\\\").Replace("\n", "\\n").Replace("\r", "");
}

public static class Log
{
    private static readonly object Gate = new();
    private static StreamWriter? _writer;
    private static string _day = "";
    private static readonly string Dir = Path.Combine(AppContext.BaseDirectory, "logs");

    // Batched logger: Emit() enqueues to a channel, a single background thread
    // writes at most once per 200ms. Under attack (1000 lines/sec) this removes
    // 1000 lock+IO per second → ~1 flush per 200ms.
    private static readonly System.Threading.Channels.Channel<string> _logChan =
        System.Threading.Channels.Channel.CreateBounded<string>(new System.Threading.Channels.BoundedChannelOptions(2048)
        {
            FullMode = System.Threading.Channels.BoundedChannelFullMode.DropOldest,
            SingleWriter = false,
            SingleReader = true,
        });
    private static bool _logFlushStarted;

    private static void StartFlushThread()
    {
        if (_logFlushStarted) return;
        _logFlushStarted = true;
        var t = new Thread(async () =>
        {
            try
            {
                while (await _logChan.Reader.WaitToReadAsync().ConfigureAwait(false))
                {
                    var batch = new List<string>();
                    await Task.Delay(200).ConfigureAwait(false);
                    while (_logChan.Reader.TryRead(out var line)) batch.Add(line);
                    if (batch.Count == 0) continue;
                    lock (Gate)
                    {
                        foreach (var l in batch)
                        {
                            try { Console.WriteLine(l); } catch { }
                        }
                        Ensure();
                        foreach (var l in batch)
                            try { _writer?.WriteLine(l); } catch { }
                        try { _writer?.Flush(); } catch { }
                    }
                }
            }
            catch { }
        })
        { IsBackground = true, Name = "log-flush" };
        t.Start();
    }

    public static void Init()
    {
        Directory.CreateDirectory(Dir);
        StartFlushThread();
        if (OperatingSystem.IsWindows() && Environment.GetEnvironmentVariable("V3_DEBUG") == "1")
            AttachParentConsole();
        Info($"v3 start pid={Environment.ProcessId} elevated={Diag.IsElevated()}");
    }

    /// <summary>
    /// Attaches this windowless process to the console that launched it, so
    /// --diag output is visible when run from a terminal.
    /// </summary>
    public static void AttachParentConsole()
    {
        AttachConsole(-1);
        try
        {
            var stdout = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
            Console.SetOut(stdout);
        }
        catch { }
    }

    [DllImport("kernel32.dll")] private static extern bool AttachConsole(int pid);
    [DllImport("kernel32.dll")] private static extern bool SetProcessWorkingSetSize(IntPtr proc, IntPtr min, IntPtr max);

    /// <summary>
    /// Returns the process's resident pages to the standby list.
    ///
    /// This lowers the working set Windows reports; it does not lower committed
    /// memory, since the pages come straight back if touched. It is worth doing
    /// because the guard is idle almost all the time, and the effect is large -
    /// a few hundred KB resident instead of tens of MB, which is what an operator
    /// watching Task Manager sees and what keeps the agent off the radar of
    /// memory-pressure tooling.
    /// </summary>
    public static void TrimWorkingSet()
    {
        try { SetProcessWorkingSetSize(GetCurrentProcess(), (IntPtr)(-1), (IntPtr)(-1)); }
        catch { }
    }

    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();

    public static long PrivateBytesKb()
    {
        try { return System.Diagnostics.Process.GetCurrentProcess().PrivateMemorySize64 / 1024; }
        catch { return 0; }
    }

    public static long WorkingSetKb()
    {
        try { return System.Diagnostics.Process.GetCurrentProcess().WorkingSet64 / 1024; }
        catch { return 0; }
    }

    private static void Ensure()
    {
        string today = DateTime.Now.ToString("yyyy-MM-dd");
        if (_writer != null && _day == today) return;
        try
        {
            _writer?.Dispose();
            _writer = new StreamWriter(Path.Combine(Dir, today + ".txt"), append: true)
            {
                AutoFlush = true,
            };
            _day = today;
        }
        catch { _writer = null; }
    }

    private static void Emit(string line)
    {
        // Fast path: enqueue, background thread batches + writes.
        _logChan.Writer.TryWrite(line);
    }

    /// <summary>Synchronous fallback for CLI --diag/--demo (needs instant output).</summary>
    public static void EmitSync(string line)
    {
        lock (Gate)
        {
            try { Console.WriteLine(line); } catch { }
            Ensure();
            try { _writer?.WriteLine(line); _writer?.Flush(); } catch { }
        }
    }

    private static string Stamp() => DateTime.Now.ToString("HH:mm:ss");

    public static void Info(string m) => Emit($"[{Stamp()}] INFO  {m}");
    public static void Warn(string m) => Emit($"[{Stamp()}] WARN  {m}");
    public static void Error(string m) => Emit($"[{Stamp()}] ERROR {m}");
    public static void Block(string ip, string user, string reason, string dur) =>
        Emit($"[{Stamp()}] BLOCK ip={ip} user={user} reason={reason} dur={dur}");
    public static void Unblock(string ip, string reason) =>
        Emit($"[{Stamp()}] UNBLOCK ip={ip} reason={reason}");
    public static void Allow(string ip, string user) =>
        Emit($"[{Stamp()}] ALLOW ip={ip} user={user}");

    /// <summary>Deletes day files older than the retention window.</summary>
    public static void Prune(int days)
    {
        if (days <= 0) return;
        try
        {
            var cutoff = DateTime.Now.AddDays(-days);
            foreach (var f in Directory.EnumerateFiles(Dir, "*.txt"))
                if (File.GetLastWriteTime(f) < cutoff) File.Delete(f);
        }
        catch { }
    }
}