using System.Runtime.InteropServices;

namespace V3Guard;

/// <summary>A parsed logon event, independent of where it came from.</summary>
public sealed record LogonEvent(
    int EventId,
    string Ip,
    string User,
    string SubStatus,
    DateTime TimestampUtc,
    int LogonType = 0);

/// <summary>
/// Source of logon events. The guard uses the Security log today; the interface
/// exists so an ETW provider can be dropped in without touching policy or the UI.
/// </summary>
public interface IEventSource : IDisposable
{
    bool IsHealthy { get; }
    string Name { get; }
    void Start();
}

/// <summary>
/// Push-based Security log reader built on EvtSubscribe.
///
/// EvtSubscribe delivers events on a callback the moment Windows writes them -
/// no polling, so it costs no CPU while idle and reacts immediately instead of
/// on a timer tick. The callback only renders, parses and enqueues; the blocking
/// work (WFP, disk, mail) happens on a worker thread so the delivery thread is
/// never held up and events cannot be dropped behind slow work.
/// </summary>
public sealed class EventLogSource : IEventSource, IDisposable
{
    public const int LogonFailure = 4625;
    public const int LogonSuccess = 4624;
    public const int AuditLogCleared = 1102;
    public const int AuditPolicyChanged = 4719;
    public const int AuditPolicyAssigned = 4907;

    private const string Query =
        "*[System[(EventID=4624 or EventID=4625 or EventID=1102 or EventID=4719 or EventID=4907)]]";

    // EvtSubscribe flags
    private const uint SubscribeToFutureEvents = 0x1;
    private const uint SubscribeAfterBookmark = 0x3;
    private const uint SubscribeStrict = 0x00010000;

    // Callback actions
    private const uint ActionError = 0;
    private const uint ActionDeliver = 1;

    // Render flags
    private const uint RenderEventXml = 1;
    private const uint RenderBookmark = 2;

    private const int QueueCap = 512;

    private delegate uint SubscribeCallback(uint action, IntPtr context, IntPtr evt);

    [DllImport("wevtapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr EvtSubscribe(IntPtr session, IntPtr signalEvent, string channel,
        string query, IntPtr bookmark, IntPtr context, SubscribeCallback callback, uint flags);

    [DllImport("wevtapi.dll", SetLastError = true)]
    private static extern bool EvtClose(IntPtr handle);

    [DllImport("wevtapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr EvtCreateBookmark(string? bookmarkXml);

    [DllImport("wevtapi.dll", SetLastError = true)]
    private static extern bool EvtUpdateBookmark(IntPtr bookmark, IntPtr evt);

    [DllImport("wevtapi.dll", SetLastError = true)]
    private static extern bool EvtRender(IntPtr context, IntPtr fragment, uint flags,
        int bufferSize, IntPtr buffer, out int bufferUsed, out int propertyCount);

    [DllImport("wevtapi.dll", SetLastError = true)]
    private static extern IntPtr EvtQuery(IntPtr session, string path, string query, uint flags);

    [DllImport("wevtapi.dll", SetLastError = true)]
    private static extern bool EvtNext(IntPtr resultSet, int arraySize, IntPtr[] events,
        int timeoutMs, int flags, out int returned);

    private readonly string _channel;
    private readonly string _bookmarkPath;

    // Keep the callback delegate alive: wevtapi holds a raw function pointer and
    // a collected delegate would crash the delivery thread.
    private SubscribeCallback? _callbackKeepAlive;

    // Lock-free bounded channel replaces Queue+SemaphoreSlim: Enqueue is one
    // atomic write, Pump is one ReadAsync. DropOldest keeps the delivery
    // thread non-blocking when the worker lags under attack.
    private readonly System.Threading.Channels.Channel<LogonEvent> _chan =
        System.Threading.Channels.Channel.CreateBounded<LogonEvent>(new System.Threading.Channels.BoundedChannelOptions(QueueCap)
        {
            FullMode = System.Threading.Channels.BoundedChannelFullMode.DropOldest,
            SingleWriter = false,
            SingleReader = true,
        });
    private readonly object _gate = new();

    private IntPtr _subscription;
    private IntPtr _nativeBookmark;
    private Thread? _worker;
    private CancellationTokenSource? _cts;

    public bool IsHealthy { get; private set; }
    public string Name => "eventlog";
    public event Action<LogonEvent>? Event;

    /// <summary>Events that parsed successfully since start.</summary>
    public long Delivered { get { lock (_gate) return _delivered; } }
    private long _delivered;

    /// <summary>Events seen but discarded, with the most recent reason.</summary>
    public long Skipped { get { lock (_gate) return _skipped; } }
    private long _skipped;
    public string LastSkipReason { get; private set; } = "";

    /// <summary>Raised when the subscription drops and detection goes blind.</summary>
    public bool NeedsResubscribe => !IsHealthy;

    public EventLogSource(string channel = "Security")
    {
        _channel = channel;
        _bookmarkPath = Path.Combine(AppContext.BaseDirectory, "bookmark.xml");
    }

    public void Start()
    {
        lock (_gate)
        {
            if (_subscription != IntPtr.Zero) return;

            _cts ??= new CancellationTokenSource();

            if (_worker is null)
            {
                _worker = new Thread(Pump) { IsBackground = true, Name = "evt-worker" };
                _worker.Start();
            }

            Subscribe();
        }
    }

    private void Subscribe()
    {
        _callbackKeepAlive ??= OnEventDelivered;

        // Resume from the stored position when one exists, so a restart does not
        // miss the events that occurred while the guard was down.
        _nativeBookmark = LoadBookmark();
        uint flags = _nativeBookmark != IntPtr.Zero
            ? SubscribeAfterBookmark | SubscribeStrict
            : SubscribeToFutureEvents | SubscribeStrict;

        IntPtr sub = EvtSubscribe(IntPtr.Zero, IntPtr.Zero, _channel, Query,
            _nativeBookmark, IntPtr.Zero, _callbackKeepAlive, flags);

        if (sub == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();

            // A bookmark the log no longer recognises (log cleared or rolled)
            // makes the subscribe fail; drop it and start from now.
            if (_nativeBookmark != IntPtr.Zero)
            {
                Log.Warn($"subscribe with bookmark failed (win32 {err}); retrying from now");
                EvtClose(_nativeBookmark);
                _nativeBookmark = IntPtr.Zero;
                try { File.Delete(_bookmarkPath); } catch { }

                sub = EvtSubscribe(IntPtr.Zero, IntPtr.Zero, _channel, Query,
                    IntPtr.Zero, IntPtr.Zero, _callbackKeepAlive,
                    SubscribeToFutureEvents | SubscribeStrict);
                if (sub != IntPtr.Zero)
                {
                    _subscription = sub;
                    IsHealthy = true;
                    Log.Info($"subscribed to '{_channel}' (4624/4625/tamper)");
                    return;
                }
                err = Marshal.GetLastWin32Error();
            }

            IsHealthy = false;
            Log.Warn(err == 5
                ? "Security log access denied - run as Administrator"
                : $"EvtSubscribe failed (win32 {err}) - detection is OFF");
            return;
        }

        _subscription = sub;
        IsHealthy = true;
        Log.Info($"subscribed to '{_channel}' (4624/4625/tamper), flags=0x{flags:X}");
    }

    /// <summary>
    /// Runs on the wevtapi delivery thread. Must return quickly: only render,
    /// parse and enqueue here. Anything slow would stall event delivery.
    /// </summary>
    private uint OnEventDelivered(uint action, IntPtr context, IntPtr evt)
    {
        try
        {
            if (action == ActionError)
            {
                // The event argument carries the error status for this action.
                uint status = (uint)evt.ToInt64();
                Log.Warn($"event subscription error 0x{status:X8} - resubscribing");
                MarkUnhealthy();
                return 0;
            }

            if (action != ActionDeliver || evt == IntPtr.Zero) return 0;

            // Advance the bookmark so a restart resumes from here.
            if (_nativeBookmark != IntPtr.Zero)
                EvtUpdateBookmark(_nativeBookmark, evt);

            string xml = Render(evt, RenderEventXml);
            if (xml.Length == 0) return 0;

            Handle(xml);
        }
        catch (Exception ex)
        {
            Log.Warn($"delivery callback: {ex.Message}");
        }
        return 0;
    }

    private void Handle(string xml)
    {
        int id = (int)FieldInt(xml, "EventID");

        // Tamper events are rare and important: act on them directly.
        if (id is AuditLogCleared or AuditPolicyChanged or AuditPolicyAssigned)
        {
            Enqueue(new LogonEvent(id, "-", "-", "-", DateTime.UtcNow));
            return;
        }

        if (id is not (LogonFailure or LogonSuccess)) return;

        var parsed = ParseVerbose(id, xml, out string reason);
        if (parsed is null)
        {
            lock (_gate)
            {
                _skipped++;
                LastSkipReason = reason;
            }
            LogSkipped(id, reason);
            return;
        }

        Enqueue(parsed);
    }

    private readonly Dictionary<string, DateTime> _skipLogged = new(StringComparer.Ordinal);

    /// <summary>
    /// Records a discarded event in the log.
    ///
    /// This is the counterpart to the "counted" line in the notification path. If
    /// an operator sends seven attempts and the block lands on the fifth, the
    /// difference is explained here instead of being invisible. Each distinct
    /// reason is logged at most once a minute so a busy host cannot flood the file.
    /// </summary>
    private void LogSkipped(int id, string reason)
    {
        lock (_gate)
        {
            if (_skipLogged.TryGetValue(reason, out var last) &&
                (DateTime.UtcNow - last).TotalSeconds < 60) return;
            if (_skipLogged.Count > 64) _skipLogged.Clear();
            _skipLogged[reason] = DateTime.UtcNow;
        }
        Log.Info($"{id} IGNORED - {reason}");
    }

    private void Enqueue(LogonEvent e)
    {
        if (!_chan.Writer.TryWrite(e))
        {
            lock (_gate) { _skipped++; LastSkipReason = "queue full"; }
        }
    }

    /// <summary>Worker thread: does the slow work off the delivery thread.</summary>
    private void Pump()
    {
        var ct = _cts!.Token;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var item = _chan.Reader.ReadAsync(ct).AsTask().GetAwaiter().GetResult();
                lock (_gate) _delivered++;
                Event?.Invoke(item);
            }
            catch (OperationCanceledException) { return; }
            catch (System.Threading.Channels.ChannelClosedException) { return; }
            catch (Exception ex) { Log.Warn($"detect worker: {ex.Message}"); }
        }
    }

    private void MarkUnhealthy()
    {
        lock (_gate)
        {
            IsHealthy = false;
            if (_subscription != IntPtr.Zero)
            {
                try { EvtClose(_subscription); } catch { }
                _subscription = IntPtr.Zero;
            }
        }
    }

    /// <summary>
    /// Re-establishes the subscription after a drop, and persists the bookmark.
    /// Called from the main loop; cheap when nothing is wrong.
    /// </summary>
    public void Maintain()
    {
        lock (_gate)
        {
            if (_subscription == IntPtr.Zero)
            {
                Subscribe();
                return;
            }

            // Keep the bookmark on disk so a hard kill loses at most one save
            // interval of position.
            SaveBookmark();
        }
    }

    /// <summary>Opens a result set for one-off queries. Throws if unreadable.</summary>
    internal static IntPtr OpenQuery(string channel, string xpath, bool newestFirst)
    {
        uint flags = 0x1; // EvtQueryChannelPath
        if (newestFirst) flags |= 0x200; // EvtQueryReverseDirection

        IntPtr h = EvtQuery(IntPtr.Zero, channel, xpath, flags);
        if (h == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            if (err == 5) throw new UnauthorizedAccessException("access to the Security log was denied");
            throw new InvalidOperationException($"EvtQuery failed (win32 {err})");
        }
        return h;
    }

    internal static int Next(IntPtr resultSet, IntPtr[] buffer)
    {
        if (!EvtNext(resultSet, buffer.Length, buffer, 0, 0, out int n))
        {
            int err = Marshal.GetLastWin32Error();
            if (err == 259) return 0; // ERROR_NO_MORE_ITEMS
            throw new InvalidOperationException($"EvtNext failed (win32 {err})");
        }
        return n;
    }

    internal static void CloseEvent(IntPtr h)
    {
        if (h != IntPtr.Zero) EvtClose(h);
    }

    internal static string RenderEvent(IntPtr evt) => Render(evt, RenderEventXml);

    private static string Render(IntPtr handle, uint flags)
    {
        // First call sizes the buffer; it fails with ERROR_INSUFFICIENT_BUFFER
        // and reports how much room is needed.
        EvtRender(IntPtr.Zero, handle, flags, 0, IntPtr.Zero, out int needed, out _);
        if (needed <= 0) return "";

        IntPtr buf = Marshal.AllocHGlobal(needed);
        try
        {
            if (!EvtRender(IntPtr.Zero, handle, flags, needed, buf, out int used, out _)) return "";
            if (used <= 0) return "";

            // The buffer is UTF-16 with a trailing terminator; `used` is bytes.
            int chars = used / sizeof(char);
            if (chars > 0 && Marshal.ReadInt16(buf, (chars - 1) * sizeof(char)) == 0) chars--;
            return Marshal.PtrToStringUni(buf, chars) ?? "";
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    /// <summary>Record id from rendered event XML.</summary>
    public static long ParseRecordId(string xml)
    {
        string v = TagText(xml, "EventRecordID");
        return v.Length > 0 && long.TryParse(v, out var n) ? n : 0;
    }

    /// <summary>Text of the first &lt;tag&gt;value&lt;/tag&gt; in the document.</summary>
    private static string TagText(string xml, string tag)
    {
        int open = xml.IndexOf('<' + tag + '>', StringComparison.Ordinal);
        if (open < 0) return "";
        int start = open + tag.Length + 2;
        int end = xml.IndexOf('<', start);
        return end > start ? xml[start..end] : "";
    }

    private static long FieldInt(string xml, string tag)
    {
        string v = TagText(xml, tag);
        return v.Length > 0 && long.TryParse(v.Trim(), out var n) ? n : 0;
    }

    /// <summary>
    /// Value of an EventData element by its Name attribute.
    ///
    /// Hand-scanned rather than parsed with System.Xml.Linq: the guard only ever
    /// reads six scalar values out of one flat element, and pulling in the whole
    /// XML object model to do it costs a large assembly and a tree of allocations
    /// for every event.
    /// </summary>
    private static string DataField(string xml, string name)
    {
        const string marker = "<Data Name=";
        int i = 0;
        while (true)
        {
            int at = xml.IndexOf(marker, i, StringComparison.Ordinal);
            if (at < 0) return "";
            int q = at + marker.Length;
            if (q >= xml.Length) return "";

            char quote = xml[q];
            if (quote != '\'' && quote != '"') { i = at + 1; continue; }

            int nameStart = q + 1;
            int nameEnd = xml.IndexOf(quote, nameStart);
            if (nameEnd < 0) return "";

            if (nameEnd - nameStart == name.Length &&
                string.CompareOrdinal(xml, nameStart, name, 0, name.Length) == 0)
            {
                int gt = xml.IndexOf('>', nameEnd);
                if (gt < 0) return "";
                int valStart = gt + 1;
                int lt = xml.IndexOf('<', valStart);
                return lt > valStart ? xml[valStart..lt].Trim() : "";
            }
            i = nameEnd + 1;
        }
    }

    /// <summary>Nth EventData value, used only when an event carries no Name attributes.</summary>
    private static string DataFieldOrdinal(string xml, int ordinal)
    {
        const string marker = "<Data ";
        int i = 0, seen = 0;
        while (true)
        {
            int at = xml.IndexOf(marker, i, StringComparison.Ordinal);
            if (at < 0) return "";
            int gt = xml.IndexOf('>', at);
            if (gt < 0) return "";
            int valStart = gt + 1;
            int lt = xml.IndexOf('<', valStart);
            if (lt < 0) return "";
            if (seen == ordinal) return xml[valStart..lt].Trim();
            seen++;
            i = lt;
        }
    }

    /// <summary>SystemTime attribute of TimeCreated, or empty.</summary>
    private static string TimeCreatedRaw(string xml)
    {
        int at = xml.IndexOf("<TimeCreated", StringComparison.Ordinal);
        if (at < 0) return "";
        int sp = xml.IndexOf("SystemTime=", at, StringComparison.Ordinal);
        if (sp < 0) return "";
        int q = sp + 11;
        if (q >= xml.Length) return "";
        char quote = xml[q];
        if (quote != '\'' && quote != '"') return "";
        int start = q + 1;
        int end = xml.IndexOf(quote, start);
        return end > start ? xml[start..end] : "";
    }

    public static LogonEvent? Parse(int eventId, string xml) => ParseVerbose(eventId, xml, out _);

    /// <summary>
    /// As <see cref="Parse"/>, but reports why an event was discarded. Silent
    /// rejection is what makes a broken detector look identical to a quiet day,
    /// so the reason is always available for logging.
    /// </summary>
    public static LogonEvent? ParseVerbose(int eventId, string xml, out string reason)
    {
        reason = "";
        if (string.IsNullOrEmpty(xml) || xml[0] != '<')
        {
            reason = "empty or non-xml payload";
            return null;
        }

        // Name-based lookup, with a positional fallback for hosts that omit the
        // Name attribute. Position alone is not trustworthy: the ordinal layout
        // of a 4625 shifts depending on which optional fields are present.
        string Get(string name, int ordinal)
        {
            string v = DataField(xml, name);
            return v.Length > 0 ? v : DataFieldOrdinal(xml, ordinal);
        }

        string logonType, ip, user, sub = "-";
        if (eventId == LogonFailure)
        {
            // 4625: 0 SubjectUserSid, 1 SubjectUserName, 2 SubjectDomainName,
            // 3 SubjectLogonId, 4 TargetUserSid, 5 TargetUserName, 6 LogonType,
            // 7 TargetDomainName, 8 TargetLogonId, 9 LogonProcessName,
            // 10 AuthPackage, 11 Workstation, 12 LogonGuid, 13 ProcessName,
            // 14 IpAddress, 15 IpPort, 16 SubStatus. (Tests + Windows layout.)
            logonType = Get("LogonType", 6);
            user = Get("TargetUserName", 5);
            ip = Get("IpAddress", 14);
            sub = Get("SubStatus", 16);
        }
        else if (eventId == LogonSuccess)
        {
            // 4624: 4 LogonType, 8 TargetUserName, 13 IpAddress.
            logonType = Get("LogonType", 4);
            user = Get("TargetUserName", 8);
            ip = Get("IpAddress", 13);
        }
        else
        {
            reason = $"event id {eventId} not handled";
            return null;
        }

        if (!IsRdpLogonType(logonType))
        {
            reason = $"logon type '{logonType}' is not a remote logon (need 10, 3 or 5), "
                   + $"ip='{ip}', user='{user}'";
            return null;
        }
        if (ip.Length == 0 || ip == "-")
        {
            reason = "no ip address field";
            return null;
        }
        if (ip.Contains(':'))
        {
            reason = $"ipv6 '{ip}' (not supported)";
            return null;
        }
        if (!Net.TryParseIpv4(ip, out _))
        {
            reason = $"unparsable ip '{ip}'";
            return null;
        }
        if (Net.IsLoopbackOrLocal(ip))
        {
            reason = $"local source '{ip}'";
            return null;
        }

        if (user.Length == 0 || user == "-") user = "unknown";

        string tsRaw = TimeCreatedRaw(xml);
        var when = tsRaw.Length > 0
            && DateTime.TryParse(tsRaw, null, System.Globalization.DateTimeStyles.RoundtripKind, out var parsed)
            ? parsed
            : DateTime.UtcNow;

        int lt = 0;
        int.TryParse(logonType, out lt);
        return new LogonEvent(eventId, ip, user, sub.Length == 0 ? "-" : sub, when, lt);
    }

    // ---- bookmark -----------------------------------------------------------

    private IntPtr LoadBookmark()
    {
        try
        {
            if (!File.Exists(_bookmarkPath)) return IntPtr.Zero;
            string xml = File.ReadAllText(_bookmarkPath).Trim();
            if (xml.Length == 0) return IntPtr.Zero;
            IntPtr bm = EvtCreateBookmark(xml);
            return bm == IntPtr.Zero ? IntPtr.Zero : bm;
        }
        catch
        {
            return IntPtr.Zero;
        }
    }

    private void SaveBookmark()
    {
        if (_nativeBookmark == IntPtr.Zero) return;
        try
        {
            string xml = Render(_nativeBookmark, RenderBookmark);
            if (xml.Length > 0) File.WriteAllText(_bookmarkPath, xml);
        }
        catch { }
    }

    /// <summary>
    /// True for logon types that represent a remote authentication attempt.
    ///
    /// 3  = network (NTLM/NLA, the classic RDP credential check)
    /// 10 = RemoteInteractive (the RDP session logon itself)
    /// 5  = service
    ///
    /// Type 5 is included because a service-type logon failure that carries a real
    /// remote address is a remote authentication attempt, not local noise. This is
    /// the path Microsoft-account (MSA) sign-ins take over RDP, and it was the
    /// cause of a live miscount: seven attempts produced five counted failures and
    /// two discards, so the block landed two attempts late. Genuine local service
    /// logons are unaffected - they arrive with IpAddress "-" and never get past
    /// the remote-address checks below.
    /// </summary>
    private static bool IsRdpLogonType(string v)
    {
        if (v.Length == 0) return false;
        int end = 0;
        while (end < v.Length && char.IsAsciiDigit(v[end])) end++;
        if (end == 0) return false;
        return v[..end] is "10" or "3" or "5";
    }

    public void Dispose()
    {
        try { _cts?.Cancel(); } catch { }
        MarkUnhealthy();
        try { _chan.Writer.TryComplete(); } catch { }
        if (_nativeBookmark != IntPtr.Zero)
        {
            try { EvtClose(_nativeBookmark); } catch { }
            _nativeBookmark = IntPtr.Zero;
        }
    }
}
