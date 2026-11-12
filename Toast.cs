using System.Runtime.InteropServices;

namespace V3Guard;

/// <summary>
/// Self-drawn top-right toast.
///
/// Deliberately not a Windows notification: the guard renders its own layered
/// window so the appearance is fully controlled and no WinRT/COM path is needed.
///
/// Drawn with raw GDI and direct pixel compositing rather than System.Drawing.
/// That package drags in System.Private.Windows.Core, GdiPlus and SystemEvents -
/// about 1.85 MB, or 85% of the shipped binary - to fill rounded rectangles and
/// draw three lines of text. Everything here writes the DIB directly with
/// analytic antialiasing, which is also faster and gives tighter control.
/// </summary>
public sealed class ToastHost : IDisposable
{
    /// <summary>Design-time size at 96 DPI; scaled to the display when shown.</summary>
    private const int Width = 384;
    private const int Height = 124;
    private const int Radius = 14;
    /// <summary>Left text margin.</summary>
    private const int Margin = 20;

    private readonly Thread _ui;
    private readonly Queue<Item> _pending = new();
    private readonly object _gate = new();
    private readonly AppSettings _cfg;
    private readonly Dictionary<string, DateTime> _recent = [];
    private DateTime _lastShown = DateTime.MinValue;
    private int _suppressed;
    private volatile bool _stopping;

    internal sealed record Item(
        string Title, string L1, string L2, string L3, uint AccentRgb, int LifeMs)
    {
        public byte R => (byte)(AccentRgb >> 16);
        public byte G => (byte)(AccentRgb >> 8);
        public byte B => (byte)AccentRgb;
    }

    public ToastHost(AppSettings cfg)
    {
        _cfg = cfg;
        _ui = new Thread(UiLoop) { IsBackground = true, Name = "toast" };
        _ui.SetApartmentState(ApartmentState.STA);
        _ui.Start();
    }

    public int Suppressed { get { lock (_gate) return _suppressed; } }

    /// <summary>
    /// Throttled entry point. Repeats for the same address inside the cooldown
    /// window are counted and folded into the next toast as "+N more" rather than
    /// stacking notifications.
    /// </summary>
    public void Notify(NoticeKind kind, string title, string l1, string l2 = "", string l3 = "", string accent = "#e0483d")
    {
        lock (_gate)
        {
            if (!_cfg.ToastEnabled && kind == NoticeKind.Block)
            {
                _suppressed++;
                Log.Info($"toast suppressed (toasts are disabled in settings): {title}");
                return;
            }

            var now = DateTime.UtcNow;
            if (kind == NoticeKind.Block)
            {
                string ip = l1.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
                if (ip.Length > 0)
                {
                    if (_recent.TryGetValue(ip, out var prev) &&
                        (now - prev).TotalSeconds < _cfg.ToastCooldownSeconds)
                    {
                        _suppressed++;
                        Log.Info($"toast suppressed (cooldown {_cfg.ToastCooldownSeconds}s for {ip}): {title}");
                        return;
                    }
                    _recent[ip] = now;
                    if (_recent.Count > 128) _recent.Clear();
                }
            }

            if ((now - _lastShown).TotalSeconds < _cfg.ToastMinGapSeconds)
            {
                _suppressed++;
                Log.Info($"toast suppressed (min-gap {_cfg.ToastMinGapSeconds}s): {title}");
                return;
            }

            _lastShown = now;
            if (_suppressed > 0 && kind == NoticeKind.Block)
                l1 += $"  (+{_suppressed} more suppressed)";
            _suppressed = 0;

            _pending.Enqueue(new Item(title, l1, l2, l3, ParseRgb(accent),
                Math.Clamp(_cfg.ToastDisplaySeconds, 3, 120) * 1000));
            if (_pending.Count > 8) _pending.Dequeue();
        }
    }

    private static uint ParseRgb(string hex)
    {
        var s = hex.TrimStart('#');
        return uint.TryParse(s, System.Globalization.NumberStyles.HexNumber, null, out var v) ? v : 0xE0483D;
    }

    private Item? Take()
    {
        lock (_gate) return _pending.Count > 0 ? _pending.Dequeue() : null;
    }

    private void UiLoop()
    {
        try
        {
            Native.Register();
        }
        catch (Exception ex)
        {
            Log.Warn($"toast init failed, notifications disabled: {ex.Message}");
            return;
        }

        while (!_stopping)
        {
            var item = Take();
            if (item is null) { Thread.Sleep(300); continue; }
            try { Native.ShowToast(item, Dpi.S(Width), Dpi.S(Height), Dpi.S(Radius)); }
            catch (Exception ex) { Log.Warn($"toast render failed: {ex.Message}"); }
        }
    }

    public void Dispose() => _stopping = true;

    /// <summary>Diagnostics: how often Windows asked the toast to set the cursor.</summary>
    public static int SetCursorMessages => Native.SetCursorMessages;
    public static int MouseMoveMessages => Native.MouseMoveMessages;
    /// <summary>Diagnostics: how often the close glyph was clicked.</summary>
    public static int CloseClicks => Native.CloseClicks;
    /// <summary>Diagnostics: how many button messages reached the toast window.</summary>
    public static int ButtonMessages => Native.ButtonMessages;
}

/// <summary>Layered-window plumbing and the software renderer.</summary>
internal static unsafe class Native
{
    private const uint WS_POPUP = 0x80000000;
    private const uint WS_EX_LAYERED = 0x00080000;
    private const uint WS_EX_TOPMOST = 0x00000008;
    private const uint WS_EX_TOOLWINDOW = 0x00000080;
    private const uint WS_EX_NOACTIVATE = 0x08000000;
    private const int ULW_ALPHA = 0x02;
    private const byte AcSrcOver = 0x00;
    private const int SwShowNoActivate = 4;
    private const uint SpiGetWorkArea = 0x0030;
    private const string ClassName = "NpavToastV3";

    // DrawText format flags. DT_SINGLELINE is 0x0020 - NOT 0x0001, which is
    // DT_CENTER. Using 0x0001 silently centre-aligned every line, which is what
    // made the card look wrong despite the DT_LEFT flag being present.
    private const uint DT_LEFT = 0x0000, DT_SINGLELINE = 0x0020,
                       DT_NOCLIP = 0x0100, DT_NOPREFIX = 0x0800;
    private const int TRANSPARENT = 1;

    [StructLayout(LayoutKind.Sequential)] private struct Pt { public int X, Y; }
    [StructLayout(LayoutKind.Sequential)] private struct Size { public int Cx, Cy; }
    [StructLayout(LayoutKind.Sequential)] private struct Rect { public int Left, Top, Right, Bottom; }
    [StructLayout(LayoutKind.Sequential)] private struct Blend { public byte Op, Flags, Alpha, Format; }

    [StructLayout(LayoutKind.Sequential)]
    private struct BitmapInfo
    {
        public int Size, Width, Height;
        public short Planes, BitCount;
        public int Compression, SizeImage, XPels, YPels, ClrUsed, ClrImportant;
    }

    /// <summary>
    /// WNDCLASSEXW. Every field is a pointer-sized value: it must contain no
    /// managed references, because its address is taken and passed to Win32. An
    /// earlier version used string fields for the two name slots, which made the
    /// struct non-blittable - RegisterClassExW then failed with
    /// ERROR_INVALID_PARAMETER (87) and no toast could ever appear.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct WndClassEx
    {
        public int Size;
        public int Style;
        public IntPtr WndProc;
        public int ClsExtra;
        public int WndExtra;
        public IntPtr Instance;
        public IntPtr Icon;
        public IntPtr Cursor;
        public IntPtr Background;
        public IntPtr MenuName;
        public IntPtr ClassName;
        public IntPtr SmallIcon;
    }

    private delegate IntPtr WndProcDelegate(IntPtr h, uint m, IntPtr w, IntPtr l);
    private static WndProcDelegate? _wndProcKeepAlive;

    // ExactSpelling is required on every W-suffixed import. Without it the
    // runtime appends another W (DrawTextW becomes DrawTextWW) and the lookup
    // fails - silently, for calls whose result is unused.
    [DllImport("user32.dll", SetLastError = true)]
    private static extern ushort RegisterClassExW(WndClassEx* c);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr CreateWindowExW(uint ex, IntPtr className, IntPtr title, uint style,
        int x, int y, int w, int h, IntPtr parent, IntPtr menu, IntPtr inst, IntPtr param);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool UpdateLayeredWindow(IntPtr h, IntPtr hdcDst, Pt* dst, Size* size,
        IntPtr hdcSrc, Pt* src, uint key, ref Blend blend, uint flags);
    [DllImport("user32.dll")] private static extern IntPtr GetDC(IntPtr h);
    [DllImport("user32.dll")] private static extern int ReleaseDC(IntPtr h, IntPtr dc);

    // Message pump. A window whose owning thread never drains its message queue is
    // treated by Windows as not responding, and the pointer over it changes to the
    // busy "app starting" cursor. The toast holds the screen for seconds, so it has
    // to keep pumping rather than sleeping.
    [StructLayout(LayoutKind.Sequential)]
    private struct Msg
    {
        public IntPtr Hwnd;
        public uint Message;
        public IntPtr WParam;
        public IntPtr LParam;
        public uint Time;
        public int PtX, PtY;
    }

    private const uint PM_REMOVE = 0x0001;

    [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "PeekMessageW")]
    private static extern bool PeekMessage(out Msg msg, IntPtr hwnd, uint min, uint max, uint remove);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref Msg msg);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "DispatchMessageW")]
    private static extern IntPtr DispatchMessage(ref Msg msg);

    /// <summary>
    /// Waits for the given time while keeping the message queue drained, so the
    /// window stays responsive and the pointer keeps its normal shape.
    ///
    /// When <paramref name="abortable"/> is set the wait ends early if the close
    /// button was clicked, which is how dismissing works.
    /// </summary>
    private static void PumpFor(int ms, bool abortable = false)
    {
        long end = Environment.TickCount64 + ms;
        while (true)
        {
            while (PeekMessage(out Msg msg, IntPtr.Zero, 0, 0, PM_REMOVE))
            {
                TranslateMessage(ref msg);
                DispatchMessage(ref msg);
            }
            if (abortable && _closeRequested) return;
            long remaining = end - Environment.TickCount64;
            if (remaining <= 0) return;
            Thread.Sleep((int)Math.Min(15, remaining));
        }
    }

    /// <summary>Set when the close glyph is clicked; cleared for each new toast.</summary>
    private static volatile bool _closeRequested;

    /// <summary>Diagnostics: how many times the close hit test succeeded.</summary>
    public static int CloseClicks => _closeClicks;
    private static int _closeClicks;

    /// <summary>Diagnostics: how many button messages reached the window at all.</summary>
    public static int ButtonMessages => _leftDownMessages;
    private static int _leftDownMessages;

    private const uint WM_LBUTTONUP = 0x0202;
    private const uint WM_MOUSEACTIVATE = 0x0021;
    /// <summary>Deliver the click but do not activate the window.</summary>
    private const int MA_NOACTIVATE = 3;

    /// <summary>Current toast size, needed to locate the close glyph.</summary>
    private static int _toastW, _toastH;

    private const uint WM_LBUTTONDOWN = 0x0201;

    /// <summary>
    /// Whether a client-area point lands on the close glyph.
    ///
    /// The target is deliberately larger than the drawn X: the glyph is about
    /// 14px, which is an awkward click target, so the hit area is padded out to
    /// roughly 34px square.
    /// </summary>
    private static bool HitClose(int mx, int my)
    {
        int pad = Dpi.S(10);
        int x0 = _toastW - Dpi.S(34) - pad;
        int x1 = _toastW - Dpi.S(10) + pad;
        int y0 = Dpi.S(16) - pad;
        int y1 = Dpi.S(46) + pad;
        return mx >= x0 && mx <= x1 && my >= y0 && my <= y1;
    }

    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr h, int cmd);
    [DllImport("user32.dll")] private static extern bool DestroyWindow(IntPtr h);
    [DllImport("user32.dll")] private static extern bool SystemParametersInfo(uint a, uint b, ref Rect r, uint f);

    [DllImport("gdi32.dll")] private static extern IntPtr CreateCompatibleDC(IntPtr dc);
    [DllImport("gdi32.dll")] private static extern IntPtr CreateDIBSection(IntPtr dc, ref BitmapInfo bi, uint usage, out IntPtr bits, IntPtr section, uint offset);
    [DllImport("gdi32.dll")] private static extern IntPtr SelectObject(IntPtr dc, IntPtr obj);
    [DllImport("gdi32.dll")] private static extern bool DeleteObject(IntPtr obj);
    [DllImport("gdi32.dll")] private static extern bool DeleteDC(IntPtr dc);
    [DllImport("gdi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern IntPtr CreateFontW(int height, int width, int escapement, int orientation,
        int weight, uint italic, uint underline, uint strikeout, uint charset, uint outPrecision,
        uint clipPrecision, uint quality, uint pitchAndFamily, string face);
    [DllImport("gdi32.dll")] private static extern int SetTextColor(IntPtr dc, int color);
    [DllImport("gdi32.dll")] private static extern int SetBkMode(IntPtr dc, int mode);
    // DrawTextW is exported by user32, not gdi32, despite being a text call.
    [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int DrawTextW(IntPtr dc, string text, int len, ref Rect r, uint flags);

    private const int FW_NORMAL = 400, FW_SEMIBOLD = 600;
    private const uint DEFAULT_CHARSET = 1, CLEARTYPE_QUALITY = 5, DEFAULT_PITCH = 0;
    /// <summary>Left text margin inside the card.</summary>
    private const int Margin = 20;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr LoadCursorW(IntPtr instance, IntPtr cursorName);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetCursor(IntPtr cursor);

    /// <summary>IDC_ARROW as a resource ordinal, for LoadCursorW.</summary>
    private static readonly IntPtr CursorArrowId = (IntPtr)32512;

    /// <summary>
    /// The real HCURSOR behind <see cref="CursorArrowId"/>, obtained once from
    /// LoadCursorW.
    ///
    /// SetCursor needs an actual cursor handle. Passing the resource ordinal -
    /// as an earlier version did - silently does nothing, so the pointer keeps
    /// whatever shape the last window set (a spinner left behind by another
    /// process, for instance).
    /// </summary>
    private static IntPtr _arrowCursor;

    private static IntPtr ArrowCursor
    {
        get
        {
            if (_arrowCursor == IntPtr.Zero)
                _arrowCursor = LoadCursorW(IntPtr.Zero, CursorArrowId);
            return _arrowCursor;
        }
    }

    private const uint WM_SETCURSOR = 0x0020;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr GetModuleHandleW(string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ProcessIdToSessionId(uint pid, out uint sessionId);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern IntPtr DefWindowProcW(IntPtr h, uint msg, IntPtr w, IntPtr l);

    public static void Register()
    {
        _wndProcKeepAlive = DefWndProc;
        // hInstance must be the module handle, not the process handle. Passing the
        // process handle still registers on most builds, but it is the wrong value
        // and makes the class lookup unreliable.
        IntPtr instance = GetModuleHandleW(null);

        // The class name has to outlive the call: it is passed as a raw pointer and
        // Win32 copies it during registration, but the pointer must be valid then.
        // It is never freed - a few bytes for the life of the process.
        _classNamePtr ??= Marshal.StringToHGlobalUni(ClassName);

        var wc = new WndClassEx
        {
            Size = Marshal.SizeOf<WndClassEx>(),
            WndProc = Marshal.GetFunctionPointerForDelegate(_wndProcKeepAlive),
            Instance = instance,
            ClassName = _classNamePtr.Value,
            // A NULL class cursor is not "use the default": Windows then leaves the
            // cursor exactly as it was, so moving onto the toast from a text field
            // kept showing the I-beam. Supplying the wanted handle fixes it.
            Cursor = ArrowCursor,
        };
        ushort atom = RegisterClassExW(&wc);
        if (atom == 0)
        {
            int err = Marshal.GetLastWin32Error();
            // 1410 = ERROR_CLASS_ALREADY_EXISTS, which is harmless.
            if (err != 1410)
                Log.Error($"RegisterClassExW failed win32={err} - toasts will not appear");
            else
                Log.Info("toast window class already registered");
        }
        else
        {
            Log.Info($"toast window class registered (atom={atom})");
        }
        // Session diagnostics: if the guard is started by the scheduler or a
        // service in session 0, its toasts render on a desktop nobody sees while
        // the dashboard keeps working - indistinguishable from a broken toast
        // until the session is recorded here.
        try
        {
            uint sid = 0;
            if (ProcessIdToSessionId((uint)Environment.ProcessId, out sid) != 0)
                Log.Info($"toast thread session={sid} interactive={Environment.UserInteractive}");
        }
        catch { }
        _instance = instance;
    }

    private static IntPtr _instance;
    private static IntPtr? _classNamePtr;

    /// <summary>
    /// Every message must reach DefWindowProc. Returning zero for everything - as
    /// an earlier version did - is read by Windows as a failure during
    /// WM_NCCREATE, so CreateWindowExW returned NULL with no error code set and no
    /// toast could be created.
    ///
    /// WM_SETCURSOR and WM_MOUSEMOVE both force the arrow. WM_SETCURSOR is the
    /// documented place, but if the window is judged busy Windows shows the
    /// app-starting cursor instead, so the pointer is re-asserted on every mouse
    /// move as well.
    /// </summary>
    private static IntPtr DefWndProc(IntPtr h, uint m, IntPtr w, IntPtr l)
    {
        if (m == WM_SETCURSOR)
        {
            Interlocked.Increment(ref _setCursorMessages);
            IntPtr arrow = ArrowCursor;
            if (arrow != IntPtr.Zero)
            {
                SetCursor(arrow);
                return (IntPtr)1; // handled
            }
            // No valid handle: let the class cursor apply rather than swallowing
            // the message and leaving the previous shape in place.
            return DefWindowProcW(h, m, w, l);
        }
        if (m == WM_MOUSEMOVE)
        {
            Interlocked.Increment(ref _mouseMoveMessages);
            IntPtr arrow = ArrowCursor;
            if (arrow != IntPtr.Zero) SetCursor(arrow);
            return (IntPtr)0;
        }
        if (m == WM_MOUSEACTIVATE)
        {
            // A WS_EX_NOACTIVATE window still initiates an activation when
            // clicked, and that attempt swallows the button message - the window
            // sees pointer movement but never WM_LBUTTONDOWN, so the close glyph
            // could not be clicked. MA_NOACTIVATE tells Windows to deliver the
            // click without activating us.
            return (IntPtr)MA_NOACTIVATE;
        }
        if (m == WM_LBUTTONDOWN)
        {
            Interlocked.Increment(ref _leftDownMessages);
            // Client coordinates arrive packed into lParam as two signed shorts.
            long lp = l.ToInt64();
            int mx = unchecked((short)(lp & 0xFFFF));
            int my = unchecked((short)((lp >> 16) & 0xFFFF));
            if (HitClose(mx, my))
            {
                Interlocked.Increment(ref _closeClicks);
                _closeRequested = true;   // the display loop stops on this
            }
            return (IntPtr)0;
        }
        if (m == WM_LBUTTONUP)
        {
            Interlocked.Increment(ref _leftDownMessages);
            long lp = l.ToInt64();
            int mx = unchecked((short)(lp & 0xFFFF));
            int my = unchecked((short)((lp >> 16) & 0xFFFF));
            if (HitClose(mx, my))
            {
                Interlocked.Increment(ref _closeClicks);
                _closeRequested = true;
            }
            return (IntPtr)0;
        }
        return DefWindowProcW(h, m, w, l);
    }

    /// <summary>Diagnostics: how often Windows asked us to set the cursor.</summary>
    public static int SetCursorMessages => Volatile.Read(ref _setCursorMessages);
    public static int MouseMoveMessages => Volatile.Read(ref _mouseMoveMessages);
    private static int _setCursorMessages;
    private static int _mouseMoveMessages;

    private const uint WM_MOUSEMOVE = 0x0200;

    private static Rect WorkArea()
    {
        var r = default(Rect);
        SystemParametersInfo(SpiGetWorkArea, 0, ref r, 0);
        return r;
    }

    /// <summary>Renders the card into a premultiplied 32-bit DIB and shows it.</summary>
    public static void ShowToast(ToastHost.Item item, int width, int height, int radius)
    {
        // Fresh toast: clear any dismissal left over from the previous one, and
        // record the size so the window proc can locate the close glyph.
        _closeRequested = false;
        _toastW = width;
        _toastH = height;

        IntPtr screenDc = GetDC(IntPtr.Zero);
        IntPtr memDc = CreateCompatibleDC(screenDc);
        var bmi = new BitmapInfo
        {
            Size = Marshal.SizeOf<BitmapInfo>(),
            Width = width,
            Height = -height, // negative: top-down
            Planes = 1,
            BitCount = 32,
        };

        IntPtr bmp = CreateDIBSection(memDc, ref bmi, 0, out IntPtr bits, IntPtr.Zero, 0);
        if (bmp == IntPtr.Zero)
        {
            Log.Error($"CreateDIBSection failed win32={Marshal.GetLastWin32Error()}");
            DeleteDC(memDc);
            ReleaseDC(IntPtr.Zero, screenDc);
            return;
        }

        IntPtr old = SelectObject(memDc, bmp);
        try
        {
            Render((byte*)bits, memDc, width, height, radius, item);
            DumpIfRequested((byte*)bits, width, height, item.Title);

            var wa = WorkArea();
            int x = wa.Right - width - 20;
            int y = wa.Top + 20;

            IntPtr hwnd = CreateWindowExW(
                WS_EX_LAYERED | WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                _classNamePtr ?? IntPtr.Zero, IntPtr.Zero, WS_POPUP,
                x, y, width, height,
                IntPtr.Zero, IntPtr.Zero, _instance, IntPtr.Zero);

            if (hwnd == IntPtr.Zero)
            {
                // Previously this returned silently, which made a toast that never
                // appeared indistinguishable from one that worked.
                Log.Error($"CreateWindowExW failed win32={Marshal.GetLastWin32Error()} - toast not shown");
                return;
            }

            try
            {
                var size = new Size { Cx = width, Cy = height };
                var origin = new Pt { X = 0, Y = 0 };

                // Fade in while sliding in from the right.
                //
                // The blend is re-applied through UpdateLayeredWindow on every
                // frame. Two earlier mistakes made the toast invisible:
                // MoveWindow was called with width and height of zero, which
                // resized it away to nothing; and SetLayeredWindowAttributes was
                // used for the fade, which replaces the per-pixel alpha that
                // UpdateLayeredWindow set up and stops the card compositing.
                const int steps = 8;
                for (int i = 1; i <= steps; i++)
                {
                    float f = i / (float)steps;
                    var d = new Pt { X = x + (int)((1 - f) * 48), Y = y };
                    var b = new Blend { Op = AcSrcOver, Flags = 0, Alpha = (byte)(f * 255), Format = 1 };
                    if (!UpdateLayeredWindow(hwnd, screenDc, &d, &size, memDc, &origin, 0, ref b, ULW_ALPHA))
                    {
                        Log.Error($"UpdateLayeredWindow failed win32={Marshal.GetLastWin32Error()}");
                        return;
                    }
                    // Shown only once the surface has real content, so it never
                    // flashes an empty frame at full size.
                    if (i == 1) ShowWindow(hwnd, SwShowNoActivate);
                    PumpFor(18);
                }

                // Confirmed on screen: the window has real per-pixel alpha content
                // and visible coordinates. Without this line a toast that reached
                // the wrong desktop or session looked identical to one that
                // silently failed.
                Log.Info($"toast shown: {item.Title} - {item.L1}");

                // Hold. Pumping rather than sleeping is what keeps the window
                // responsive so Windows does not mark it hung. Abortable so the
                // close button can cut the wait short.
                PumpFor(item.LifeMs, abortable: true);

                for (int i = steps; i >= 0; i--)
                {
                    float f = i / (float)steps;
                    var d = new Pt { X = x, Y = y };
                    var b = new Blend { Op = AcSrcOver, Flags = 0, Alpha = (byte)(f * 255), Format = 1 };
                    UpdateLayeredWindow(hwnd, screenDc, &d, &size, memDc, &origin, 0, ref b, ULW_ALPHA);
                    // A dismissal fades out quickly instead of playing the full
                    // animation, so the click feels immediate.
                    PumpFor(_closeRequested ? 4 : 18);
                }
            }
            finally
            {
                DestroyWindow(hwnd);
            }
        }
        finally
        {
            SelectObject(memDc, old);
            DeleteObject(bmp);
            DeleteDC(memDc);
            ReleaseDC(IntPtr.Zero, screenDc);
        }
    }

    /// <summary>
    /// Writes the rendered card to a 32-bit BMP when V3_DUMP_TOAST is set.
    ///
    /// The appearance of a toast can only be judged by looking at it, and the
    /// window is gone in seconds. This makes the exact pixels reviewable.
    /// </summary>
    private static void DumpIfRequested(byte* px, int w, int h, string title)
    {
        string? dir = Environment.GetEnvironmentVariable("V3_DUMP_TOAST");
        if (string.IsNullOrEmpty(dir)) return;
        try
        {
            Directory.CreateDirectory(dir);
            string safe = new string(title.Where(char.IsLetterOrDigit).ToArray());
            if (safe.Length == 0) safe = "toast";
            string path = Path.Combine(dir, safe + ".bmp");

            int stride = w * 4;
            int imageSize = stride * h;
            using var fs = new FileStream(path, FileMode.Create, FileAccess.Write);
            using var bw = new BinaryWriter(fs);

            bw.Write((byte)'B'); bw.Write((byte)'M');
            bw.Write(54 + imageSize);
            bw.Write(0);
            bw.Write(54);
            bw.Write(40);
            bw.Write(w);
            bw.Write(h);            // positive: bottom-up
            bw.Write((short)1);
            bw.Write((short)32);
            bw.Write(0);
            bw.Write(imageSize);
            bw.Write(2835); bw.Write(2835);
            bw.Write(0); bw.Write(0);

            // BMP rows run bottom-up, and the DIB is top-down BGRA.
            for (int y = h - 1; y >= 0; y--)
                for (int x = 0; x < w; x++)
                {
                    byte* p = px + (y * w + x) * 4;
                    bw.Write(p[0]); bw.Write(p[1]); bw.Write(p[2]); bw.Write((byte)255);
                }
        }
        catch (Exception ex)
        {
            Log.Warn($"toast dump failed: {ex.Message}");
        }
    }

    // ---- software renderer --------------------------------------------------

    private static void Render(byte* px, IntPtr dc, int w, int h, int radius, ToastHost.Item t)
    {
        // Every metric below is a design value at 96 DPI; S() scales it to the
        // display so the card keeps its proportions and the text stays sharp.
        int S(int v) => Dpi.S(v);
        int margin = S(Margin);

        // Drop shadow: nested rounded rects with falling alpha approximate a blur.
        for (int i = S(5); i >= 1; i--)
            FillRoundRect(px, w, h,
                new Rect { Left = -i, Top = -i + S(3), Right = w + i, Bottom = h + i },
                radius + i, 0, 0, 0, 0.05f);

        var card = new Rect { Left = 0, Top = 0, Right = w, Bottom = h };
        FillRoundRect(px, w, h, card, radius, 255, 255, 255, 1f);

        // Left accent stripe, clipped to the card's rounded edge.
        int stripe = S(6);
        for (int y = 0; y < h; y++)
            for (int x = 0; x < stripe && x < w; x++)
            {
                float cov = RoundRectCoverage(x + 0.5f, y + 0.5f, card, radius);
                if (cov > 0) BlendPixel(px, w, x, y, t.R, t.G, t.B, cov);
            }

        // Brand line, then the title and body. There is no icon: the product name
        // is the branding, which keeps the card quiet and lets the message carry
        // the emphasis.
        DrawTextLine(dc, w, Brand.ProductNameUpper, margin, S(16), -S(11), FW_SEMIBOLD,
                     t.R, t.G, t.B);

        int y0 = DrawTextLine(dc, w, t.Title, margin, S(36), -S(17), FW_SEMIBOLD, 22, 27, 32);
        y0 += S(4);
        if (t.L1.Length > 0) y0 = DrawTextLine(dc, w, Clip(t.L1, 46), margin, y0, -S(13), FW_NORMAL, 56, 63, 71) + S(2);
        if (t.L2.Length > 0) y0 = DrawTextLine(dc, w, Clip(t.L2, 52), margin, y0, -S(13), FW_NORMAL, 56, 63, 71) + S(2);
        if (t.L3.Length > 0) DrawTextLine(dc, w, Clip(t.L3, 64), margin, y0, -S(13), FW_NORMAL, 126, 136, 146);

        // Dismiss affordance.
        DrawLine(px, w, h, w - S(30), S(24), w - S(16), S(38), 150, 156, 162, 0.85f, S(1));
        DrawLine(px, w, h, w - S(16), S(24), w - S(30), S(38), 150, 156, 162, 0.85f, S(1));

        // GDI does not write the alpha byte, so freshly drawn text would be
        // invisible. Inside the card the only non-white pixels are glyphs, so any
        // such pixel is forced fully opaque.
        //
        // The scan is inset past the corner radius: the rounded edge and the drop
        // shadow also contain non-white pixels, and forcing those opaque would
        // square off the corners.
        int inset = radius + 2;
        for (int y = inset; y < h - inset; y++)
            for (int x = inset; x < w - inset; x++)
            {
                byte* p = px + (y * w + x) * 4;
                if (p[3] == 255) continue;
                if (p[0] == 255 && p[1] == 255 && p[2] == 255) continue;
                p[3] = 255;
            }
    }

    /// <summary>Draws one line of text and returns the y coordinate below it.</summary>
    private static int DrawTextLine(IntPtr dc, int w, string text, int x, int y,
        int fontHeight, int weight, byte r, byte g, byte b)
    {
        IntPtr font = CreateFontW(fontHeight, 0, 0, 0, weight, 0, 0, 0,
            DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, DEFAULT_PITCH, "Segoe UI");
        IntPtr oldFont = font == IntPtr.Zero ? IntPtr.Zero : SelectObject(dc, font);
        try
        {
            SetBkMode(dc, TRANSPARENT);
            // GDI wants a COLORREF: 0x00BBGGRR.
            SetTextColor(dc, (b << 16) | (g << 8) | r);
            var rect = new Rect
            {
                Left = x,
                Top = y,
                Right = w - Dpi.S(16),
                Bottom = y + Math.Abs(fontHeight) + Dpi.S(6),
            };
            DrawTextW(dc, text, text.Length, ref rect, DT_LEFT | DT_SINGLELINE | DT_NOCLIP | DT_NOPREFIX);
            return y + Math.Abs(fontHeight);
        }
        finally
        {
            if (oldFont != IntPtr.Zero) SelectObject(dc, oldFont);
            if (font != IntPtr.Zero) DeleteObject(font);
        }
    }

    /// <summary>Antialiased line via distance-to-segment.</summary>
    private static void DrawLine(byte* px, int w, int h,
        float x0, float y0, float x1, float y1, byte r, byte g, byte b,
        float alpha, float halfWidth = 0.9f)
    {
        int minX = (int)MathF.Min(x0, x1) - 3, maxX = (int)MathF.Max(x0, x1) + 3;
        int minY = (int)MathF.Min(y0, y1) - 3, maxY = (int)MathF.Max(y0, y1) + 3;

        float dx = x1 - x0, dy = y1 - y0;
        float len2 = dx * dx + dy * dy;

        for (int y = Math.Max(0, minY); y <= Math.Min(h - 1, maxY); y++)
            for (int x = Math.Max(0, minX); x <= Math.Min(w - 1, maxX); x++)
            {
                float pxc = x + 0.5f, pyc = y + 0.5f;
                float tt = len2 <= 0 ? 0 : Math.Clamp(((pxc - x0) * dx + (pyc - y0) * dy) / len2, 0, 1);
                float nx = x0 + tt * dx, ny = y0 + tt * dy;
                float ddx = pxc - nx, ddy = pyc - ny;
                float d = MathF.Sqrt(ddx * ddx + ddy * ddy);
                float cov = Cover(d - (halfWidth - 0.5f));
                if (cov > 0) BlendPixel(px, w, x, y, r, g, b, cov * alpha);
            }
    }

    private static void FillRoundRect(byte* px, int w, int h, Rect r, int radius,
        byte cr, byte cg, byte cb, float alpha)
    {
        for (int y = Math.Max(0, r.Top); y < Math.Min(h, r.Bottom); y++)
            for (int x = Math.Max(0, r.Left); x < Math.Min(w, r.Right); x++)
            {
                float cov = RoundRectCoverage(x + 0.5f, y + 0.5f, r, radius);
                if (cov > 0) BlendPixel(px, w, x, y, cr, cg, cb, cov * alpha);
            }
    }

    /// <summary>Coverage of a pixel by a rounded rectangle, via a signed distance field.</summary>
    private static float RoundRectCoverage(float x, float y, Rect r, float radius)
    {
        float halfW = (r.Right - r.Left) / 2f, halfH = (r.Bottom - r.Top) / 2f;
        float cxp = r.Left + halfW, cyp = r.Top + halfH;
        radius = MathF.Min(radius, MathF.Min(halfW, halfH));

        float qx = MathF.Abs(x - cxp) - (halfW - radius);
        float qy = MathF.Abs(y - cyp) - (halfH - radius);
        float mx = MathF.Max(qx, 0), my = MathF.Max(qy, 0);
        float d = MathF.Sqrt(mx * mx + my * my) + MathF.Min(MathF.Max(qx, qy), 0) - radius;
        return Cover(d);
    }

    /// <summary>Converts a signed distance to edge coverage in [0,1].</summary>
    private static float Cover(float d) => Math.Clamp(0.5f - d, 0f, 1f);

    /// <summary>Source-over blend into a premultiplied BGRA pixel.</summary>
    private static void BlendPixel(byte* px, int w, int x, int y, byte r, byte g, byte b, float a)
    {
        if (a <= 0) return;
        if (a > 1) a = 1;
        byte* p = px + (y * w + x) * 4;
        float ia = 1f - a;
        p[0] = (byte)(b * a + p[0] * ia);
        p[1] = (byte)(g * a + p[1] * ia);
        p[2] = (byte)(r * a + p[2] * ia);
        p[3] = (byte)(255 * a + p[3] * ia);
    }

    private static string Clip(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "â€¦";
}