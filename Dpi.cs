using System.Runtime.InteropServices;

namespace V3Guard;

/// <summary>
/// Display scaling.
///
/// A process that does not declare DPI awareness gets its windows bitmap-stretched
/// by Windows on a scaled display, which makes everything soft and slightly wrong
/// in size. Declaring per-monitor awareness hands the process real pixels, and the
/// toast then scales its own metrics so it stays crisp and correctly proportioned
/// at any setting.
/// </summary>
internal static class Dpi
{
    // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
    private static readonly IntPtr PerMonitorV2 = (IntPtr)(-4);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetProcessDpiAwarenessContext(IntPtr context);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetProcessDPIAware();

    [DllImport("user32.dll")]
    private static extern uint GetDpiForSystem();

    private static float _scale;

    /// <summary>
    /// Must run before any window is created - Windows rejects the change once a
    /// window exists, and silently leaves the old behaviour in place.
    /// </summary>
    public static void Enable()
    {
        try
        {
            if (SetProcessDpiAwarenessContext(PerMonitorV2)) return;
        }
        catch { }

        // Older Windows: system-wide awareness is better than none.
        try { SetProcessDPIAware(); } catch { }
    }

    /// <summary>1.0 at 96 DPI, 1.5 at 144 DPI, and so on.</summary>
    public static float Scale
    {
        get
        {
            if (_scale > 0f) return _scale;
            float dpi = 96f;
            try
            {
                uint d = GetDpiForSystem();
                if (d > 0) dpi = d;
            }
            catch { }
            _scale = dpi / 96f;
            return _scale;
        }
    }

    /// <summary>Scales a design-time pixel value to the current display.</summary>
    public static int S(int designPixels) => (int)MathF.Round(designPixels * Scale);
}
