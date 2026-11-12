namespace V3Guard;

/// <summary>
/// Product identity and icon lookup.
///
/// The icon is a loose <c>@1.ico</c> beside the executable rather than
/// embedded, so it can be swapped without a rebuild. The dashboard favicon and
/// any future consumer read it through here, and fall back cleanly when the file
/// is absent so a missing icon never breaks the guard.
/// </summary>
public static class Brand
{
    public const string ProductName = "NPav RDP Protection";
    /// <summary>Uppercase form, used as the toast header line.</summary>
    public const string ProductNameUpper = "NPAV RDP PROTECTION";
    public const string ShortName = "NPav";

    /// <summary>File name looked for beside the executable.</summary>
    public const string IconFileName = "@1.ico";

    private static string? _resolved;
    private static bool _searched;

    /// <summary>Full path to the icon, or null when it is not present.</summary>
    public static string? IconPath
    {
        get
        {
            if (_searched) return _resolved;
            _searched = true;

            // Beside the exe first, then the working directory: the guard runs from
            // its own folder, but may be started from elsewhere.
            string[] candidates =
            [
                Path.Combine(AppContext.BaseDirectory, IconFileName),
                Path.Combine(Directory.GetCurrentDirectory(), IconFileName),
            ];

            foreach (var c in candidates)
            {
                try
                {
                    if (File.Exists(c)) { _resolved = c; break; }
                }
                catch { }
            }
            return _resolved;
        }
    }

    public static bool HasIcon => IconPath is not null;

    /// <summary>Raw file bytes, or null when unavailable.</summary>
    public static byte[]? IconBytes()
    {
        var p = IconPath;
        if (p is null) return null;
        try { return File.ReadAllBytes(p); }
        catch { return null; }
    }
}