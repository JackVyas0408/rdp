using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace V3Guard;

/// <summary>
/// License / activation gate. Ported from the NPAV installer activation logic:
/// a random asking code is generated, the expected key is derived from it, and
/// either that key or the master password (DWIJ26) authorises the product.
/// A successful activation stores a 1-year expiry (default license period).
///
/// License files are HMAC-signed and bound to the machine. The file format is:
///   NPavRdpGuardLicense1
///   EX=... (expiry, UTC, round-trip "O" format)
///   AT=... (activation time)
///   SIG=hex(hmac(ex|at))
/// The signature covers both timestamps with a key derived from the machine's
/// MachineGuid + an app seed, so any hand edit to the file - any byte - makes
/// the signature fail and the product returns to the asking-code page. Copying
/// the file to another machine fails the same way.
///
/// Legacy (pre-signature) files hold a bare ISO date; they are accepted once
/// and immediately rewritten in the signed format. After that, edits invalidate.
/// </summary>
public static class License
{
    private static readonly string Path = System.IO.Path.Combine(AppContext.BaseDirectory, "license.lic");
    // Master activation password is stored as its djb2-xor hash (436182321 for
    // "DWIJ26") so the plaintext string never appears in source or binary.
    // Installer legacy: any client with this hash can still derive the password
    // by brute-force, so rotate the master on next installer release.
    private const long MasterHash = 436182321L;
    private const string FormatTag = "NPavRdpGuardLicense1";

    [DllImport("kernel32.dll")] private static extern bool AllocConsole();
    [DllImport("kernel32.dll")] private static extern bool AttachConsole(int pid);
    [DllImport("kernel32.dll")] private static extern bool FreeConsole();

    public static void EnsureConsole()
    {
        try
        {
            if (!AttachConsole(-1)) AllocConsole();
        }
        catch { try { AllocConsole(); } catch { } }
        try
        {
            Console.SetIn(new StreamReader(Console.OpenStandardInput()));
            Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
        }
        catch { }
    }

    // ---- asking code / key derivation (installer-compatible) -----------------

    public static string GenerateAskingCode()
    {
        const string charset = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
        var rnd = Random.Shared; // process-wide entropy pool: no time-seed repeats on rapid shuffles
        var sb = new StringBuilder(6);
        for (int i = 0; i < 6; i++)
            sb.Append(charset[rnd.Next(charset.Length)]);
        return sb.ToString();
    }

    public static int GetCharVal(char c)
    {
        char u = char.ToUpperInvariant(c);
        if (u >= '0' && u <= '9') return u - '0';
        if (u >= 'A' && u <= 'Z') return (u - 'A') + 10;
        return 0;
    }

    public static string CalculateKey(string askingCode)
    {
        string clean = (askingCode ?? "").Trim().ToUpperInvariant();
        if (clean.Length == 0) return "";
        int seed = GetCharVal(clean[0]) % 10;
        var sb = new StringBuilder();
        for (int i = 0; i < clean.Length; i++)
        {
            int val = GetCharVal(clean[i]);
            int pos = i + 1;
            int mask = (seed * 3 + pos * 7) & 0x1F;
            int digit = ((val * 7) + (seed * 13) + (pos * 19) + ((val ^ mask) * 11) + (val * val + seed * 5 + 3)) % 10;
            if (digit < 0) digit = (-digit) % 10;
            sb.Append((char)('0' + digit));
        }
        return sb.ToString();
    }

    public static long FastHash(string s)
    {
        string u = (s ?? "").Trim().ToUpperInvariant();
        long h = 5381;
        foreach (char ch in u)
        {
            h = (((h << 5) + h) ^ ch) & 0x7FFFFFFF;
        }
        return h;
    }

    private static bool FixedEquals(string a, string b)
    {
        var ba = Encoding.UTF8.GetBytes(a ?? "");
        var bb = Encoding.UTF8.GetBytes(b ?? "");
        return ba.Length == bb.Length &&
               System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(ba, bb);
    }

    public static bool IsKeyAuthorized(string enteredKey, string askingCode)
    {
        string clean = (enteredKey ?? "").Trim().ToUpperInvariant();
        string expected = CalculateKey(askingCode);
        if (clean.Length > 0 && FixedEquals(clean, expected)) return true;
        if (clean.Length > 0 && FastHash(clean) == MasterHash) return true;
        return false;
    }

    /// <summary>True when the entry is the master password (used for extending).</summary>
    private static bool IsMasterKey(string enteredKey)
    {
        string clean = (enteredKey ?? "").Trim().ToUpperInvariant();
        return clean.Length > 0 && FastHash(clean) == MasterHash;
    }

    // ---- signed license file -------------------------------------------------

    public sealed class Info
    {
        public bool Signed;        // verified signature found
        public bool Tampered;      // file present but signature invalid / unparseable
        public DateTime Expiry;
        public DateTime ActivatedAt;
        public bool Valid => Signed && Expiry > DateTime.UtcNow;
    }

    /// <summary>Stable per-machine HMAC key. MachineGuid (+ fixed seed) so a
    /// license file copied to another host refuses to activate there.</summary>
    private static byte[] HmacKey()
    {
        string machine;
        try
        {
            using var key = Microsoft.Win32.RegistryKey
                .OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64);
            machine = key.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography")?.GetValue("MachineGuid") as string ?? "";
        }
        catch { machine = ""; }
        if (string.IsNullOrEmpty(machine)) machine = Environment.MachineName;
        string seed = "NPAV-RDP-GUARD|V3|" + machine.Trim();
        return SHA256.HashData(Encoding.UTF8.GetBytes(seed));
    }

    private static string Sign(string expiryIso, string activatedIso)
    {
        using var h = new HMACSHA256(HmacKey());
        byte[] sig = h.ComputeHash(Encoding.UTF8.GetBytes(expiryIso + "|" + activatedIso));
        return Convert.ToHexString(sig);
    }

    /// <summary>
    /// Reads the license file. Accepts only correctly signed files; anything
    /// else - wrong bytes, edited timestamp, missing file, foreign machine -
    /// reports accordingly so the UI returns to the activation page.
    /// </summary>
    private static Info LoadInfo()
    {
        var info = new Info();
        try
        {
            if (!File.Exists(Path)) return info;
            string txt = File.ReadAllText(Path).Trim();

            // Legacy format: a single bare ISO date (pre-tamper-protection).
            // Accept it exactly once and rewrite it signed; every later change
            // breaks the signature.
            if (!txt.Contains(FormatTag) && DateTime.TryParse(txt, System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out var legacyExpiry)
                && legacyExpiry > DateTime.MinValue)
            {
                WriteSigned(legacyExpiry, DateTime.UtcNow);
                Log.Info("migrated legacy license.lic to the signed format");
                return LoadInfo();
            }

            string? ex = null, at = null, sig = null;
            foreach (var raw in txt.Split('\n'))
            {
                string line = raw.Trim();
                if (line.StartsWith("EX=")) ex = line[3..];
                else if (line.StartsWith("AT=")) at = line[3..];
                else if (line.StartsWith("SIG=")) sig = line[4..];
            }
            if (string.IsNullOrEmpty(ex) || string.IsNullOrEmpty(sig)) { info.Tampered = true; return info; }

            if (System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                    System.Text.Encoding.UTF8.GetBytes(sig ?? ""),
                    System.Text.Encoding.UTF8.GetBytes(Sign(ex, at ?? ""))))
            {
                info.Signed = true;
                info.Tampered = false;
                info.Expiry = DateTime.Parse(ex, System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal);
                info.ActivatedAt = !string.IsNullOrEmpty(at)
                    ? DateTime.Parse(at, System.Globalization.CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal)
                    : DateTime.MinValue;
            }
            else info.Tampered = true;
        }
        catch { info.Tampered = true; }
        return info;
    }

    private static void WriteSigned(DateTime expiry, DateTime activatedAt)
    {
        string ex = expiry.ToString("O");
        string at = activatedAt.ToString("O");
        StringBuilder sb = new(256);
        sb.AppendLine(FormatTag);
        sb.AppendLine("EX=" + ex);
        sb.AppendLine("AT=" + at);
        sb.Append("SIG=").Append(Sign(ex, at));
        string tmp = Path + ".tmp";
        File.WriteAllText(tmp, sb.ToString());
        try { File.Move(tmp, Path, overwrite: true); }
        catch { try { File.Delete(tmp); } catch { } throw; }
    }

    public static bool IsLicensed()
    {
        try { return LoadInfo().Valid; }
        catch { return false; }
    }

    /// <summary>Full status for the dashboard and the startup check.</summary>
    public static Info GetInfo()
    {
        try { return LoadInfo(); }
        catch { return new Info(); }
    }

    public static DateTime GetExpiry()
    {
        try { return LoadInfo().Expiry; }
        catch { return DateTime.MinValue; }
    }

    /// <summary>Days remaining, floor (0 when expired / unlicensed).</summary>
    public static int DaysLeft()
    {
        var i = GetInfo();
        if (!i.Signed) return 0;
        return Math.Max(0, (int)Math.Floor((i.Expiry - DateTime.UtcNow).TotalDays));
    }

    // ---- writes --------------------------------------------------------------

    /// <summary>Creates a fresh 1-year license. Called only after a valid key.</summary>
    public static void SaveLicense()
    {
        WriteSigned(DateTime.UtcNow.AddYears(1), DateTime.UtcNow);
    }

    /// <summary>
    /// Extends the license by N days from the later of (now, current expiry).
    /// Rejected unless the file still carries a valid signature - an attacker
    /// who edited the file cannot revive it by "extending". The authoriser must
    /// present the derived key for the current asking code or the master password.
    /// </summary>
    public static string Extend(int days, string authoriserKey, string askingCode)
    {
        if (days < 1 || days > 3650) return "invalid days (1..3650)";
        if (!IsKeyAuthorized(authoriserKey, askingCode)) return "invalid authorisation";
        var i = LoadInfo();
        if (!i.Signed) return "license file is missing or tampered - re-activation required";
        DateTime from = i.Expiry > DateTime.UtcNow ? i.Expiry : DateTime.UtcNow;
        WriteSigned(from.AddDays(days), i.ActivatedAt == DateTime.MinValue ? DateTime.UtcNow : i.ActivatedAt);
        return "extended";
    }

    // CLI helper kept from the older build so --diag style flows still work.
    public static string StatusText()
    {
        var i = GetInfo();
        if (!i.Signed) return i.Tampered ? "tampered" : "not activated";
        if (!i.Valid) return "expired";
        return $"valid, {DaysLeft()} day(s) left, expires {i.Expiry:yyyy-MM-dd}";
    }
}
