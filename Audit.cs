using System.Diagnostics;

namespace V3Guard;

/// <summary>Windows-side operations: audit policy and RDP port discovery.</summary>
public static class Audit
{
    /// <summary>
    /// Logon subcategory GUID. The subcategory is addressed by GUID rather than
    /// by the name "Logon" because that name is localised - on a non-English
    /// Windows the name lookup fails and auditing is never enabled, which leaves
    /// the guard with nothing to detect and no visible error.
    /// </summary>
    private const string LogonSubcategory = "{0CCE9215-69AE-11D9-BED3-505054503030}";

    /// <summary>Enables failure auditing for Logon. Without this Windows never writes 4625.</summary>
    public static bool EnsureLogonAuditing()
    {
        bool ok = AuditPol("/set", $"/subcategory:{LogonSubcategory}", "/failure:enable");
        if (ok)
        {
            // Confirm rather than assume: a silent failure here disables the
            // entire product, so it is worth one extra call.
            string state = QueryLogonAuditing();
            Log.Info($"audit policy: {state}");
            return state.Contains("Failure", StringComparison.OrdinalIgnoreCase);
        }
        Log.Error("could not enable logon failure auditing - 4625 events will not be generated");
        return false;
    }

    public static string QueryLogonAuditing()
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("auditpol.exe")
            {
                ArgumentList = { "/get", $"/subcategory:{LogonSubcategory}" },
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                UseShellExecute = false,
            });
            if (p is null) return "auditpol unavailable";
            string outp = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit(10000);

            foreach (var raw in outp.Split('\n'))
            {
                var line = raw.Trim();
                if (line.Contains("Failure", StringComparison.OrdinalIgnoreCase)) return line;
            }
            return outp.Trim().Length > 0 ? "unknown" : "no output";
        }
        catch (Exception ex)
        {
            return $"query failed: {ex.Message}";
        }
    }

    private static bool AuditPol(params string[] args)
    {
        try
        {
            var psi = new ProcessStartInfo("auditpol.exe")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            foreach (var a in args) psi.ArgumentList.Add(a);

            using var p = Process.Start(psi);
            if (p is null) return false;
            p.WaitForExit(10000);
            if (p.ExitCode == 0) return true;

            string err = p.StandardError.ReadToEnd().Trim();
            Log.Warn($"auditpol exited {p.ExitCode}{(err.Length > 0 ? ": " + err : "")}");
            return false;
        }
        catch (Exception ex)
        {
            Log.Warn($"auditpol failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>The RDP listening port from the registry, or 3389.</summary>
    public static int DetectRdpPort()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
            if (key?.GetValue("PortNumber") is int port && port is > 0 and <= 65535)
                return port;
        }
        catch { }
        return 3389;
    }
}