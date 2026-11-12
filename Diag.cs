using System.Diagnostics.Eventing.Reader;
using System.Security.Principal;
using System.Text;

namespace V3Guard;

/// <summary>
/// Diagnostic mode (<c>v3.exe --diag</c>). Answers the only question that matters
/// when nothing is being blocked: is the guard actually able to see 4625 events?
///
/// Print a report and exit. Never touches WFP, the dashboard or the db.
/// </summary>
public static class Diag
{
    public static int Run()
    {
        var sb = new StringBuilder(8192);
        void W(string s = "") { sb.Append(s).Append('\n'); }

        W("NPav RDP Protection - diagnostics");
        W(new string('=', 55));

        W();
        W("[ identity ]");
        W($"  elevated ............ {IsElevated()}");
        W($"  user ................ {Environment.UserName}");
        W($"  base dir ............ {AppContext.BaseDirectory}");
        W($"  runtime ............. {Environment.Version}");
        W($"  os .................. {Environment.OSVersion}");

        W();
        W("[ audit policy - decides whether 4625 is written AT ALL ]");
        string audit = RunAuditPol();
        W(Indent(audit));
        bool auditOn = audit.Contains("Success and Failure", StringComparison.OrdinalIgnoreCase)
                    || audit.Contains("Failure", StringComparison.OrdinalIgnoreCase);
        W($"  failure auditing .... {(auditOn ? "APPEARS ENABLED" : "NOT CONFIRMED - this is fatal")}");

        W();
        W("[ security log ]");
        long n4625 = 0, n4624 = 0, maxId = 0;
        string newest4625 = "";
        try
        {
            n4625 = CountEvents(EventLogSource.LogonFailure);
            n4624 = CountEvents(EventLogSource.LogonSuccess);
            maxId = MaxRecordId();
            newest4625 = NewestEventXml(EventLogSource.LogonFailure);

            W($"  readable ............ yes");
            W($"  4625 in log ......... {n4625}");
            W($"  4624 in log ......... {n4624}");
            W($"  newest record id .... {maxId}");
            W($"  resume bookmark ..... {(BookmarkPresent() ? "present" : "none (starts from now)")}");
        }
        catch (Exception ex)
        {
            W($"  readable ............ NO - {ex.GetType().Name}: {ex.Message}");
            W("  => the guard cannot see any logon events. Run elevated.");
        }

        W();
        W("[ newest 4625 raw xml ]");
        W(newest4625.Length > 0 ? Indent(newest4625) : "  (none present)");

        if (newest4625.Length > 0)
        {
            W();
            W("[ parser result for that event ]");
            var parsed = EventLogSource.ParseVerbose(EventLogSource.LogonFailure, newest4625, out string why);
            if (parsed is null)
            {
                W($"  REJECTED - the guard would ignore this event.");
                W($"  reason: {why}");
            }
            else
            {
                W($"  ip ......... {parsed.Ip}");
                W($"  user ....... {parsed.User}");
                W($"  substatus .. {parsed.SubStatus}");
                W($"  class ...... {PolicyEngine.Classify(parsed.SubStatus)}");
                W("  => this event WOULD be counted toward a block.");
            }
        }

        W();
        W("[ verdict ]");
        if (!auditOn)
            W("  Failure auditing for Logon is not confirmed enabled. Windows will not");
        else if (n4625 == 0)
            W("  Auditing looks enabled but there are no 4625 events yet - nothing to detect.");
        else if (newest4625.Length > 0 && EventLogSource.Parse(EventLogSource.LogonFailure, newest4625) is null)
            W("  4625 events exist but the parser rejects them - send the XML above.");
        else
            W("  Detection path looks healthy.");

        string report = sb.ToString();
        Console.Write(report);
        try
        {
            string outPath = Path.Combine(AppContext.BaseDirectory, "diag.txt");
            File.WriteAllText(outPath, report);
            Console.WriteLine();
            Console.WriteLine($"written to {outPath}");
        }
        catch { }

        return 0;
    }

    public static bool IsElevated()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Queries the Logon subcategory by GUID, not by name: the display name is
    /// localised and "Logon" fails on a non-English Windows.
    /// </summary>
    public static string RunAuditPol()
    {
        try
        {
            using var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("auditpol.exe")
            {
                ArgumentList = { "/get", "/subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}" },
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                UseShellExecute = false,
            });
            if (p is null) return "auditpol could not be started";
            string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit(10000);
            return o.Trim().Length > 0 ? o.Trim() : $"(no output, exit {p.ExitCode})";
        }
        catch (Exception ex)
        {
            return $"auditpol failed: {ex.Message}";
        }
    }

    private static long CountEvents(int id)
    {
        long n = 0;
        IntPtr rs = EventLogSource.OpenQuery("Security", $"*[System[(EventID={id})]]", newestFirst: false);
        try
        {
            var one = new IntPtr[1];
            while (EventLogSource.Next(rs, one) > 0)
            {
                EventLogSource.CloseEvent(one[0]);
                one[0] = IntPtr.Zero;
                n++;
                if (n >= 100000) break;
            }
        }
        finally { EventLogSource.CloseEvent(rs); }
        return n;
    }

    private static long MaxRecordId()
    {
        IntPtr rs = EventLogSource.OpenQuery("Security", "*", newestFirst: true);
        try
        {
            var one = new IntPtr[1];
            if (EventLogSource.Next(rs, one) == 0) return 0;
            try { return EventLogSource.ParseRecordId(EventLogSource.RenderEvent(one[0])); }
            finally { EventLogSource.CloseEvent(one[0]); }
        }
        finally { EventLogSource.CloseEvent(rs); }
    }

    private static string NewestEventXml(int id)
    {
        IntPtr rs = EventLogSource.OpenQuery("Security", $"*[System[(EventID={id})]]", newestFirst: true);
        try
        {
            var one = new IntPtr[1];
            if (EventLogSource.Next(rs, one) == 0) return "";
            try { return EventLogSource.RenderEvent(one[0]); }
            finally { EventLogSource.CloseEvent(one[0]); }
        }
        finally { EventLogSource.CloseEvent(rs); }
    }

    private static long LoadWatermark()
    {
        try
        {
            string p = Path.Combine(AppContext.BaseDirectory, "evt.pos");
            return File.Exists(p) && long.TryParse(File.ReadAllText(p), out var v) ? v : 0;
        }
        catch { return 0; }
    }

    private static bool BookmarkPresent() =>
        File.Exists(Path.Combine(AppContext.BaseDirectory, "bookmark.xml"));

    private static string Indent(string s) =>
        string.Join('\n', s.Split('\n').Select(l => "  " + l.TrimEnd()));
}