using System.Net;
using System.Net.Sockets;

namespace V3Guard;

/// <summary>
/// End-to-end WFP test (<c>v3.exe --wfp-test</c>).
///
/// Proves the filter actually refuses a connection rather than merely reporting
/// that one was installed. That distinction matters: every earlier attempt to
/// describe the WFP path as working was based on a call returning success, which
/// says nothing about whether traffic was stopped.
///
/// Method: listen on a loopback port, confirm a connection succeeds, install a
/// port-scoped block for that same address and port, then confirm the connection
/// is refused, then remove the filter and confirm it succeeds again. The filter
/// is always removed, and the WFP session is dynamic, so nothing survives a crash.
///
/// Needs Administrator rights.
/// </summary>
public static class WfpTest
{
    public static int Run(string[] args)
    {
        Log.AttachParentConsole();

        int port = ArgPort(args) ?? 39999;
        var target = IPAddress.Loopback;

        Console.WriteLine("NPav RDP Protection - WFP filter test");
        Console.WriteLine(new string('=', 52));
        Console.WriteLine($"target   : {target}:{port}");
        Console.WriteLine($"elevated : {Diag.IsElevated()}");
        Console.WriteLine();

        if (!Diag.IsElevated())
        {
            Console.WriteLine("FAIL - Administrator rights are required to add WFP filters.");
            Console.WriteLine("       Re-run this from an elevated prompt.");
            return 1;
        }

        if (!Wfp.Open())
        {
            Console.WriteLine("FAIL - the WFP engine could not be opened.");
            return 1;
        }
        Console.WriteLine("PASS - WFP engine opened");

        TcpListener? listener = null;
        ulong filterId = 0;
        bool installed = false;
        int failures = 0;

        try
        {
            listener = new TcpListener(target, port);
            listener.Start();
            Console.WriteLine($"PASS - listening on {target}:{port}");

            // 1. Baseline: with no filter, the connection must succeed. Without
            //    this the rest of the test proves nothing.
            bool before = CanConnect(target, port, 1500);
            Console.WriteLine($"{(before ? "PASS" : "FAIL")} - baseline connect succeeds ({before})");
            if (!before) failures++;

            // 2. Install the block and let the engine apply it.
            installed = Wfp.Block(target.ToString(), port, out filterId);
            Console.WriteLine($"{(installed ? "PASS" : "FAIL")} - block filter installed (id={filterId})");
            if (!installed) failures++;
            Thread.Sleep(500);

            // 3. The connection must now be refused or time out.
            bool blocked = !CanConnect(target, port, 1500);
            Console.WriteLine($"{(blocked ? "PASS" : "FAIL")} - connection is refused while blocked ({blocked})");
            if (!blocked) failures++;

            // 4. Remove the filter.
            Wfp.Unblock(target.ToString());
            installed = false;
            Thread.Sleep(500);

            bool after = CanConnect(target, port, 1500);
            Console.WriteLine($"{(after ? "PASS" : "FAIL")} - connect works again after release ({after})");
            if (!after) failures++;

            Console.WriteLine();
            if (failures == 0)
            {
                Console.WriteLine("RESULT: WFP BLOCKING WORKS - traffic was refused, then restored.");
                return 0;
            }

            if (!blocked)
            {
                Console.WriteLine("RESULT: the filter installs but does NOT stop traffic.");
                Console.WriteLine("        The filter is being accepted by the engine yet not enforced.");
                return 2;
            }

            Console.WriteLine($"RESULT: {failures} check(s) failed - see above.");
            return 2;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"FAIL - {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
        finally
        {
            // Always undo, even on failure: leaving a block behind would silently
            // cut off the test port.
            if (installed) Wfp.Unblock(target.ToString());
            try { listener?.Stop(); } catch { }
            Console.WriteLine();
            Console.WriteLine("cleanup: filter released, listener stopped");
        }
    }

    /// <summary>True when a TCP connection is accepted within the timeout.</summary>
    private static bool CanConnect(IPAddress ip, int port, int timeoutMs)
    {
        try
        {
            using var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            var ar = s.BeginConnect(ip, port, null, null);
            if (!ar.AsyncWaitHandle.WaitOne(timeoutMs)) return false;
            s.EndConnect(ar);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static int? ArgPort(string[] args)
    {
        foreach (var a in args)
        {
            if (a.StartsWith("--wfp-test=", StringComparison.OrdinalIgnoreCase) &&
                int.TryParse(a["--wfp-test=".Length..], out var v) && v is > 1024 and < 65536)
                return v;
        }
        int idx = Array.FindIndex(args, a => a.Equals("--wfp-test", StringComparison.OrdinalIgnoreCase));
        if (idx >= 0 && idx + 1 < args.Length && int.TryParse(args[idx + 1], out var w) && w is > 1024 and < 65536)
            return w;
        return null;
    }
}