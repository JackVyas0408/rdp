using System.Net;
using System.Runtime.InteropServices;

namespace V3Guard;

/// <summary>
/// Windows Filtering Platform block filters. One filter is installed per blocked
/// address, matching the remote IP and the local RDP port. A dynamic session means
/// every filter disappears automatically if the process dies, so a crash can never
/// leave a host permanently unreachable.
/// </summary>
public static unsafe class Wfp
{
    private const uint FwpUint32 = 3;
    private const uint FwpUint16 = 2;
    private const uint MatchEqual = 0;
    private const uint ActionBlock = 0x00001001;
    private const uint SessionFlagDynamic = 0x00000001;
    private const uint AuthnWin = 10;

    [StructLayout(LayoutKind.Sequential)]
    private struct Guid16 { public byte A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P; }

    [StructLayout(LayoutKind.Sequential)]
    private struct Blob { public uint Size; public uint _pad; public byte* Data; }

    [StructLayout(LayoutKind.Sequential)]
    private struct Value0 { public uint Type; public uint _pad; public ulong Value; }

    [StructLayout(LayoutKind.Sequential)]
    private struct DisplayData { public char* Name; public char* Description; }

    [StructLayout(LayoutKind.Sequential)]
    private struct Action0 { public uint Type; public Guid16 FilterType; }

    [StructLayout(LayoutKind.Sequential)]
    private struct ConditionValue { public uint Type; public uint _pad; public ulong Value; }

    [StructLayout(LayoutKind.Sequential)]
    private struct Condition
    {
        public Guid16 FieldKey;
        public uint MatchType;
        public uint _pad;
        public ConditionValue ConditionValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Filter
    {
        public Guid16 FilterKey;
        public DisplayData DisplayData;
        public uint Flags;
        public uint _pad1;
        public Guid16* ProviderKey;
        public Blob ProviderData;
        public Guid16 LayerKey;
        public Guid16 SubLayerKey;
        public Value0 Weight;
        public uint NumFilterConditions;
        public uint _pad2;
        public Condition* FilterCondition;
        public Action0 Action;
        public uint _pad3;
        public ulong RawContext;
        public ulong RawContextTail;
        public Guid16* Reserved;
        public ulong FilterId;
        public Value0 EffectiveWeight;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Session
    {
        public Guid16 SessionKey;
        public DisplayData DisplayData;
        public uint Flags;
        public uint TransactionWaitTimeoutMs;
        public uint ProcessId;
        public uint _pad;
        public void* Sid;
        public char* Username;
        public int KernelMode;
        public uint _pad2;
    }

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmEngineOpen0(char* server, uint authn, void* identity, Session* session, out IntPtr engine);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmEngineClose0(IntPtr engine);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterAdd0(IntPtr engine, Filter* filter, void* sd, out ulong id);

    [DllImport("fwpuclnt.dll")]
    private static extern uint FwpmFilterDeleteById0(IntPtr engine, ulong id);

    // Canonical SDK GUIDs, raw memory order (first three fields little-endian).
    private static Guid16 LayerInboundV4 = new()
    {
        A = 0xc8, B = 0xdf, C = 0x26, D = 0x59, E = 0xcf, F = 0xe3, G = 0x26, H = 0x44,
        I = 0xa2, J = 0x83, K = 0xdc, L = 0x39, M = 0x3f, N = 0x5d, O = 0x0f, P = 0x9d,
    };

    /// <summary>
    /// FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, {c38d57d1-05a7-4c33-904f-7fbceee60e82}.
    ///
    /// This is the layer the Windows Firewall itself decides inbound connections
    /// at, and it is the reliable place to refuse one. Filtering at
    /// INBOUND_TRANSPORT_V4 alone does not consistently terminate a connection,
    /// which is why a block can look installed while traffic still gets through.
    /// </summary>
    private static Guid16 LayerAleRecvAcceptV4 = new()
    {
        A = 0xd1, B = 0x57, C = 0x8d, D = 0xc3, E = 0xa7, F = 0x05, G = 0x33, H = 0x4c,
        I = 0x90, J = 0x4f, K = 0x7f, L = 0xbc, M = 0xee, N = 0xe6, O = 0x0e, P = 0x82,
    };
    private static Guid16 SubLayerUniversal = new()
    {
        A = 0x03, B = 0xcc, C = 0xbe, D = 0xee, E = 0xd4, F = 0xce, G = 0x80, H = 0x43,
        I = 0x81, J = 0x9a, K = 0x27, L = 0x34, M = 0x39, N = 0x7b, O = 0x2b, P = 0x74,
    };
    private static Guid16 CondRemoteAddress = new()
    {
        A = 0x9a, B = 0xae, C = 0x35, D = 0xb2, E = 0x64, F = 0x1d, G = 0xb8, H = 0x49,
        I = 0xa4, J = 0x4c, K = 0x5f, L = 0xf3, M = 0xd9, N = 0x09, O = 0x50, P = 0x45,
    };
    private static Guid16 CondLocalPort = new()
    {
        A = 0xaf, B = 0xa1, C = 0x1b, D = 0x0c, E = 0x65, F = 0x57, G = 0x3f, H = 0x45,
        I = 0xaf, J = 0x22, K = 0xa8, L = 0xf7, M = 0x91, N = 0xac, O = 0x77, P = 0x5b,
    };

    private static IntPtr _engine;
    private static readonly object Gate = new();
    /// <summary>Filter ids per address per port: ip -> (port -> list of filter ids).</summary>
    private static readonly Dictionary<string, Dictionary<int, List<ulong>>> Active = [];

    public static bool IsOpen { get { lock (Gate) return _engine != IntPtr.Zero; } }

    public static bool Open()
    {
        lock (Gate)
        {
            if (_engine != IntPtr.Zero) return true;
            var session = new Session { Flags = SessionFlagDynamic };
            fixed (char* name = "NPav RDP Protection")
            fixed (char* desc = "RDP brute-force protection")
                session.DisplayData = new DisplayData { Name = name, Description = desc };

            uint hr = FwpmEngineOpen0(null, AuthnWin, null, &session, out IntPtr engine);
            if (hr != 0)
            {
                Log.Error($"FwpmEngineOpen0 failed hr=0x{hr:X8} - administrator rights required");
                return false;
            }
            _engine = engine;
            Log.Info("WFP engine open (dynamic session)");
            return true;
        }
    }

    public static void Close()
    {
        lock (Gate)
        {
            if (_engine == IntPtr.Zero) return;
            FwpmEngineClose0(_engine);
            _engine = IntPtr.Zero;
            Active.Clear();
        }
    }

    /// <summary>
    /// Install a block for ip on one local port.
    ///
    /// Always port-scoped. An earlier version fell back to an IP-only filter when
    /// the port condition was refused, which silently blocked that address on
    /// every port - well beyond what was asked for. If no layer accepts the
    /// port-scoped filter this now fails loudly instead.
    ///
    /// The ALE receive/accept layer is tried first: that is where an inbound
    /// connection is actually authorised, so a block there is enforced. The
    /// transport layer is the fallback.
    /// </summary>
    public static bool Block(string ip, int port, out ulong id)
    {
        id = 0;
        if (!Net.TryParseIpv4(ip, out uint ipBe)) return false;

        lock (Gate)
        {
            if (_engine == IntPtr.Zero) return false;

            // Already blocked on this port: nothing to do.
            if (Active.TryGetValue(ip, out var existingPorts) &&
                existingPorts.TryGetValue(port, out var existingIds) &&
                existingIds.Count > 0)
            {
                id = existingIds[0];
                return true;
            }

            fixed (char* fname = "NPav RDP Protection block")
            {
                Condition* conds = stackalloc Condition[2];
                conds[0].FieldKey = CondRemoteAddress;
                conds[0].MatchType = MatchEqual;
                conds[0].ConditionValue = new ConditionValue { Type = FwpUint32, Value = ipBe };

                conds[1].FieldKey = CondLocalPort;
                conds[1].MatchType = MatchEqual;
                conds[1].ConditionValue = new ConditionValue { Type = FwpUint16, Value = (ulong)(ushort)port };

                Span<(Guid16 layer, string name)> attempts =
                [
                    (LayerAleRecvAcceptV4, "ALE"),
                    (LayerInboundV4, "TRANS"),
                ];

                // Install at every layer that accepts the filter rather than
                // stopping at the first success. A single filter at one layer
                // proved insufficient in practice - the ALE filter authorises and
                // the transport filter drops packets that are already flowing - so
                // both are installed and both ids are tracked for removal.
                var ids = new List<ulong>(2);
                uint lastHr = 0;
                foreach (var (layer, name) in attempts)
                {
                    var filter = Build(fname, conds, 2, layer);
                    uint hr = FwpmFilterAdd0(_engine, &filter, null, out ulong filterId);
                    if (hr == 0)
                    {
                        ids.Add(filterId);
                        Log.Info($"block {ip} on port {port} via {name} filter={filterId}");
                    }
                    else
                    {
                        lastHr = hr;
                        Log.Warn($"{name} block filter refused for {ip} (hr=0x{hr:X8})");
                    }
                }

                if (ids.Count == 0)
                {
                    Log.Error($"could not block {ip} on port {port} (last hr=0x{lastHr:X8})" +
                              (lastHr == 5 ? " - access denied, run as Administrator" : ""));
                    return false;
                }

                if (!Active.TryGetValue(ip, out var portMap))
                {
                    portMap = new Dictionary<int, List<ulong>>();
                    Active[ip] = portMap;
                }
                portMap[port] = ids;
                id = ids[0];

                // Drop live connections on that port so the block applies now.
                TcpBlocker.KillFor(ip, port);
                return true;
            }
        }
    }

    private static Filter Build(char* name, Condition* conds, uint count, Guid16 layer)
    {
        return new Filter
        {
            LayerKey = layer,
            SubLayerKey = SubLayerUniversal,
            DisplayData = new DisplayData { Name = name, Description = null },
            Action = new Action0 { Type = ActionBlock },
            Weight = new Value0 { Type = FwpUint8Const, Value = 0x0F },
            NumFilterConditions = count,
            FilterCondition = conds,
        };
    }

    private const uint FwpUint8Const = 1;

    public static bool Unblock(string ip)
    {
        lock (Gate)
        {
            if (_engine == IntPtr.Zero) return false;
            if (!Active.TryGetValue(ip, out var portMap)) return true;
            foreach (var kv in portMap)
                foreach (var id in kv.Value) FwpmFilterDeleteById0(_engine, id);
            Active.Remove(ip);
            return true;
        }
    }

    /// <summary>Removes only the filters for one port, leaving other ports blocked.</summary>
    public static void UnblockPort(string ip, int port)
    {
        lock (Gate)
        {
            if (_engine == IntPtr.Zero) return;
            if (!Active.TryGetValue(ip, out var portMap)) return;
            if (!portMap.TryGetValue(port, out var ids)) return;
            foreach (var id in ids) FwpmFilterDeleteById0(_engine, id);
            portMap.Remove(port);
            if (portMap.Count == 0) Active.Remove(ip);
        }
    }

    public static void UnblockAll()
    {
        lock (Gate)
        {
            if (_engine == IntPtr.Zero) return;
            foreach (var ipMap in Active.Values)
                foreach (var ids in ipMap.Values)
                    foreach (var id in ids) FwpmFilterDeleteById0(_engine, id);
            Active.Clear();
        }
    }

    /// <summary>How many filters this guard currently has installed.</summary>
    public static int InstalledFilterCount
    {
        get { lock (Gate) return Active.Values.Sum(p => p.Values.Sum(v => v.Count)); }
    }
}

/// <summary>
/// Drops live TCP connections from a blocked address so the WFP filter takes effect
/// immediately instead of at the next reconnect. Windows exposes no dedicated
/// "disconnect peer" API, but setting a table row to MIB_TCP_STATE_DELETE_TCB tears
/// the connection down at the stack level.
/// </summary>
public static class TcpBlocker
{
    private const uint TcpStateEstablished = 5;
    private const uint TcpStateDeleteTcb = 12;

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRow
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint SetTcpEntry(ref MibTcpRow row);

    public static int KillFor(string ip, int localPort)
    {
        if (!Net.TryParseIpv4(ip, out uint target)) return 0;
        int killed = 0;
        try
        {
            var rows = GetConnections(target, localPort);
            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                row.State = TcpStateDeleteTcb;
                if (SetTcpEntry(ref row) == 0) killed++;
            }
            if (killed > 0) Log.Info($"dropped {killed} live connection(s) from {ip} on port {localPort}");
        }
        catch (Exception ex)
        {
            Log.Warn($"tcp kill failed for {ip}: {ex.Message}");
        }
        return killed;
    }

    private static unsafe List<MibTcpRow> GetConnections(uint remoteAddr, int localPort)
    {
        var result = new List<MibTcpRow>();
        int size = 0;
        // AF_INET, IPPROTO_TCP
        if (GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 6, 0) != 0 || size <= 0)
            return result;

        IntPtr mem = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(mem, ref size, false, 2, 6, 0) != 0) return result;

            // The table stores the port in network byte order in the low 16 bits.
            // Byte-swap into that same low half - shifting was wrong and meant no
            // row ever matched, so live connections were never dropped.
            uint wantPort = (uint)(ushort)System.Net.IPAddress.HostToNetworkOrder((short)localPort);

            var count = Marshal.ReadInt32(mem);
            var basePtr = (byte*)mem + 4;
            for (int i = 0; i < count; i++)
            {
                var row = *(MibTcpRow*)(basePtr + i * sizeof(MibTcpRow));
                if (row.State != TcpStateEstablished) continue;
                if (row.RemoteAddr != remoteAddr) continue;
                if ((row.LocalPort & 0xFFFF) != wantPort) continue;
                result.Add(row);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(mem);
        }
        return result;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int family, int protocol, uint reserved);
}