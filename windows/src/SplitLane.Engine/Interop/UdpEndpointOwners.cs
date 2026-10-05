using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace SplitLane.Engine.Interop;

/// <summary>Who owns a local UDP port, as the IP Helper table reports it.</summary>
/// <param name="ProcessId">The owning process.</param>
/// <param name="DualStack">Bound to the IPv6 wildcard, so it also sends IPv4.</param>
public readonly record struct UdpEndpointOwner(uint ProcessId, bool DualStack);

/// <summary>
/// Finds the process that owns a UDP port when no socket-layer BIND event was seen for it.
/// </summary>
/// <remarks>
/// <para>
/// WinDivert reports a BIND only for sockets bound while the engine is running. A socket opened before
/// that - or whose BIND is still in the socket queue when its first datagram reaches the packet loop -
/// has no recorded owner, and the packet loop used to read "no owner" as "not selected" (SL-SEC-009):
/// a selected application's first datagrams, or all datagrams of a socket it opened before the engine
/// started, went out DIRECT.
/// </para>
/// <para>
/// This is the fallback: <c>GetExtendedUdpTable</c> with <c>UDP_TABLE_OWNER_PID</c>, which lists every
/// UDP endpoint with its owner. It is a few hundred microseconds on a busy machine, so it runs once per
/// unknown port, never per datagram.
/// </para>
/// </remarks>
public static partial class UdpEndpointOwners
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int UdpTableOwnerPid = 1;
    private const uint ErrorInsufficientBuffer = 122;
    private const int Ipv4RowSize = 12;
    private const int Ipv6RowSize = 28;

    /// <summary>
    /// Looks up the owner of a local UDP port in one family. An IPv4 lookup also accepts an IPv6
    /// wildcard socket on the same port, which carries that socket's IPv4 datagrams.
    /// </summary>
    public static UdpEndpointOwner? Find(bool ipv6, ushort port)
    {
        if (!ipv6 && FindIn(AfInet, port) is { } v4)
        {
            return v4;
        }

        return FindIn(AfInet6, port) is { } v6 && (ipv6 || v6.DualStack) ? v6 : null;
    }

    private static UdpEndpointOwner? FindIn(int family, ushort port)
    {
        var size = 0;
        var result = GetExtendedUdpTable(0, ref size, false, family, UdpTableOwnerPid, 0);

        for (var attempt = 0; attempt < 4 && result == ErrorInsufficientBuffer; attempt++)
        {
            // Grown a little beyond what was asked for: the table can gain rows between the two calls.
            size += 4096;
            var buffer = Marshal.AllocHGlobal(size);

            try
            {
                result = GetExtendedUdpTable(buffer, ref size, false, family, UdpTableOwnerPid, 0);
                if (result == 0)
                {
                    return Scan(buffer, size, family == AfInet6, port);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        return null;
    }

    private static unsafe UdpEndpointOwner? Scan(nint buffer, int size, bool ipv6, ushort port)
    {
        var table = new ReadOnlySpan<byte>((void*)buffer, size);
        if (table.Length < 4)
        {
            return null;
        }

        var count = BinaryPrimitives.ReadUInt32LittleEndian(table);
        var rowSize = ipv6 ? Ipv6RowSize : Ipv4RowSize;
        var rows = table[4..];

        for (var i = 0; i < count && (i + 1) * rowSize <= rows.Length; i++)
        {
            var row = rows.Slice(i * rowSize, rowSize);

            // MIB_UDPROW_OWNER_PID:  addr(4) port(4) pid(4)
            // MIB_UDP6ROW_OWNER_PID: addr(16) scope(4) port(4) pid(4)
            var portOffset = ipv6 ? 20 : 4;
            var rowPort = BinaryPrimitives.ReadUInt16BigEndian(row.Slice(portOffset, 2));
            if (rowPort != port)
            {
                continue;
            }

            var pid = BinaryPrimitives.ReadUInt32LittleEndian(row.Slice(portOffset + 4, 4));
            var wildcard = ipv6 && row[..16].IndexOfAnyExcept((byte)0) < 0;
            return new UdpEndpointOwner(pid, wildcard);
        }

        return null;
    }

    [LibraryImport("iphlpapi.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial uint GetExtendedUdpTable(
        nint table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order, int family, int tableClass, uint reserved);
}
