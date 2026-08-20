using System.Runtime.InteropServices;

namespace SplitLane.Engine.Interop;

/// <summary>Which stack location a handle observes.</summary>
public enum WinDivertLayer
{
    /// <summary>Packets. The only layer that can modify or drop.</summary>
    Network = 0,

    /// <summary>Packets on the forwarding path. Unused here.</summary>
    NetworkForward = 1,

    /// <summary>Connection lifecycle with a process id. Sniff only.</summary>
    Flow = 2,

    /// <summary>Socket operations with a process id, delivered before the packet. Sniff only.</summary>
    Socket = 3,

    /// <summary>Other WinDivert handles on the system. Unused here.</summary>
    Reflect = 4,
}

/// <summary>What happened, for the non-packet layers.</summary>
public enum WinDivertEvent
{
    /// <summary>A packet.</summary>
    NetworkPacket = 0,

    /// <summary>A flow was established.</summary>
    FlowEstablished = 1,

    /// <summary>A flow was torn down.</summary>
    FlowDeleted = 2,

    /// <summary>A socket bound.</summary>
    SocketBind = 3,

    /// <summary>A socket connected. This is the event that carries the destination and the pid.</summary>
    SocketConnect = 4,

    /// <summary>A socket started listening.</summary>
    SocketListen = 5,

    /// <summary>A socket accepted.</summary>
    SocketAccept = 6,

    /// <summary>A socket closed.</summary>
    SocketClose = 7,

    /// <summary>A WinDivert handle opened.</summary>
    ReflectOpen = 8,

    /// <summary>A WinDivert handle closed.</summary>
    ReflectClose = 9,
}

/// <summary>Handle-open flags.</summary>
[Flags]
public enum WinDivertFlags : ulong
{
    /// <summary>Default: intercept and require reinjection.</summary>
    None = 0,

    /// <summary>Observe copies; the originals are not held.</summary>
    Sniff = 1,

    /// <summary>Matching packets are dropped rather than queued.</summary>
    Drop = 2,

    /// <summary>The handle cannot inject.</summary>
    RecvOnly = 4,

    /// <summary>The handle cannot receive.</summary>
    SendOnly = 8,

    /// <summary>Do not install the driver if it is not already running.</summary>
    NoInstall = 16,

    /// <summary>Deliver IP fragments individually rather than reassembled.</summary>
    Fragments = 32,
}

/// <summary>Tunable queue parameters.</summary>
public enum WinDivertParam
{
    /// <summary>Maximum packets held in the kernel queue.</summary>
    QueueLength = 0,

    /// <summary>Milliseconds a packet may sit in the queue.</summary>
    QueueTime = 1,

    /// <summary>Maximum bytes held in the kernel queue.</summary>
    QueueSize = 2,

    /// <summary>Driver major version.</summary>
    VersionMajor = 3,

    /// <summary>Driver minor version.</summary>
    VersionMinor = 4,
}

/// <summary>Socket-layer payload of <see cref="WinDivertAddress"/>.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct WinDivertDataSocket
{
    /// <summary>Endpoint identifier.</summary>
    public ulong EndpointId;

    /// <summary>Parent endpoint identifier.</summary>
    public ulong ParentEndpointId;

    /// <summary>Owning process id. The reason this layer exists for us.</summary>
    public uint ProcessId;

    /// <summary>Local address, four words. IPv4 lives in word 0.</summary>
    public uint LocalAddr0;

    /// <summary>Local address word 1.</summary>
    public uint LocalAddr1;

    /// <summary>Local address word 2.</summary>
    public uint LocalAddr2;

    /// <summary>Local address word 3.</summary>
    public uint LocalAddr3;

    /// <summary>Remote address, four words. IPv4 lives in word 0.</summary>
    public uint RemoteAddr0;

    /// <summary>Remote address word 1.</summary>
    public uint RemoteAddr1;

    /// <summary>Remote address word 2.</summary>
    public uint RemoteAddr2;

    /// <summary>Remote address word 3.</summary>
    public uint RemoteAddr3;

    /// <summary>Local port, host byte order.</summary>
    public ushort LocalPort;

    /// <summary>Remote port, host byte order.</summary>
    public ushort RemotePort;

    /// <summary>IP protocol number.</summary>
    public byte Protocol;
}

/// <summary>Network-layer payload of <see cref="WinDivertAddress"/>.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct WinDivertDataNetwork
{
    /// <summary>Interface index.</summary>
    public uint IfIdx;

    /// <summary>Sub-interface index.</summary>
    public uint SubIfIdx;
}

/// <summary>
/// Per-packet metadata. Mirrors <c>WINDIVERT_ADDRESS</c> exactly, including the 64-byte union.
/// </summary>
/// <remarks>
/// The bitfield word is exposed raw and unpacked by properties rather than by a managed bitfield,
/// because C# has none and a hand-rolled struct with eight one-bit fields would be a layout guess.
/// The layout is fixed by the ABI and verified by <c>WinDivertInteropTests</c>.
/// </remarks>
[StructLayout(LayoutKind.Explicit, Size = 80)]
public struct WinDivertAddress
{
    /// <summary>Kernel timestamp.</summary>
    [FieldOffset(0)]
    public long Timestamp;

    /// <summary>Packed layer, event and flag bits.</summary>
    [FieldOffset(8)]
    public uint Bits;

    /// <summary>Reserved.</summary>
    [FieldOffset(12)]
    public uint Reserved;

    /// <summary>Union member for the network layer.</summary>
    [FieldOffset(16)]
    public WinDivertDataNetwork Network;

    /// <summary>Union member for the socket and flow layers.</summary>
    [FieldOffset(16)]
    public WinDivertDataSocket Socket;

    /// <summary>Which layer produced this.</summary>
    public WinDivertLayer Layer
    {
        readonly get => (WinDivertLayer)(Bits & 0xFF);
        set => Bits = (Bits & ~0xFFu) | ((uint)value & 0xFF);
    }

    /// <summary>What happened.</summary>
    public WinDivertEvent Event
    {
        readonly get => (WinDivertEvent)((Bits >> 8) & 0xFF);
        set => Bits = (Bits & ~(0xFFu << 8)) | (((uint)value & 0xFF) << 8);
    }

    /// <summary>True when the handle only observed a copy.</summary>
    public bool Sniffed
    {
        readonly get => GetBit(16);
        set => SetBit(16, value);
    }

    /// <summary>True for packets leaving this machine.</summary>
    public bool Outbound
    {
        readonly get => GetBit(17);
        set => SetBit(17, value);
    }

    /// <summary>True for packets on the loopback interface.</summary>
    public bool Loopback
    {
        readonly get => GetBit(18);
        set => SetBit(18, value);
    }

    /// <summary>True when the packet was injected by another handle.</summary>
    public bool Impostor
    {
        readonly get => GetBit(19);
        set => SetBit(19, value);
    }

    /// <summary>True for IPv6.</summary>
    public bool IPv6
    {
        readonly get => GetBit(20);
        set => SetBit(20, value);
    }

    /// <summary>True when the IPv4 header checksum is valid.</summary>
    public bool IPChecksum
    {
        readonly get => GetBit(21);
        set => SetBit(21, value);
    }

    /// <summary>True when the TCP checksum is valid.</summary>
    public bool TCPChecksum
    {
        readonly get => GetBit(22);
        set => SetBit(22, value);
    }

    /// <summary>True when the UDP checksum is valid.</summary>
    public bool UDPChecksum
    {
        readonly get => GetBit(23);
        set => SetBit(23, value);
    }

    private readonly bool GetBit(int index) => ((Bits >> index) & 1) != 0;

    private void SetBit(int index, bool value) =>
        Bits = value ? Bits | (1u << index) : Bits & ~(1u << index);
}

/// <summary>
/// Raw entry points of <c>WinDivert.dll</c>.
/// </summary>
/// <remarks>
/// <para>
/// The DLL is not vendored. Every call site must be prepared for <see cref="DllNotFoundException"/>,
/// which is what a machine without the driver produces, and must translate it into a message the
/// user can act on rather than a stack trace.
/// </para>
/// <para>
/// Address formatting goes through the library's own helpers rather than being reimplemented here.
/// The word order WinDivert uses for its address arrays is an implementation detail of the library,
/// and guessing at it is exactly the kind of mistake that produces a routing bug visible only on
/// IPv6, only on some machines.
/// </para>
/// </remarks>
internal static partial class WinDivertNative
{
    private const string Library = "WinDivert.dll";

    [LibraryImport(Library, EntryPoint = "WinDivertOpen", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial nint Open(string filter, WinDivertLayer layer, short priority, WinDivertFlags flags);

    [LibraryImport(Library, EntryPoint = "WinDivertClose")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool Close(nint handle);

    [LibraryImport(Library, EntryPoint = "WinDivertShutdown")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool Shutdown(nint handle, int how);

    [LibraryImport(Library, EntryPoint = "WinDivertRecv")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static unsafe partial bool Recv(
        nint handle, byte* packet, uint packetLen, uint* recvLen, WinDivertAddress* address);

    [LibraryImport(Library, EntryPoint = "WinDivertSend")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static unsafe partial bool Send(
        nint handle, byte* packet, uint packetLen, uint* sendLen, WinDivertAddress* address);

    [LibraryImport(Library, EntryPoint = "WinDivertSetParam")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool SetParam(nint handle, WinDivertParam param, ulong value);

    [LibraryImport(Library, EntryPoint = "WinDivertGetParam")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static unsafe partial bool GetParam(nint handle, WinDivertParam param, ulong* value);

    [LibraryImport(Library, EntryPoint = "WinDivertHelperCalcChecksums")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static unsafe partial bool CalcChecksums(
        byte* packet, uint packetLen, WinDivertAddress* address, ulong flags);

    [LibraryImport(Library, EntryPoint = "WinDivertHelperFormatIPv4Address")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static unsafe partial bool FormatIPv4Address(uint address, byte* buffer, uint bufferLength);

    [LibraryImport(Library, EntryPoint = "WinDivertHelperFormatIPv6Address")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static unsafe partial bool FormatIPv6Address(uint* address, byte* buffer, uint bufferLength);

    [LibraryImport(Library, EntryPoint = "WinDivertHelperCompileFilter", StringMarshalling = StringMarshalling.Utf8)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static unsafe partial bool CompileFilter(
        string filter, WinDivertLayer layer, byte* obj, uint objLen, byte** errorStr, uint* errorPos);
}
