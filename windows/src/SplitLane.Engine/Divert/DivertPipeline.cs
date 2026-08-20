using System.Collections.Concurrent;
using System.Net;
using SplitLane.Core.Logging;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;
using SplitLane.Engine.Flows;
using SplitLane.Engine.Interop;
using SplitLane.Engine.Net;
using SplitLane.Engine.Runtime;

namespace SplitLane.Engine.Divert;

/// <summary>
/// The divert layer: three WinDivert handles and the threads that drain them.
/// </summary>
/// <remarks>
/// <para>
/// This is the Windows counterpart of the macOS provider's <c>handleNewFlow</c>, and the differences
/// are worth stating plainly rather than hiding:
/// </para>
/// <list type="bullet">
/// <item>
/// <b>Identity arrives separately from packets.</b> The socket layer reports a process id at
/// <c>connect()</c> time; the network layer reports packets with no process at all. So the socket
/// pump makes the routing decision in advance and leaves a NAT entry, and the packet loop is a
/// lookup keyed on the source port. That ordering is guaranteed by Windows: the socket-layer event is
/// delivered before the SYN is sent.
/// </item>
/// <item>
/// <b>Unselected traffic is copied, not untouched.</b> On macOS, returning <c>false</c> hands the
/// flow back to the kernel and nothing is recreated. Here, an outbound packet from an unselected
/// application transits user mode and is reinjected byte-for-byte. It is unmodified, but it is not
/// untouched, and pretending otherwise would be dishonest. This is the single largest behavioural
/// difference between the two builds and is documented in docs/windows/NETWORKING.md.
/// </item>
/// <item>
/// <b>Nothing is opened until something needs routing.</b> When routing is paused, or when no enabled
/// rule sends anything to the proxy, the handles are closed and not one packet is intercepted. A
/// paused SplitLane on Windows really is inert.
/// </item>
/// </list>
/// </remarks>
public sealed class DivertPipeline : IAsyncDisposable
{
    private const string LogCategory = "divert";

    /// <summary>Maximum packet WinDivert will hand back, plus room for the largest jumbo frame.</summary>
    private const int PacketBufferSize = 0xFFFF;

    /// <summary>Interface index of the loopback adapter, which is fixed on Windows.</summary>
    private const uint LoopbackInterfaceIndex = 1;

    private readonly NatTable _nat;
    private readonly DnsObserver _dns;
    private readonly ProcessResolver _processes;
    private readonly EngineStatistics _statistics;
    private readonly Func<RuleEngine> _engine;
    private readonly uint _selfProcessId;

    /// <summary>Local UDP ports owned by processes whose rule sends them to the proxy.</summary>
    /// <remarks>
    /// Populated from socket-layer BIND events, which are the only place a process id and a UDP local
    /// port appear together. An unconnected <c>sendto()</c> never produces a CONNECT event, so
    /// without this map a selected application's QUIC traffic would be unattributable at the packet
    /// layer and would escape DIRECT — the exact leak ADR 0004 exists to prevent.
    /// </remarks>
    private readonly ConcurrentDictionary<ushort, uint> _udpPortOwners = new();

    private DivertHandle? _socketHandle;
    private DivertHandle? _networkHandle;
    private DivertHandle? _dnsHandle;
    private Thread? _socketThread;
    private Thread? _networkThread;
    private Thread? _dnsThread;
    private volatile bool _running;
    private ushort _listenerPort;
    private long _socketEvents;
    private long _packetsSeen;
    private long _redirected;
    private long _sendFailures;
    private Timer? _heartbeat;

    /// <summary>Builds a pipeline over the shared engine state.</summary>
    public DivertPipeline(
        NatTable nat,
        DnsObserver dns,
        ProcessResolver processes,
        EngineStatistics statistics,
        Func<RuleEngine> engine)
    {
        _nat = nat ?? throw new ArgumentNullException(nameof(nat));
        _dns = dns ?? throw new ArgumentNullException(nameof(dns));
        _processes = processes ?? throw new ArgumentNullException(nameof(processes));
        _statistics = statistics ?? throw new ArgumentNullException(nameof(statistics));
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _selfProcessId = (uint)Environment.ProcessId;
    }

    /// <summary>Whether the divert threads are running.</summary>
    public bool IsRunning => _running;

    /// <summary>Driver version, once a handle has been opened.</summary>
    public string? DriverVersion { get; private set; }

    /// <summary>
    /// Filter for the socket layer.
    /// </summary>
    /// <remarks>
    /// BIND is included for UDP attribution, CONNECT for the routing decision itself, and CLOSE so
    /// the NAT table does not have to rely on expiry alone to forget a finished connection.
    /// </remarks>
    internal const string SocketFilter = "event = CONNECT or event = BIND or event = CLOSE";

    /// <summary>
    /// Filter for the packet layer, given the redirect listener's port.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Three clauses, and each one earns its place:
    /// </para>
    /// <list type="number">
    /// <item>Outbound non-loopback TCP — the application's traffic, which may need redirecting.</item>
    /// <item>Outbound loopback TCP from the listener — the replies, which need restoring. Matching on
    /// the listener's own source port keeps the redirected traffic itself, whose source port is the
    /// application's, from being captured a second time and looping.</item>
    /// <item>Outbound non-loopback UDP — needed only so that a selected application's datagrams can
    /// be dropped rather than allowed to escape. This is the expensive clause, and it is here because
    /// failing closed matters more than throughput (ADR 0004).</item>
    /// </list>
    /// </remarks>
    internal static string NetworkFilter(ushort listenerPort) =>
        $"(outbound and tcp and not loopback) or " +
        $"(outbound and tcp and loopback and tcp.SrcPort = {listenerPort}) or " +
        $"(outbound and udp and not loopback)";

    /// <summary>Filter for the DNS observer: inbound answers only, sniffed.</summary>
    internal const string DnsFilter = "inbound and udp and udp.SrcPort = 53";

    /// <summary>
    /// Opens the handles and starts the threads.
    /// </summary>
    /// <param name="listenerPort">Port the redirect listener has already bound.</param>
    public void Start(ushort listenerPort)
    {
        if (_running)
        {
            return;
        }

        ArgumentOutOfRangeException.ThrowIfZero(listenerPort);
        _listenerPort = listenerPort;

        _socketHandle = DivertHandle.Open(
            SocketFilter, WinDivertLayer.Socket, priority: 0,
            WinDivertFlags.Sniff | WinDivertFlags.RecvOnly);

        var major = _socketHandle.GetParam(WinDivertParam.VersionMajor);
        var minor = _socketHandle.GetParam(WinDivertParam.VersionMinor);
        DriverVersion = major is not null && minor is not null ? $"{major}.{minor}" : null;

        _networkHandle = DivertHandle.Open(
            NetworkFilter(listenerPort), WinDivertLayer.Network, priority: 0, WinDivertFlags.None);

        // A deeper queue costs kernel memory and buys tolerance for a scheduling hiccup in the
        // drain thread. Dropping a packet here is a stalled connection, so the trade favours depth.
        _networkHandle.SetParam(WinDivertParam.QueueLength, 8192);
        _networkHandle.SetParam(WinDivertParam.QueueTime, 2000);

        // The DNS observer is opened last and is optional: losing hostname recovery degrades SOCKS5
        // requests to IP literals, which still work. It must never prevent routing from starting.
        try
        {
            _dnsHandle = DivertHandle.Open(
                DnsFilter, WinDivertLayer.Network, priority: 1,
                WinDivertFlags.Sniff | WinDivertFlags.RecvOnly);
        }
        catch (DivertException ex)
        {
            SplitLaneLog.Warning(LogCategory, $"DNS observer unavailable, falling back to IP literals: {ex.Message}");
        }

        _running = true;

        _socketThread = StartThread("SplitLane.SocketPump", () => SocketLoop(_socketHandle));
        _networkThread = StartThread("SplitLane.PacketLoop", () => NetworkLoop(_networkHandle));

        if (_dnsHandle is not null)
        {
            _dnsThread = StartThread("SplitLane.DnsObserver", () => DnsLoop(_dnsHandle));
        }

        // A heartbeat, because "nothing is happening" and "everything is broken" are otherwise
        // indistinguishable from outside. Debug level, so it costs nothing in normal operation.
        _heartbeat = new Timer(
            _ => SplitLaneLog.Debug(
                LogCategory,
                $"socket events {Interlocked.Read(ref _socketEvents)}, " +
                $"packets {Interlocked.Read(ref _packetsSeen)}, " +
                $"redirected {Interlocked.Read(ref _redirected)}, " +
                $"send failures {Interlocked.Read(ref _sendFailures)}, " +
                $"nat entries {_nat.Count}"),
            null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));

        SplitLaneLog.Info(
            LogCategory,
            $"divert started, driver {DriverVersion ?? "unknown"}, listener port {listenerPort}");
    }

    private static Thread StartThread(string name, Action body)
    {
        // Dedicated OS threads rather than thread-pool work items. Each of these loops parks in a
        // blocking native call for its entire life; on the pool that is a starved worker.
        var thread = new Thread(() => body()) { Name = name, IsBackground = true };
        thread.Start();
        return thread;
    }

    // ---- Socket layer -----------------------------------------------------------------------

    private void SocketLoop(DivertHandle handle)
    {
        var failures = 0;

        try
        {
            while (_running)
            {
                if (!handle.Receive(Span<byte>.Empty, out _, out var address, out var error))
                {
                    if (!_running)
                    {
                        return;
                    }

                    // A failing receive is reported, not slept through. The first version spun here
                    // on a one-millisecond sleep and routed nothing, which from the outside looked
                    // exactly like a machine with no traffic on it.
                    if (++failures is 1 or 100 or 1000)
                    {
                        SplitLaneLog.Error(
                            LogCategory,
                            $"socket layer receive failed (Win32 {error}), {failures} so far - no " +
                            "application identity is reaching the router, so everything is DIRECT");
                    }

                    Thread.Sleep(failures < 100 ? 1 : 50);
                    continue;
                }

                failures = 0;
                Interlocked.Increment(ref _socketEvents);
                HandleSocketEvent(address);
            }
        }
        catch (Exception ex) when (_running)
        {
            SplitLaneLog.Error(LogCategory, "socket pump stopped", ex);
        }
    }

    private void HandleSocketEvent(in WinDivertAddress address)
    {
        var socket = address.Socket;

        switch (address.Event)
        {
            case WinDivertEvent.SocketClose:
                _nat.Remove(socket.LocalPort);
                _udpPortOwners.TryRemove(socket.LocalPort, out _);
                return;

            case WinDivertEvent.SocketBind when socket.Protocol == PacketView.ProtocolUdp:
                TrackUdpBind(socket);
                return;

            case WinDivertEvent.SocketConnect:
                HandleConnect(address);
                return;

            default:
                return;
        }
    }

    private void TrackUdpBind(in WinDivertDataSocket socket)
    {
        if (socket.ProcessId == _selfProcessId)
        {
            return;
        }

        var path = _processes.Resolve(socket.ProcessId);
        if (path.Length == 0)
        {
            return;
        }

        // Only ports belonging to applications that would be proxied are remembered. Everything else
        // never needs a lookup, and a map of every UDP socket on the machine would be both larger and
        // a description of what the user is doing.
        var flow = new FlowDescriptor(
            socket.ProcessId, path, "203.0.113.1", 0, FlowProtocol.Udp);

        if (_engine().Decide(flow).Action == RouteAction.Block)
        {
            _udpPortOwners[socket.LocalPort] = socket.ProcessId;
        }
    }

    private void HandleConnect(in WinDivertAddress address)
    {
        var socket = address.Socket;

        if (socket.Protocol != PacketView.ProtocolTcp)
        {
            return;
        }

        var isSelf = socket.ProcessId == _selfProcessId;
        var path = isSelf ? string.Empty : _processes.Resolve(socket.ProcessId);
        var remote = SocketAddressReader.ReadRemote(address);
        var local = SocketAddressReader.ReadLocal(address);
        var remoteText = remote.ToString();
        var hostname = _dns.Lookup(remote);

        var flow = new FlowDescriptor(
            socket.ProcessId,
            path,
            remoteText,
            socket.RemotePort,
            FlowProtocol.Tcp,
            hostname,
            isSelf);

        var engine = _engine();
        var decision = engine.Decide(flow);

        switch (decision.Action)
        {
            case RouteAction.Proxy:
                engine.Snapshot.TryGetRule(path, out var rule, out _);
                _nat.Record(socket.LocalPort, NatTable.EntryFor(
                    local, remote, socket.RemotePort, socket.ProcessId, path, rule, hostname,
                    DateTimeOffset.UtcNow));
                _statistics.CountProxied();
                SplitLaneLog.Debug(
                    LogCategory,
                    $"PROXY {ExecutablePath.FileName(path)} :{socket.LocalPort} -> " +
                    $"{flow.DestinationDisplay}");
                break;

            case RouteAction.Block:
                _statistics.CountBlocked();
                break;

            default:
                _statistics.CountDirect();
                if (engine.Snapshot.LogsDirectFlows)
                {
                    SplitLaneLog.Debug(
                        LogCategory,
                        $"DIRECT {ExecutablePath.FileName(path)} -> {flow.DestinationDisplay} ({decision.Explain()})");
                }

                break;
        }
    }

    // ---- Packet layer -----------------------------------------------------------------------

    private void NetworkLoop(DivertHandle handle)
    {
        var buffer = GC.AllocateArray<byte>(PacketBufferSize, pinned: true);
        var failures = 0;

        try
        {
            while (_running)
            {
                if (!handle.Receive(buffer, out var length, out var address, out var error))
                {
                    if (!_running)
                    {
                        return;
                    }

                    if (++failures is 1 or 100 or 1000)
                    {
                        SplitLaneLog.Error(
                            LogCategory, $"packet receive failed (Win32 {error}), {failures} so far");
                    }

                    Thread.Sleep(failures < 100 ? 1 : 50);
                    continue;
                }

                failures = 0;
                Interlocked.Increment(ref _packetsSeen);

                var packet = buffer.AsSpan(0, length);
                var action = Classify(packet, ref address);

                if (action == PacketAction.Drop)
                {
                    continue;
                }

                // Everything not dropped is reinjected — modified for a redirected connection,
                // byte-for-byte identical for everything else.
                if (action == PacketAction.Rewritten)
                {
                    // Let the driver settle the checksums and their flags on anything we changed.
                    handle.CalculateChecksums(packet, ref address);
                }

                if (!handle.Send(packet, ref address, out var sendError) && _running)
                {
                    if (Interlocked.Increment(ref _sendFailures) is 1 or 100 or 1000)
                    {
                        SplitLaneLog.Error(
                            LogCategory,
                            $"reinjection refused (Win32 {sendError}) — a refused packet is a " +
                            "connection that hangs with no error anywhere");
                    }
                }
            }
        }
        catch (Exception ex) when (_running)
        {
            SplitLaneLog.Error(LogCategory, "packet loop stopped", ex);
        }
    }

    private enum PacketAction
    {
        /// <summary>Reinject unchanged.</summary>
        Forward,

        /// <summary>Reinject after a rewrite, so the checksums have to be settled first.</summary>
        Rewritten,

        /// <summary>Do not reinject.</summary>
        Drop,
    }

    /// <summary>Decides what to do with one captured packet, rewriting it in place when needed.</summary>
    private PacketAction Classify(Span<byte> packet, ref WinDivertAddress address)
    {
        if (!PacketView.TryParse(packet, out var view) || !view.HasPorts)
        {
            return PacketAction.Forward;
        }

        if (view.Protocol == PacketView.ProtocolUdp)
        {
            return ClassifyUdp(view);
        }

        // Reply from the redirect listener on its way back to the application.
        if (address.Loopback && view.SourcePort == _listenerPort)
        {
            return RestoreReply(packet, view, ref address);
        }

        // Application traffic that a socket-layer decision already marked for the proxy lane.
        if (_nat.TryGet(view.SourcePort, out var entry) &&
            entry.OriginalDestinationPort == view.DestinationPort &&
            AddressMatches(view.DestinationAddress, entry.OriginalDestination))
        {
            if (RedirectRewriter.TryRedirectToListener(packet, _listenerPort))
            {
                // The packet is now loopback-to-loopback and its destination is a socket on this
                // machine, so it is injected INBOUND on the loopback interface rather than sent
                // outbound. Injected outbound, WinDivert accepts it and the stack silently discards
                // it: the send succeeds, no error is raised anywhere, and the application's SYN
                // simply retransmits until it gives up. That was observed directly - ten packets
                // redirected, zero send failures, nothing ever arriving at the listener.
                address.Loopback = true;
                address.Outbound = false;
                address.Network.IfIdx = LoopbackInterfaceIndex;
                address.Network.SubIfIdx = 0;
                Interlocked.Increment(ref _redirected);
                return PacketAction.Rewritten;
            }
        }

        return PacketAction.Forward;
    }

    private PacketAction ClassifyUdp(in PacketView view)
    {
        if (!_udpPortOwners.ContainsKey(view.SourcePort))
        {
            return PacketAction.Forward;
        }

        // A selected application's datagram. Dropped, never forwarded: letting it out would be the
        // silent QUIC bypass the design exists to prevent. The application sees the failure and falls
        // back to TCP, which is proxied correctly.
        _statistics.CountBlocked();
        return PacketAction.Drop;
    }

    private PacketAction RestoreReply(Span<byte> packet, in PacketView view, ref WinDivertAddress address)
    {
        if (!_nat.TryGet(view.DestinationPort, out var entry))
        {
            // The connection is gone. Dropping is right: reinjecting a loopback packet addressed to a
            // port whose NAT entry expired would deliver the listener's bytes to whatever now owns
            // that port.
            return PacketAction.Drop;
        }

        if (!RedirectRewriter.TryRestoreFromListener(
                packet, entry.OriginalDestination, entry.OriginalDestinationPort, entry.OriginalSource))
        {
            return PacketAction.Drop;
        }

        // The packet is no longer loopback traffic: it now claims to come from the real destination
        // and is delivered inbound to the application's socket.
        address.Loopback = false;
        address.Outbound = false;
        return PacketAction.Rewritten;
    }

    private static bool AddressMatches(ReadOnlySpan<byte> packetAddress, IPAddress expected)
    {
        Span<byte> buffer = stackalloc byte[16];
        return expected.TryWriteBytes(buffer, out var written) &&
               written == packetAddress.Length &&
               buffer[..written].SequenceEqual(packetAddress);
    }

    // ---- DNS observer -----------------------------------------------------------------------

    private void DnsLoop(DivertHandle handle)
    {
        var buffer = GC.AllocateArray<byte>(PacketBufferSize, pinned: true);

        try
        {
            while (_running)
            {
                if (!handle.Receive(buffer, out var length, out _, out _))
                {
                    if (!_running)
                    {
                        return;
                    }

                    Thread.Sleep(5);
                    continue;
                }

                if (!PacketView.TryParse(buffer.AsSpan(0, length), out var view) ||
                    view.Protocol != PacketView.ProtocolUdp)
                {
                    continue;
                }

                // UDP header is eight bytes; the DNS message follows.
                var payloadOffset = view.TransportOffset + 8;
                if (payloadOffset >= length)
                {
                    continue;
                }

                _dns.IngestResponse(buffer.AsSpan(payloadOffset, length - payloadOffset));
            }
        }
        catch (Exception ex) when (_running)
        {
            SplitLaneLog.Error(LogCategory, "DNS observer stopped", ex);
        }
    }

    // ---- Shutdown ---------------------------------------------------------------------------

    /// <summary>Stops the threads and closes the handles.</summary>
    public async ValueTask DisposeAsync()
    {
        if (!_running && _socketHandle is null && _networkHandle is null && _dnsHandle is null)
        {
            return;
        }

        _running = false;

        // Shutdown before close: a thread parked inside WinDivertRecv must be released first, and
        // closing the handle underneath it is not defined behaviour.
        _heartbeat?.Dispose();
        _heartbeat = null;

        _socketHandle?.Shutdown();
        _networkHandle?.Shutdown();
        _dnsHandle?.Shutdown();

        await Task.WhenAll(
            JoinAsync(_socketThread),
            JoinAsync(_networkThread),
            JoinAsync(_dnsThread)).ConfigureAwait(false);

        _socketHandle?.Dispose();
        _networkHandle?.Dispose();
        _dnsHandle?.Dispose();

        _socketHandle = null;
        _networkHandle = null;
        _dnsHandle = null;
        _socketThread = null;
        _networkThread = null;
        _dnsThread = null;

        _udpPortOwners.Clear();
        _nat.Clear();

        SplitLaneLog.Info(LogCategory, "divert stopped");
    }

    private static Task JoinAsync(Thread? thread) => thread is null
        ? Task.CompletedTask
        : Task.Run(() =>
        {
            // A bounded join. If a native call refuses to return, the process is going away anyway
            // and a hung shutdown is worse than an abandoned background thread.
            if (!thread.Join(TimeSpan.FromSeconds(5)))
            {
                SplitLaneLog.Warning(LogCategory, $"thread {thread.Name} did not stop within five seconds");
            }
        });
}
