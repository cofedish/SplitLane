using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using SplitLane.Core.Logging;
using SplitLane.Core.Models;
using SplitLane.Core.Proxy.Socks5;
using SplitLane.Core.Rules;
using SplitLane.Engine.Flows;
using SplitLane.Engine.Interop;
using SplitLane.Engine.Net;
using SplitLane.Engine.Relay;
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
/// <summary>What was decided about a UDP socket when it bound.</summary>
/// <param name="ProcessId">Who owns it. Diagnostic.</param>
/// <param name="Action">
/// Proxy to carry its datagrams, Block to refuse them. Never Direct: a selected application's
/// datagrams do not leave this machine unproxied, and an unselected one is not in this table.
/// </param>
internal readonly record struct UdpSocketDecision(uint ProcessId, RouteAction Action);

public sealed class DivertPipeline : IAsyncDisposable
{
    private const string LogCategory = "divert";

    /// <summary>Maximum packet WinDivert will hand back, plus room for the largest jumbo frame.</summary>
    private const int PacketBufferSize = 0xFFFF;

    /// <summary>Interface index of the loopback adapter, which is fixed on Windows.</summary>
    private const uint LoopbackInterfaceIndex = 1;

    /// <summary>
    /// How long a SYN waits for its routing decision before being let through.
    /// </summary>
    /// <remarks>
    /// Long enough to absorb the scheduling gap between two threads, short enough that a connection
    /// SplitLane has no interest in is delayed imperceptibly. Letting it through on timeout rather
    /// than dropping it is deliberate: a dropped SYN breaks an application SplitLane was never asked
    /// to touch, which is a worse failure than a missed redirect.
    /// </remarks>
    private const int DecisionWaitMilliseconds = 8;

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
    private readonly ConcurrentDictionary<ushort, UdpSocketDecision> _udpPortOwners = new();
    private readonly ConcurrentDictionary<ushort, IPAddress> _udpOrigins = new();
    private UdpRelay? _udpRelay;
    private UdpLanePool? _lanePool;

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
    private long _lateDecisions;
    private long _decisionsWaitedFor;
    private long _decisionTimeouts;
    private long _traced;
    private long _udpRedirected;
    private long _udpRestored;
    private Timer? _heartbeat;
    private DivertHandle? _traceHandle;
    private Thread? _traceThread;

    /// <summary>
    /// Whether a redirected connection is moved to loopback, or to the machine's own address.
    /// </summary>
    /// <remarks>
    /// Loopback is the original design and does not currently deliver: the packet is rewritten, the
    /// driver accepts the injection, and nothing ever reaches the listener. This switch exists so
    /// both shapes can be tried in one elevated session rather than one rebuild at a time.
    /// </remarks>
    public bool UseLoopbackRedirect { get; init; } = true;

    /// <summary>Whether to sniff the redirect port and report what the stack actually sees.</summary>
    /// <remarks>
    /// Everything known about the failure so far is inferred from counters. This makes it observed.
    /// </remarks>
    public bool TraceRedirects { get; init; }

    /// <summary>
    /// Whether a selected application's datagrams are carried through the proxy or refused.
    /// </summary>
    /// <remarks>
    /// Off means refused, which is what this did for its whole life before the relay existed and is
    /// still the safe answer. It never means passed through unproxied.
    /// </remarks>
    public bool ProxiesUdp { get; init; } = true;

    /// <summary>Where the upstream is, read freshly because configuration changes underneath.</summary>
    public Func<ProxyConfiguration>? Proxy { get; init; }

    /// <summary>Its credential, read the same way.</summary>
    public Func<Socks5Credential?>? Credential { get; init; }

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
    internal static string NetworkFilter(ushort listenerPort, UdpLanePool? lanes = null)
    {
        var filter =
            $"(outbound and tcp and not loopback) or " +
            $"(outbound and tcp and loopback and tcp.SrcPort = {listenerPort}) or " +
            $"(outbound and udp and not loopback)";

        // Loopback UDP, for the lanes' replies on their way back to the application - and only from
        // the block reserved for them.
        //
        // An earlier version said "outbound and udp and loopback" with no port test, on the
        // reasoning that a dictionary lookup per packet is cheap. It is; ten thousand packets a
        // second of somebody else's traffic is not. On a machine whose DNS runs through a local
        // tunnel it broke name resolution outright, and what the user saw was an internet that had
        // gone, with TCP by address still working and no error anywhere.
        if (lanes is not null)
        {
            filter +=
                $" or (outbound and udp and loopback and " +
                $"udp.SrcPort >= {lanes.BasePort} and udp.SrcPort <= {lanes.LastPort})";
        }

        return filter;
    }

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

        if (ProxiesUdp && Proxy is not null && Credential is not null)
        {
            try
            {
                _lanePool = new UdpLanePool();
            }
            catch (IOException ex)
            {
                // Without a block there is nowhere to relay datagrams to. Refusing them is the old
                // behaviour and a working machine; capturing every loopback datagram instead is not.
                SplitLaneLog.Warning(
                    LogCategory,
                    $"UDP will be refused rather than relayed: {ex.Message}");
            }
        }

        _networkHandle = DivertHandle.Open(
            NetworkFilter(listenerPort, _lanePool), WinDivertLayer.Network, priority: 0, WinDivertFlags.None);

        // A deeper queue costs kernel memory and buys tolerance for a scheduling hiccup in the
        // drain thread. Dropping a packet here is a stalled connection, so the trade favours depth.
        _networkHandle.SetParam(WinDivertParam.QueueLength, 8192);
        _networkHandle.SetParam(WinDivertParam.QueueTime, 2000);

        if (_lanePool is { } pool && Proxy is { } proxy && Credential is { } credential)
        {
            _udpRelay = new UdpRelay(pool, proxy, credential);
        }

        if (TraceRedirects)
        {
            // A sniffing handle on the redirect port. Sniff, so it can only observe: a trace that
            // can affect delivery is a trace that changes the thing it is measuring.
            try
            {
                _traceHandle = DivertHandle.Open(
                    $"tcp and (tcp.DstPort = {listenerPort} or tcp.SrcPort = {listenerPort})",
                    WinDivertLayer.Network, priority: 2,
                    WinDivertFlags.Sniff | WinDivertFlags.RecvOnly);
            }
            catch (DivertException ex)
            {
                SplitLaneLog.Warning(LogCategory, $"redirect trace unavailable: {ex.Message}");
            }
        }

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

        if (_traceHandle is not null)
        {
            _traceThread = StartThread("SplitLane.RedirectTrace", () => TraceLoop(_traceHandle));
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
                $"late {Interlocked.Read(ref _lateDecisions)}, " +
                $"waited {Interlocked.Read(ref _decisionsWaitedFor)}, " +
                $"wait timeouts {Interlocked.Read(ref _decisionTimeouts)}, " +
                $"nat entries {_nat.Count}, " +
                $"udp sent {_udpRelay?.Sent ?? 0}, " +
                $"udp back {_udpRelay?.Received ?? 0}, " +
                $"udp redirected {Interlocked.Read(ref _udpRedirected)}, " +
                $"udp restored {Interlocked.Read(ref _udpRestored)}, " +
                $"udp dropped {_udpRelay?.Refused ?? 0}, " +
                $"lanes {_udpRelay?.Count ?? 0}"),
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

                if (_udpPortOwners.TryRemove(socket.LocalPort, out _))
                {
                    // The association at the proxy outlives the socket that needed it otherwise, and
                    // each one holds a TCP connection open there.
                    _udpRelay?.Forget(socket.LocalPort);
                }

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

        // Both answers are remembered now, because they lead to different work: a refused socket's
        // datagrams are dropped where they are found, and a proxied socket's are carried. What is
        // still not remembered is every other socket on the machine, which would be both larger and
        // a description of what the user is doing.
        var action = _engine().Decide(flow).Action;

        if (action is RouteAction.Block or RouteAction.Proxy)
        {
            _udpPortOwners[socket.LocalPort] = new UdpSocketDecision(socket.ProcessId, action);
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
                _nat.RecordDirect(socket.LocalPort, remote, socket.RemotePort);
                _statistics.CountBlocked();
                break;

            default:
                // Recorded even though nothing is redirected. The packet loop reads the absence of a
                // decision as "not decided yet" and waits; without this every connection an
                // unselected application opens pays that wait in full, for an answer already given.
                _nat.RecordDirect(socket.LocalPort, remote, socket.RemotePort);
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

    /// <summary>
    /// Waits briefly for the socket pump to record a decision for this port.
    /// </summary>
    /// <remarks>
    /// Spins rather than blocking on a synchronisation primitive. The wait is measured in
    /// microseconds in the common case - the socket event is usually already in flight - and adding
    /// a per-port wait handle would cost an allocation on every connection on the machine to save a
    /// few spins on some of them.
    /// </remarks>
    private void WaitForDecision(in PacketView view)
    {
        var deadline = Stopwatch.GetTimestamp() + (Stopwatch.Frequency * DecisionWaitMilliseconds / 1000);
        var spins = 0;

        while (Stopwatch.GetTimestamp() < deadline)
        {
            if (HasDecision(view))
            {
                Interlocked.Increment(ref _decisionsWaitedFor);
                return;
            }

            // Yield rather than burn the core. The socket pump is on another thread and needs one
            // of these to make progress.
            if (++spins % 8 == 0)
            {
                Thread.Sleep(0);
            }
            else
            {
                Thread.SpinWait(64);
            }
        }

        Interlocked.Increment(ref _decisionTimeouts);
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
            return ClassifyUdp(packet, view, ref address);
        }

        // Reply from the redirect listener on its way back to the application.
        if (address.Loopback && view.SourcePort == _listenerPort)
        {
            return RestoreReply(packet, view, ref address);
        }

        // A SYN may arrive before the socket-layer decision that belongs to it.
        //
        // Windows generates the socket event first, but the two travel through separate WinDivert
        // queues on separate threads, and delivery order between them is not guaranteed. Losing that
        // race means the connection establishes with its real destination and can no longer be
        // proxied at all - a silent DIRECT leak, which is the failure this product exists to prevent.
        //
        // So a SYN with no decision waits for one, briefly. Only SYNs wait, and only for a few
        // milliseconds: they are a small fraction of traffic, the cost lands on connection setup
        // rather than throughput, and a bounded wait cannot stall the packet loop indefinitely.
        if (view.IsTcpSyn && !HasDecision(view))
        {
            WaitForDecision(view);
        }

        // Application traffic that a socket-layer decision already marked for the proxy lane.
        if (_nat.TryGet(view.SourcePort, out var entry) &&
            entry.OriginalDestinationPort == view.DestinationPort &&
            AddressMatches(view.DestinationAddress, entry.OriginalDestination))
        {
            // Only connections whose opening SYN was redirected. If the SYN got out before the
            // socket event was processed, the connection is already established with its real
            // destination, and rewriting its later packets breaks something that was working.
            if (view.IsTcpSyn)
            {
                entry.SynRedirected = true;
            }
            else if (!entry.SynRedirected)
            {
                if (Interlocked.Increment(ref _lateDecisions) is 1 or 50)
                {
                    SplitLaneLog.Warning(
                        LogCategory,
                        $"connection from port {view.SourcePort} was established before its routing " +
                        "decision was recorded, so it is being left alone rather than broken");
                }

                return PacketAction.Forward;
            }

            if (RedirectRewriter.TryRedirectToListener(packet, _listenerPort, UseLoopbackRedirect))
            {
                // The direction flags are left exactly as captured, for both shapes.
                //
                // This is the whole lesson of this path, learned the expensive way. Asserting where
                // a packet belongs in the stack - flipping it to inbound, declaring it loopback,
                // naming an interface index - produces a packet WinDivert accepts and the stack
                // discards, with no error at either end. Rewriting only the addresses and handing it
                // back the way it arrived lets the stack route it, which is what routing is for.
                //
                // Which addresses to use is a separate question, and the answer is constrained: a
                // packet whose source is one of the machine's own addresses, arriving on a physical
                // interface, is rejected as a spoof before it ever reaches a socket. That is what
                // the local-address shape ran into - the stack answered with a reset and the
                // listener never saw a connection. Both endpoints on loopback satisfy that rule.
                Interlocked.Increment(ref _redirected);
                return PacketAction.Rewritten;
            }
        }

        return PacketAction.Forward;
    }

    private PacketAction ClassifyUdp(Span<byte> packet, in PacketView view, ref WinDivertAddress address)
    {
        // A reply coming back from one of our own lanes, on its way to the application. Rewritten so
        // it carries the address the application wrote to, which is the whole point of the lane.
        if (_udpRelay is { } relay && address.Loopback &&
            relay.TryResolveLane(view.SourcePort, out var applicationPort, out var remote) &&
            view.DestinationPort == applicationPort)
        {
            if (!_udpOrigins.TryGetValue(applicationPort, out var origin) ||
                !RedirectRewriter.TryRestoreFromListener(
                    packet, remote.Address, (ushort)remote.Port, origin))
            {
                return PacketAction.Drop;
            }

            Interlocked.Increment(ref _udpRestored);
            return PacketAction.Rewritten;
        }

        if (!_udpPortOwners.TryGetValue(view.SourcePort, out var decision))
        {
            return PacketAction.Forward;
        }

        // A selected application's datagram never leaves this machine as it is. Either it goes
        // through the proxy or it goes nowhere; forwarding it would be the silent bypass the design
        // exists to prevent.
        if (decision.Action == RouteAction.Proxy && _udpRelay is not null && view.IsIPv4)
        {
            var destination = new IPAddress(view.DestinationAddress);
            var lanePort = _udpRelay.LaneFor(view.SourcePort, destination, view.DestinationPort);

            if (lanePort is null)
            {
                _statistics.CountBlocked();
                return PacketAction.Drop;
            }

            // The application's own address, kept so the reply can be addressed back to it. The
            // datagram's source is about to become loopback, and after that nothing in the packet
            // remembers where it came from.
            _udpOrigins[view.SourcePort] = new IPAddress(view.SourceAddress);

            if (!RedirectRewriter.TryRedirectToListener(packet, lanePort.Value, UseLoopbackRedirect))
            {
                return PacketAction.Drop;
            }

            Interlocked.Increment(ref _udpRedirected);
            return PacketAction.Rewritten;
        }

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

        // The direction flags are left exactly as captured, and that is the whole lesson of this
        // path. Asserting a direction - flipping the reply to inbound because "it is going to the
        // application" - produced a packet the stack accepted and discarded. Rewriting only the
        // addresses and handing it back the way it arrived lets the stack route it, which is what it
        // is for: a packet addressed to this machine's own address loops back on its own.
        return PacketAction.Rewritten;
    }

    /// <summary>
    /// Whether the socket layer has already ruled on this connection, either way.
    /// </summary>
    /// <remarks>
    /// The destination is checked as well as the port. Ephemeral ports are recycled, and a row left
    /// behind by an unrelated connection that happened to hold the same port must not be mistaken
    /// for this one's answer - in the direction that matters, that would end a real decision's wait
    /// early and let a selected application's SYN out un-redirected.
    /// </remarks>
    private bool HasDecision(in PacketView view)
    {
        if (_nat.TryGet(view.SourcePort, out var entry) &&
            entry.OriginalDestinationPort == view.DestinationPort &&
            AddressMatches(view.DestinationAddress, entry.OriginalDestination))
        {
            return true;
        }

        return _nat.TryGetDirect(view.SourcePort, out var destination, out var port) &&
               port == view.DestinationPort &&
               AddressMatches(view.DestinationAddress, destination);
    }

    private static bool AddressMatches(ReadOnlySpan<byte> packetAddress, IPAddress expected)
    {
        Span<byte> buffer = stackalloc byte[16];
        return expected.TryWriteBytes(buffer, out var written) &&
               written == packetAddress.Length &&
               buffer[..written].SequenceEqual(packetAddress);
    }

    /// <summary>
    /// Reports every packet the stack actually carries on the redirect port.
    /// </summary>
    /// <remarks>
    /// If a redirected SYN appears here, the injection worked and the problem is the listening
    /// socket. If it never appears, the injection is being discarded and the problem is the packet
    /// or the injection path. Those are opposite investigations, and counters cannot tell them apart.
    /// </remarks>
    private void TraceLoop(DivertHandle handle)
    {
        var buffer = GC.AllocateArray<byte>(PacketBufferSize, pinned: true);

        try
        {
            while (_running)
            {
                if (!handle.Receive(buffer, out var length, out var address, out _))
                {
                    if (!_running)
                    {
                        return;
                    }

                    Thread.Sleep(5);
                    continue;
                }

                if (!PacketView.TryParse(buffer.AsSpan(0, length), out var view) || !view.HasPorts)
                {
                    continue;
                }

                // Only the first few, and only handshake packets. A trace that floods the log during
                // a bulk transfer is a trace nobody can read.
                if (Interlocked.Increment(ref _traced) <= 40 && (view.IsTcpSyn || view.IsTcpReset))
                {
                    SplitLaneLog.Debug(
                        LogCategory,
                        $"TRACE {(view.IsTcpSyn ? "SYN" : "RST")} " +
                        $"{new IPAddress(view.SourceAddress)}:{view.SourcePort} -> " +
                        $"{new IPAddress(view.DestinationAddress)}:{view.DestinationPort} " +
                        $"outbound={address.Outbound} loopback={address.Loopback} ifIdx={address.Network.IfIdx}");
                }
            }
        }
        catch (Exception ex) when (_running)
        {
            SplitLaneLog.Error(LogCategory, "redirect trace stopped", ex);
        }
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

        ShutDownHandle(_socketHandle, "socket");
        ShutDownHandle(_networkHandle, "network");
        ShutDownHandle(_dnsHandle, "dns");
        ShutDownHandle(_traceHandle, "trace");

        await Task.WhenAll(
            JoinAsync(_socketThread),
            JoinAsync(_networkThread),
            JoinAsync(_dnsThread),
            JoinAsync(_traceThread)).ConfigureAwait(false);

        _socketHandle?.Dispose();
        _networkHandle?.Dispose();
        _dnsHandle?.Dispose();
        _traceHandle?.Dispose();

        _socketHandle = null;
        _networkHandle = null;
        _dnsHandle = null;
        _traceHandle = null;
        _socketThread = null;
        _networkThread = null;
        _dnsThread = null;
        _traceThread = null;

        _udpPortOwners.Clear();
        _udpOrigins.Clear();
        _lanePool?.Dispose();
        _lanePool = null;

        if (_udpRelay is { } relay)
        {
            _udpRelay = null;
            relay.DisposeAsync().AsTask().GetAwaiter().GetResult();
        }

        _nat.Clear();

        SplitLaneLog.Info(LogCategory, "divert stopped");
    }

    /// <summary>Unblocks a handle's thread, and says so when it cannot.</summary>
    private static void ShutDownHandle(DivertHandle? handle, string name)
    {
        if (handle is not null && !handle.Shutdown())
        {
            SplitLaneLog.Warning(
                LogCategory,
                $"the {name} handle refused to shut down (error {handle.LastError}); its thread will " +
                "not be released until a packet arrives");
        }
    }

    private static Task JoinAsync(Thread? thread) => thread is null
        ? Task.CompletedTask
        : Task.Run(() =>
        {
            // A bounded join. If a native call refuses to return, the process is going away anyway
            // and a hung shutdown is worse than an abandoned background thread.
            if (!thread.Join(TimeSpan.FromSeconds(5)))
            {
                // Not cosmetic. A thread still inside a native call keeps the process alive past the
                // point the service manager considers it stopped, and an installer replacing that
                // executable during an upgrade then fails - which is how this was noticed.
                SplitLaneLog.Warning(
                    LogCategory,
                    $"thread {thread.Name} did not stop within five seconds; the process may outlive " +
                    "its own shutdown");
            }
        });
}
