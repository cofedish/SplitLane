using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
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

/// <summary>What was decided about a UDP socket when it bound.</summary>
/// <param name="ProcessId">Who owns it. Diagnostic.</param>
/// <param name="Action">
/// Proxy to carry its datagrams, Block to refuse them. Never Direct: a selected application's
/// datagrams do not leave this machine unproxied, and an unselected one is not in this table.
/// </param>
/// <param name="EndpointId">The socket that bound; only its CLOSE removes the decision.</param>
/// <param name="DualStack">
/// Bound to the IPv6 wildcard, so it may also send IPv4 datagrams on the same port.
/// </param>
internal readonly record struct UdpSocketDecision(
    uint ProcessId, RouteAction Action, ulong EndpointId = 0, bool DualStack = false);

/// <summary>The flow a UDP socket was described as when it bound, and which socket that was.</summary>
internal sealed record UdpFlow(FlowDescriptor Flow, ulong EndpointId, bool DualStack);

/// <summary>A TCP connection held while its process's identity is verified.</summary>
/// <param name="Flow">The flow as it was described at connect time.</param>
/// <param name="Local">The application's own address.</param>
/// <param name="Remote">Where it was connecting.</param>
/// <param name="Image">The process's image, whose verification is awaited.</param>
/// <param name="PackageFamily">The package family from the process token, if any.</param>
/// <param name="EndpointId">The socket that connected.</param>
internal sealed record PendingConnection(
    FlowDescriptor Flow, IPAddress Local, IPAddress Remote, ImageRecord Image, string? PackageFamily,
    ulong EndpointId = 0);

/// <summary>A UDP socket whose datagrams are held while its process's identity is verified.</summary>
/// <param name="Flow">The flow as it was described when the socket bound.</param>
/// <param name="Image">The process's image, whose verification is awaited.</param>
/// <param name="PackageFamily">The package family from the process token, if any.</param>
/// <param name="EndpointId">The socket that bound.</param>
/// <param name="DualStack">Bound to the IPv6 wildcard.</param>
internal sealed record PendingBind(
    FlowDescriptor Flow, ImageRecord Image, string? PackageFamily, ulong EndpointId = 0, bool DualStack = false);

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
/// lookup keyed on the source port. Windows generates the socket event before the SYN, but the two
/// arrive through separate queues on separate threads, so a SYN with no decision yet waits a few
/// milliseconds for one (see <see cref="WaitForDecision"/>).
/// </item>
/// <item>
/// <b>Unselected traffic is copied, not untouched.</b> On macOS, returning <c>false</c> hands the
/// flow back to the kernel and nothing is recreated. Here, an outbound packet from an unselected
/// application transits user mode and is reinjected byte-for-byte. It is unmodified, but it is not
/// untouched, and pretending otherwise would be dishonest. This is the single largest behavioural
/// difference between the two builds and is documented in docs/NETWORKING.md.
/// </item>
/// <item>
/// <b>Identity can take longer than a connection is willing to wait.</b> A process whose file name,
/// folder or size points at a selected application is not routed on that claim: its image is verified
/// in the background, and until then its SYN and datagrams are dropped - held, not refused, because
/// TCP retransmits the SYN a second later and by then the answer is usually in. Guessing either way
/// would be worse: DIRECT leaks a selected application, PROXY hands its lane to an impostor.
/// </item>
/// <item>
/// <b>The handles stay open while the engine routes</b>, whether or not any rule currently selects
/// anything; pausing routing makes every decision DIRECT but does not close them. Only stopping routing
/// does.
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

    /// <summary>
    /// How long a SYN, or the first datagram of an unknown UDP socket, waits for its routing decision.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Long enough to absorb the scheduling gap between two threads, short enough that a connection
    /// SplitLane has no interest in is delayed imperceptibly.
    /// </para>
    /// <para>
    /// What happens on timeout used to depend on luck: the SYN was let through, on the reasoning that a
    /// dropped SYN breaks an application SplitLane was never asked to touch. But "not decided" may be a
    /// selected application, and letting it through is exactly the silent DIRECT the product exists to
    /// prevent (SL-SEC-009). So whenever any rule could protect a flow
    /// (<see cref="RuleSnapshot.MayProtectTraffic"/>), an undecided SYN is dropped - TCP sends it again a
    /// second later, by when the decision is in - and only when nothing could be protected is it
    /// forwarded.
    /// </para>
    /// </remarks>
    private const int DecisionWaitMilliseconds = 8;

    /// <summary>How long a failed owner lookup for a UDP port is remembered.</summary>
    /// <remarks>
    /// The table lookup is not free; a socket whose owner cannot be found would otherwise repeat it for
    /// every datagram. While remembered, such datagrams are dropped if anything could be protected.
    /// </remarks>
    private static readonly long UnknownOwnerLifetimeTicks = Stopwatch.Frequency;

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
    /// <remarks>
    /// Keyed on family and port, not the port alone, and each row remembers the socket that made it
    /// (SL-SEC-005): a socket on the same number in the other family, or another socket sharing the
    /// port through address reuse, can neither erase nor overwrite a stricter decision.
    /// </remarks>
    private readonly ConcurrentDictionary<PortSlot, UdpSocketDecision> _udpPortOwners = new();
    private readonly ConcurrentDictionary<PortSlot, UdpFlow> _udpFlows = new();
    private readonly ConcurrentDictionary<ushort, IPAddress> _udpOrigins = new();
    private readonly ConcurrentDictionary<FlowKey, PendingConnection> _pendingTcp = new();
    private readonly ConcurrentDictionary<PortSlot, PendingBind> _pendingUdp = new();
    private readonly Lock _udpGate = new();

    /// <summary>
    /// UDP sockets whose BIND was seen (or whose owner was looked up), by family and port, with the
    /// socket that bound. Only a socket on this list has a known owner; a datagram from anything else is
    /// undecided, not DIRECT (SL-SEC-009). Bounded by the port space.
    /// </summary>
    private readonly ConcurrentDictionary<PortSlot, ulong> _udpSeen = new();

    /// <summary>Ports whose owner lookup failed, and when, so it is not repeated per datagram.</summary>
    private readonly ConcurrentDictionary<PortSlot, long> _udpUnknownOwner = new();
    private UdpRelay? _udpRelay;
    private UdpLanePool? _lanePool;

    private DivertHandle? _socketHandle;
    private DivertHandle? _networkHandle;
    private Thread? _socketThread;
    private Thread? _networkThread;
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
    private long _held;
    private long _released;
    private long _heldPacketsDropped;
    private long _refusedPacketsDropped;
    private long _undecidedDropped;
    private Timer? _heartbeat;
    private DivertHandle? _traceHandle;
    private Thread? _traceThread;

    /// <summary>
    /// Whether a redirected connection is moved to loopback, or to the machine's own address.
    /// </summary>
    /// <remarks>
    /// Loopback is the default and the shape verified on a live machine. The switch exists so the
    /// other shape can still be tried in one elevated session rather than one rebuild at a time.
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

    /// <summary>
    /// Where process images are verified. Without it a flow that depends on verification is refused,
    /// never guessed at.
    /// </summary>
    public ImageCatalog? Images { get; init; }

    /// <summary>Connections and sockets currently held for verification. Diagnostic.</summary>
    public int HeldCount => _pendingTcp.Count + _pendingUdp.Count;

    /// <summary>
    /// Finds the owner of a UDP port that produced no BIND event. The table lookup by default; tests
    /// supply their own.
    /// </summary>
    public Func<bool, ushort, UdpEndpointOwner?> UdpOwnerLookup { get; init; } = UdpEndpointOwners.Find;

    /// <summary>Packets dropped because no decision existed yet and one could have protected them.</summary>
    public long UndecidedDropped => Interlocked.Read(ref _undecidedDropped);

    /// <summary>
    /// Raised once, on the failing thread, when the socket pump or the packet loop can no longer do its
    /// job: it threw, or its handle has refused a thousand receives in a row.
    /// </summary>
    /// <remarks>
    /// Without this the engine stayed up and reported itself running while no decision was being made
    /// - every selected application quietly DIRECT, and a service manager with nothing to restart
    /// because the process was alive. The runtime restarts routing when it hears this.
    /// </remarks>
    public event Action<string>? Faulted;

    private int _faulted;

    private void Fault(string reason)
    {
        if (!_running || Interlocked.Exchange(ref _faulted, 1) != 0)
        {
            return;
        }

        SplitLaneLog.Error(LogCategory, $"routing has stopped working: {reason}");
        Faulted?.Invoke(reason);
    }

    /// <summary>Consecutive failed receives after which a divert thread counts as dead.</summary>
    private const int FailuresBeforeFault = 1000;

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
    /// Three clauses, and a fourth when UDP is relayed; each one earns its place:
    /// </para>
    /// <list type="number">
    /// <item>Outbound non-loopback TCP — the application's traffic, which may need redirecting.</item>
    /// <item>Outbound loopback TCP from the listener — the replies, which need restoring. Matching on
    /// the listener's own source port keeps the redirected traffic itself, whose source port is the
    /// application's, from being captured a second time and looping.</item>
    /// <item>Outbound non-loopback UDP — so a selected application's datagrams can be relayed through
    /// its lane, or dropped rather than allowed to escape. This is the expensive clause, and it is here
    /// because failing closed matters more than throughput (ADR W-0012).</item>
    /// <item>Outbound loopback UDP from the reserved lane block — the relayed replies.</item>
    /// <item>DNS: answers from port 53 in any direction, and queries to a loopback resolver. A
    /// query is what an answer is checked against (SL-SEC-003); queries to a remote resolver already
    /// arrive through the outbound clauses above.</item>
    /// </list>
    /// </remarks>
    internal static string NetworkFilter(ushort listenerPort, UdpLanePool? lanes = null)
    {
        var filter =
            $"(outbound and tcp and not loopback) or " +
            $"(outbound and tcp and loopback and tcp.SrcPort = {listenerPort}) or " +
            $"(outbound and udp and not loopback) or " +
            "(udp and udp.SrcPort = 53) or (tcp and tcp.SrcPort = 53) or " +
            "(outbound and loopback and udp and udp.DstPort = 53) or " +
            "(outbound and loopback and tcp and tcp.DstPort = 53)";

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

        // A socket event that waits in a shallow queue is a decision that arrives after its packet
        // (SL-SEC-009). The same depth as the network handle; a driver that refuses it leaves the
        // default, which is how this ran before, and says so.
        try
        {
            _socketHandle.SetParam(WinDivertParam.QueueLength, 8192);
            _socketHandle.SetParam(WinDivertParam.QueueTime, 2000);
        }
        catch (DivertException ex)
        {
            SplitLaneLog.Warning(LogCategory, $"the socket layer keeps its default queue: {ex.Message}");
        }

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

        // DNS responses transit the same packet queue. Learn before reinjecting the answer, so the
        // application cannot consume it and connect before a separate sniff thread has observed it.

        _running = true;

        if (Images is not null)
        {
            Images.Verified += OnImageVerified;
        }

        _socketThread = StartThread("SplitLane.SocketPump", () => SocketLoop(_socketHandle));
        _networkThread = StartThread("SplitLane.PacketLoop", () => NetworkLoop(_networkHandle));

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
                $"lanes {_udpRelay?.Count ?? 0}, " +
                $"held now {HeldCount}, held {Interlocked.Read(ref _held)}, " +
                $"released {Interlocked.Read(ref _released)}, " +
                $"held drops {Interlocked.Read(ref _heldPacketsDropped)}, " +
                $"refused drops {Interlocked.Read(ref _refusedPacketsDropped)}, " +
                $"undecided drops {Interlocked.Read(ref _undecidedDropped)}"),
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
                    if (++failures is 1 or 100 or FailuresBeforeFault)
                    {
                        SplitLaneLog.Error(
                            LogCategory,
                            $"socket layer receive failed (Win32 {error}), {failures} so far - no " +
                            "application identity is reaching the router, so everything is DIRECT");
                    }

                    if (failures == FailuresBeforeFault)
                    {
                        Fault($"the socket layer refused {FailuresBeforeFault} receives in a row (Win32 {error})");
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
            Fault($"the socket pump stopped: {ex.Message}");
        }
    }

    internal void HandleSocketEvent(in WinDivertAddress address)
    {
        var socket = address.Socket;

        // A socket bound to a loopback address never sends a packet the network handle routes (TCP
        // loopback is not diverted, loopback UDP only from the engine's own lanes). Its events are
        // ignored, so that they cannot touch the rows of a real connection on the same port number
        // (SL-SEC-005). The engine's own sockets are always tracked.
        if (socket.ProcessId != _selfProcessId && IPAddress.IsLoopback(SocketAddressReader.ReadLocal(address)))
        {
            return;
        }

        switch (address.Event)
        {
            case WinDivertEvent.SocketClose:
                if (socket.Protocol == PacketView.ProtocolTcp)
                {
                    var key = FlowKey.From(SocketAddressReader.ReadLocal(address), socket.LocalPort);
                    _nat.Close(key, socket.EndpointId);

                    if (_pendingTcp.TryGetValue(key, out var pending) && OwnedBy(pending.EndpointId, socket.EndpointId))
                    {
                        _pendingTcp.TryRemove(new KeyValuePair<FlowKey, PendingConnection>(key, pending));
                    }

                    return;
                }

                CloseUdp(new PortSlot(address.IPv6, socket.LocalPort), socket.EndpointId);
                return;

            case WinDivertEvent.SocketBind when socket.Protocol == PacketView.ProtocolUdp:
                TrackUdpBind(address);
                return;

            case WinDivertEvent.SocketConnect:
                HandleConnect(address);
                return;

            default:
                return;
        }
    }

    /// <summary>Whether a recorded owner is the closing socket. An owner of 0 is matched by any close.</summary>
    private static bool OwnedBy(ulong owner, ulong closing) => owner == 0 || owner == closing;

    /// <summary>The strictness of an answer, for deciding which of two sockets on one port stands.</summary>
    private static int Strictness(RouteAction action) => action switch
    {
        RouteAction.Block => 3,
        RouteAction.ProxyOnly => 2,
        RouteAction.Proxy => 1,
        _ => 0,
    };

    /// <summary>Forgets what a closing UDP socket owned, and nothing another socket owns.</summary>
    internal void CloseUdp(PortSlot slot, ulong endpointId)
    {
        lock (_udpGate)
        {
            if (_udpSeen.TryGetValue(slot, out var seen) && OwnedBy(seen, endpointId))
            {
                _udpSeen.TryRemove(new KeyValuePair<PortSlot, ulong>(slot, seen));
            }

            if (_pendingUdp.TryGetValue(slot, out var pending) && OwnedBy(pending.EndpointId, endpointId))
            {
                _pendingUdp.TryRemove(new KeyValuePair<PortSlot, PendingBind>(slot, pending));
            }

            if (_udpFlows.TryGetValue(slot, out var flow) && OwnedBy(flow.EndpointId, endpointId))
            {
                _udpFlows.TryRemove(new KeyValuePair<PortSlot, UdpFlow>(slot, flow));
            }

            if (_udpPortOwners.TryGetValue(slot, out var owner) && OwnedBy(owner.EndpointId, endpointId) &&
                _udpPortOwners.TryRemove(new KeyValuePair<PortSlot, UdpSocketDecision>(slot, owner)))
            {
                // The association at the proxy outlives the socket that needed it otherwise, and
                // each one holds a TCP connection open there. Lanes exist for IPv4 only.
                if (!slot.IPv6 || owner.DualStack)
                {
                    _udpRelay?.Forget(slot.Port);
                }
            }
        }
    }

    /// <summary>
    /// Whether a new bind from another socket may replace what is recorded for a slot: only when it
    /// is at least as strict, so a second socket on the same port can never relax a selected or
    /// refused application's answer (SL-SEC-005).
    /// </summary>
    private bool MayReplace(PortSlot slot, ulong endpointId, RouteAction incoming)
    {
        if (!_udpFlows.TryGetValue(slot, out var existing) || existing.EndpointId == 0 ||
            existing.EndpointId == endpointId)
        {
            return true;
        }

        var current = _udpPortOwners.TryGetValue(slot, out var owner) ? owner.Action : RouteAction.Direct;
        return Strictness(incoming) >= Strictness(current);
    }

    private void TrackUdpBind(in WinDivertAddress address)
    {
        var socket = address.Socket;
        var slot = new PortSlot(address.IPv6, socket.LocalPort);
        var dualStack = address.IPv6 && SocketAddressReader.ReadLocal(address).Equals(IPAddress.IPv6Any);

        // Seen, whoever owns it: from here on its datagrams are decided, not undecided.
        _udpSeen[slot] = socket.EndpointId;
        _udpUnknownOwner.TryRemove(slot, out _);

        DecideUdpSocket(slot, socket.ProcessId, socket.EndpointId, dualStack);
    }

    /// <summary>Decides a UDP socket from its owner, as its BIND event (or an owner lookup) reports it.</summary>
    private void DecideUdpSocket(PortSlot slot, uint processId, ulong endpointId, bool dualStack)
    {
        _udpSeen[slot] = endpointId;

        if (processId == _selfProcessId)
        {
            _udpFlows[slot] = new UdpFlow(
                new FlowDescriptor(processId, string.Empty, null, 0, FlowProtocol.Udp, IsEngineTraffic: true),
                endpointId,
                dualStack);
            return;
        }

        var info = _processes.ResolveInfo(processId);
        if (info.IsUnknown && _engine().Snapshot.DomainsCount == 0)
        {
            return;
        }

        var engine = _engine();

        // Only ports belonging to applications that would be proxied are remembered. Everything else
        // never needs a lookup, and a map of every UDP socket on the machine would be both larger and
        // a description of what the user is doing.
        var flow = new FlowDescriptor(
            processId, info.ExecutablePath, "203.0.113.1", 0, FlowProtocol.Udp,
            Image: EvidenceFor(info, engine));

        var decision = engine.Decide(flow);
        var held = decision.Reason == RouteReasonKind.IdentityPending && Images is not null && info.Image is not null;

        var recorded = RecordUdpDecision(
            slot,
            endpointId,
            dualStack,
            flow,
            held ? RouteAction.Block : decision.Action,
            held ? new PendingBind(flow, info.Image!, info.PackageFamilyName, endpointId, dualStack) : null);

        if (recorded && held)
        {
            Interlocked.Increment(ref _held);
            Images!.RequestVerification(info.Image!, decision.Needs);
        }
    }

    /// <summary>
    /// Records what was decided about a UDP socket when it bound - unless another socket on the same
    /// family and port already holds a stricter answer (SL-SEC-005).
    /// </summary>
    /// <returns>Whether this socket's answer was recorded.</returns>
    internal bool RecordUdpDecision(
        PortSlot slot, ulong endpointId, bool dualStack, FlowDescriptor flow, RouteAction action, PendingBind? pending)
    {
        lock (_udpGate)
        {
            if (!MayReplace(slot, endpointId, action))
            {
                return false;
            }

            _udpFlows[slot] = new UdpFlow(flow, endpointId, dualStack);
            _udpSeen[slot] = endpointId;

            if (pending is not null)
            {
                // Held: the datagrams are dropped until the image is verified, then the socket is
                // decided again. QUIC and DNS both retransmit.
                _udpPortOwners[slot] = new UdpSocketDecision(flow.ProcessId, RouteAction.Block, endpointId, dualStack);
                _pendingUdp[slot] = pending;
            }
            else if (action is RouteAction.Block or RouteAction.Proxy or RouteAction.ProxyOnly)
            {
                // Both answers are remembered, because they lead to different work: a refused
                // socket's datagrams are dropped where they are found, and a proxied socket's are
                // carried. What is not remembered is every other socket on the machine.
                _udpPortOwners[slot] = new UdpSocketDecision(flow.ProcessId, action, endpointId, dualStack);
            }
            else if (_udpPortOwners.TryGetValue(slot, out var owner) && OwnedBy(owner.EndpointId, endpointId))
            {
                // This socket's own earlier answer no longer applies.
                _udpPortOwners.TryRemove(new KeyValuePair<PortSlot, UdpSocketDecision>(slot, owner));
            }

            return true;
        }
    }

    /// <summary>
    /// The evidence a flow is decided on: what the catalog already has for the image, plus the package
    /// family from the token. Never waits for a verification.
    /// </summary>
    private ImageEvidence? EvidenceFor(in ProcessInfo info, RuleEngine engine) =>
        Images is not null && info.Image is not null
            ? Images.EvidenceFor(info.Image, info.PackageFamilyName, engine.Snapshot.NeedsProductName)
            : info.PackageFamilyName is null ? null : new ImageEvidence
            {
                ExecutablePath = info.ExecutablePath,
                PackageFamilyName = info.PackageFamilyName,
            };

    private void HandleConnect(in WinDivertAddress address)
    {
        var socket = address.Socket;

        if (socket.Protocol != PacketView.ProtocolTcp)
        {
            return;
        }

        var isSelf = socket.ProcessId == _selfProcessId;
        var remote = SocketAddressReader.ReadRemote(address);
        var local = SocketAddressReader.ReadLocal(address);

        // Loopback TCP is never diverted; a decision for it would only be a row that can collide.
        if (IPAddress.IsLoopback(remote))
        {
            return;
        }

        var info = isSelf ? default : _processes.ResolveInfo(socket.ProcessId);
        var path = info.ExecutablePath ?? string.Empty;
        var remoteText = remote.ToString();
        var hostname = _dns.Lookup(remote);
        var engine = _engine();

        var flow = new FlowDescriptor(
            socket.ProcessId,
            path,
            remoteText,
            socket.RemotePort,
            FlowProtocol.Tcp,
            hostname,
            isSelf,
            isSelf ? null : EvidenceFor(info, engine));

        var decision = engine.Decide(flow, out var rule);

        if (decision.Reason == RouteReasonKind.IdentityPending && Images is not null && info.Image is not null)
        {
            // Held, not decided. The SYN that follows is dropped until the image is verified; the
            // retransmission a second later meets whatever the answer turned out to be.
            var key = FlowKey.From(local, socket.LocalPort);
            _nat.RecordVerdict(key, remote, socket.RemotePort, NatVerdict.Pending, socket.EndpointId);
            _pendingTcp[key] = new PendingConnection(flow, local, remote, info.Image, info.PackageFamilyName, socket.EndpointId);
            Interlocked.Increment(ref _held);
            Images.RequestVerification(info.Image, decision.Needs);
            SplitLaneLog.Debug(
                LogCategory,
                $"HOLD {ExecutablePath.FileName(path)} :{socket.LocalPort} -> {flow.DestinationDisplay} ({decision.Explain()})");
            return;
        }

        RecordTcpDecision(socket.LocalPort, local, remote, flow, decision, rule, engine, socket.EndpointId);
    }

    /// <summary>Records what the packet loop must do with a connection's packets.</summary>
    internal void RecordTcpDecision(
        ushort localPort,
        IPAddress local,
        IPAddress remote,
        in FlowDescriptor flow,
        RouteDecision decision,
        AppRule? rule,
        RuleEngine engine,
        ulong endpointId = 0)
    {
        var key = FlowKey.From(local, localPort);

        switch (decision.Action)
        {
            case RouteAction.Proxy:
            case RouteAction.ProxyOnly:
                if (!_nat.Record(key, NatTable.EntryFor(
                        local, remote, flow.RemotePort, flow.ProcessId, flow.ExecutablePath, rule, flow.RemoteHostname,
                        DateTimeOffset.UtcNow) with
                    { Action = decision.Action, RuleKey = decision.RuleKey, EndpointId = endpointId }))
                {
                    // Another redirected connection holds this family and port. After the rewrite the
                    // two could not be told apart, so this one is refused rather than allowed to
                    // answer for the other - and never let out DIRECT.
                    _nat.RecordVerdict(key, remote, flow.RemotePort, NatVerdict.Block, endpointId);
                    _statistics.CountBlocked();
                    SplitLaneLog.Warning(
                        LogCategory,
                        $"refused {ExecutablePath.FileName(flow.ExecutablePath)} :{localPort} -> {flow.DestinationDisplay}: " +
                        "another redirected connection holds the same port");
                    break;
                }

                _statistics.CountProxied();
                SplitLaneLog.Debug(
                    LogCategory,
                    $"{decision.Action} pid={flow.ProcessId} {ExecutablePath.FileName(flow.ExecutablePath)} :{localPort} -> " +
                    $"{flow.DestinationDisplay} ip={remote} protocol=TCP rule={decision.RuleKey} " +
                    $"fallback=prohibited ({decision.Explain()})");
                break;

            case RouteAction.Block:
                // Dropped by the packet loop. This used to be recorded as "leave alone", which counted
                // a blocked TCP connection as blocked and then let it out.
                _nat.RecordVerdict(key, remote, flow.RemotePort, NatVerdict.Block, endpointId);
                _statistics.CountBlocked();
                SplitLaneLog.Debug(
                    LogCategory,
                    $"BLOCK {ExecutablePath.FileName(flow.ExecutablePath)} :{localPort} -> " +
                    $"{flow.DestinationDisplay} ({decision.Explain()})");
                break;

            default:
                // Recorded even though nothing is redirected. The packet loop reads the absence of a
                // decision as "not decided yet" and waits; without this every connection an
                // unselected application opens pays that wait in full, for an answer already given.
                _nat.RecordDirect(key, remote, flow.RemotePort, endpointId);
                _statistics.CountDirect();
                if (engine.Snapshot.LogsDirectFlows)
                {
                    SplitLaneLog.Debug(
                        LogCategory,
                        $"DIRECT {ExecutablePath.FileName(flow.ExecutablePath)} -> {flow.DestinationDisplay} ({decision.Explain()})");
                }

                break;
        }
    }

    /// <summary>
    /// Decides again everything that was held for an image, now that its evidence is complete.
    /// </summary>
    /// <remarks>
    /// Runs on a verification worker, concurrently with the socket pump and the packet loop. Every
    /// write is conditional on the held state still being there: a socket that closed, or a port that
    /// now belongs to another connection, is left to whatever owns it now.
    /// </remarks>
    private void OnImageVerified(ImageRecord record)
    {
        if (!_running || Images is not { } images)
        {
            return;
        }

        var engine = _engine();
        var released = 0;

        foreach (var (key, pending) in _pendingTcp)
        {
            if (!ReferenceEquals(pending.Image, record))
            {
                continue;
            }

            var flow = pending.Flow with
            {
                Image = images.EvidenceFor(record, pending.PackageFamily, engine.Snapshot.NeedsProductName),
            };

            var decision = engine.Decide(flow, out var rule);
            if (decision.Reason == RouteReasonKind.IdentityPending)
            {
                // Something else is still needed - a hash after the signature. Stay held.
                images.RequestVerification(record, decision.Needs);
                continue;
            }

            if (!_pendingTcp.TryRemove(new KeyValuePair<FlowKey, PendingConnection>(key, pending)) ||
                !_nat.TryResolvePending(key, pending.Remote, flow.RemotePort))
            {
                continue;
            }

            RecordTcpDecision(key.Port, pending.Local, pending.Remote, flow, decision, rule, engine, pending.EndpointId);
            released++;
        }

        foreach (var (slot, pending) in _pendingUdp)
        {
            if (!ReferenceEquals(pending.Image, record))
            {
                continue;
            }

            var flow = pending.Flow with
            {
                Image = images.EvidenceFor(record, pending.PackageFamily, engine.Snapshot.NeedsProductName),
            };

            var decision = engine.Decide(flow);
            if (decision.Reason == RouteReasonKind.IdentityPending)
            {
                images.RequestVerification(record, decision.Needs);
                continue;
            }

            lock (_udpGate)
            {
                // Still this socket's hold? A close, or another socket since, leaves it alone.
                if (!_pendingUdp.TryRemove(new KeyValuePair<PortSlot, PendingBind>(slot, pending)))
                {
                    continue;
                }

                _udpFlows[slot] = new UdpFlow(flow, pending.EndpointId, pending.DualStack);

                if (decision.Action is RouteAction.Block or RouteAction.Proxy or RouteAction.ProxyOnly)
                {
                    _udpPortOwners[slot] = new UdpSocketDecision(flow.ProcessId, decision.Action, pending.EndpointId, pending.DualStack);
                }
                else if (_udpPortOwners.TryGetValue(slot, out var owner) && owner.EndpointId == pending.EndpointId)
                {
                    _udpPortOwners.TryRemove(new KeyValuePair<PortSlot, UdpSocketDecision>(slot, owner));
                }
            }

            released++;
        }

        Interlocked.Add(ref _released, released);
        ReportVerification(record, engine, released);
    }

    /// <summary>
    /// Says, once per file version, what verification established and what it meant for routing.
    /// </summary>
    /// <remarks>
    /// The one log line an administrator needs when a selected application is not being routed: which
    /// file, who signed it, which rule it did or did not satisfy, and why.
    /// </remarks>
    internal static void ReportVerification(ImageRecord record, RuleEngine engine, int released)
    {
        var evidence = record.Evidence;
        var probe = new FlowDescriptor(0, record.Path, "203.0.113.1", 443, FlowProtocol.Tcp, Image: evidence);
        var decision = engine.Decide(probe, out var rule);
        var signer = evidence.Signature switch
        {
            SignatureStatus.Valid => $"signed by {evidence.SignerName}",
            SignatureStatus.Unsigned => "unsigned",
            SignatureStatus.Invalid => "signature does not verify",
            _ => "signature not checked",
        };

        var line =
            $"{record.Path}: {signer} ({record.VerificationTime.TotalMilliseconds:0} ms) -> " +
            $"{decision.Action} ({decision.Explain()})" +
            (rule is not null ? $", rule '{rule.Identity.DisplayName}'" : string.Empty) +
            (released > 0 ? $", released {released} held" : string.Empty);

        if (decision.Reason == RouteReasonKind.IdentityMismatch)
        {
            SplitLaneLog.Warning(IdentityLogCategory, line + " - select the application again if this is an update");
        }
        else
        {
            SplitLaneLog.Info(IdentityLogCategory, line);
        }
    }

    private const string IdentityLogCategory = "identity";

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

                    if (++failures is 1 or 100 or FailuresBeforeFault)
                    {
                        SplitLaneLog.Error(
                            LogCategory, $"packet receive failed (Win32 {error}), {failures} so far");
                    }

                    if (failures == FailuresBeforeFault)
                    {
                        Fault($"the packet layer refused {FailuresBeforeFault} receives in a row (Win32 {error})");
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
            Fault($"the packet loop stopped: {ex.Message}");
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
    private void WaitForDecision(FlowKey key, in PacketView view)
    {
        var deadline = Stopwatch.GetTimestamp() + (Stopwatch.Frequency * DecisionWaitMilliseconds / 1000);
        var spins = 0;

        while (Stopwatch.GetTimestamp() < deadline)
        {
            if (HasDecision(key, view))
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

    internal enum PacketAction
    {
        /// <summary>Reinject unchanged.</summary>
        Forward,

        /// <summary>Reinject after a rewrite, so the checksums have to be settled first.</summary>
        Rewritten,

        /// <summary>Do not reinject.</summary>
        Drop,
    }

    /// <summary>Decides what to do with one captured packet, rewriting it in place when needed.</summary>
    internal PacketAction Classify(Span<byte> packet, ref WinDivertAddress address)
    {
        if (!PacketView.TryParse(packet, out var view) || !view.HasPorts)
        {
            return PacketAction.Forward;
        }

        if (view.DestinationPort == 53 && address.Outbound)
        {
            ObserveDns(view, isQuery: true);

            // Loopback queries are captured only to be remembered; they were never routed here.
            if (address.Loopback)
            {
                return PacketAction.Forward;
            }
        }

        if (view.SourcePort == 53)
        {
            ObserveDns(view, isQuery: false);
            if (!address.Outbound || address.Loopback)
            {
                return PacketAction.Forward;
            }
        }

        if (view.Protocol == PacketView.ProtocolUdp)
        {
            return ClassifyUdp(packet, view, ref address);
        }

        var key = FlowKey.From(view.SourceAddress, view.SourcePort);

        if (_nat.IsClosedStrict(key, new IPAddress(view.DestinationAddress), view.DestinationPort))
        {
            Interlocked.Increment(ref _refusedPacketsDropped);
            return PacketAction.Drop;
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
        if (view.IsTcpSyn && !HasDecision(key, view))
        {
            WaitForDecision(key, view);

            // Still undecided: it may be a selected application. Dropped whenever anything could be
            // protected (SL-SEC-009) - the SYN is sent again, and meets its decision then.
            if (!HasDecision(key, view) && _engine().Snapshot.MayProtectTraffic)
            {
                Interlocked.Increment(ref _undecidedDropped);
                return PacketAction.Drop;
            }
        }

        // A connection held for verification, or refused, goes nowhere. Checked against the recorded
        // destination as well as the port, for the same reason HasDecision is: a stale row must not
        // answer for a different connection.
        if (_nat.TryGetVerdict(key, out var verdictDestination, out var verdictPort, out var verdict) &&
            verdict != NatVerdict.Direct &&
            verdictPort == view.DestinationPort &&
            AddressMatches(view.DestinationAddress, verdictDestination))
        {
            if (verdict == NatVerdict.Pending)
            {
                Interlocked.Increment(ref _heldPacketsDropped);
            }
            else
            {
                Interlocked.Increment(ref _refusedPacketsDropped);
            }

            return PacketAction.Drop;
        }

        // Application traffic that a socket-layer decision already marked for the proxy lane.
        if (_nat.TryGet(key, out var entry) &&
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
                // A proxy decision that arrived after its SYN got out. Leaving the connection to run
                // DIRECT used to be the answer for Proxy (only ProxyOnly was terminated); it is now
                // terminated for both (SL-SEC-009). The application retries, and the retry is
                // redirected. Undecided SYNs are no longer let out while anything could be protected,
                // so this is reached only when a rule appeared mid-connection.
                if (Interlocked.Increment(ref _lateDecisions) is 1 or 50)
                {
                    SplitLaneLog.Warning(
                        LogCategory,
                        $"connection from port {view.SourcePort} was established before its routing " +
                        "decision was recorded; it is refused rather than left DIRECT");
                }

                Interlocked.Increment(ref _refusedPacketsDropped);
                return PacketAction.Drop;
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

        var snapshot = _engine().Snapshot;
        if (snapshot.DomainsCount > 0 &&
            !(_nat.TryGetVerdict(key, out var directAddress, out var directPort, out var directVerdict) &&
              directVerdict == NatVerdict.Direct && directPort == view.DestinationPort &&
              AddressMatches(view.DestinationAddress, directAddress)))
        {
            // CLOSE and final kernel packets travel on separate queues. A tombstone narrows the
            // race but cannot cover packets that arrive before CLOSE itself. Lost attribution of
            // a known strict destination must therefore refuse, not fall back to reinjection.
            var destination = new IPAddress(view.DestinationAddress);
            var unknown = new FlowDescriptor(0, string.Empty, destination.ToString(),
                view.DestinationPort, FlowProtocol.Tcp, _dns.Lookup(destination));
            if (snapshot.HasStrictDomainCandidate(unknown))
            {
                Interlocked.Increment(ref _refusedPacketsDropped);
                return PacketAction.Drop;
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

        var engine = _engine();
        IPAddress? destination = null;
        RouteDecision resolved = RouteDecision.DirectDefault;
        var slot = new PortSlot(view.IsIPv6, view.SourcePort);

        // A socket nobody has decided about yet - its BIND still in the socket queue, or opened before
        // the engine started - is undecided, not DIRECT (SL-SEC-009).
        if (!IsUdpSeen(slot) && !TryDecideUnseenUdp(slot, engine))
        {
            if (engine.Snapshot.MayProtectTraffic)
            {
                Interlocked.Increment(ref _undecidedDropped);
                return PacketAction.Drop;
            }

            return PacketAction.Forward;
        }

        var hasOwner = TryGetUdpOwner(slot, out var selected);
        var action = hasOwner ? selected.Action : RouteAction.Direct;
        if (engine.Snapshot.DomainsCount > 0)
        {
            destination = new IPAddress(view.DestinationAddress);
            if (!TryGetUdpFlow(slot, out var basis))
            {
                // BIND may race the first datagram, but that must not block unrelated traffic
                // (especially DNS itself). Hold only destinations with a candidate domain rule.
                var unattributed = new FlowDescriptor(0, string.Empty, destination.ToString(),
                    view.DestinationPort, FlowProtocol.Udp, _dns.Lookup(destination));
                if (engine.Snapshot.HasDomainCandidate(unattributed))
                {
                    return PacketAction.Drop;
                }

                return action == RouteAction.Direct ? PacketAction.Forward : PacketAction.Drop;
            }
            resolved = engine.Decide(basis with
            {
                ExecutablePath = basis.ExecutablePath ?? string.Empty,
                RemoteAddress = destination.ToString(),
                RemotePort = view.DestinationPort,
                RemoteHostname = _dns.Lookup(destination),
                Protocol = FlowProtocol.Udp,
            });
            action = resolved.Action;
        }
        // Existing identity holds/mismatches retain their refusal until verification completes.
        if (hasOwner && selected.Action == RouteAction.Block &&
            resolved.Reason != RouteReasonKind.DomainRule)
        {
            action = RouteAction.Block;
        }
        if (action == RouteAction.Direct)
        {
            return PacketAction.Forward;
        }

        // A selected application's datagram never leaves this machine as it is. Either it goes
        // through the proxy or it goes nowhere; forwarding it would be the silent bypass the design
        // exists to prevent.
        if (action is RouteAction.Proxy or RouteAction.ProxyOnly && _udpRelay is not null && view.IsIPv4)
        {
            destination ??= new IPAddress(view.DestinationAddress);
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

    private bool IsUdpSeen(PortSlot slot) =>
        _udpSeen.ContainsKey(slot) ||
        (!slot.IPv6 && _udpFlows.TryGetValue(slot with { IPv6 = true }, out var wildcard) && wildcard.DualStack);

    /// <summary>
    /// Gives an unseen UDP socket a decision: first by waiting briefly for its BIND, then by asking the
    /// IP Helper table who owns the port and deciding as a BIND would have.
    /// </summary>
    /// <returns>Whether the socket now has a known owner and a recorded decision.</returns>
    private bool TryDecideUnseenUdp(PortSlot slot, RuleEngine engine)
    {
        if (!engine.Snapshot.MayProtectTraffic && engine.Snapshot.DomainsCount == 0)
        {
            // Nothing could be decided anything but DIRECT; no lookup is worth its cost.
            return false;
        }

        WaitForUdpBind(slot);
        if (IsUdpSeen(slot))
        {
            return true;
        }

        var now = Stopwatch.GetTimestamp();
        if (_udpUnknownOwner.TryGetValue(slot, out var failedAt) && now - failedAt < UnknownOwnerLifetimeTicks)
        {
            return false;
        }

        UdpEndpointOwner? owner;
        try
        {
            owner = UdpOwnerLookup(slot.IPv6, slot.Port);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or SEHException)
        {
            owner = null;
        }

        if (owner is not { } found)
        {
            _udpUnknownOwner[slot] = now;
            return false;
        }

        DecideUdpSocket(found.DualStack ? slot with { IPv6 = true } : slot, found.ProcessId, endpointId: 0, found.DualStack);
        return IsUdpSeen(slot);
    }

    /// <summary>Waits briefly for a UDP socket's BIND to be recorded.</summary>
    private void WaitForUdpBind(PortSlot slot)
    {
        var deadline = Stopwatch.GetTimestamp() + (Stopwatch.Frequency * DecisionWaitMilliseconds / 1000);
        var spins = 0;

        while (Stopwatch.GetTimestamp() < deadline)
        {
            if (IsUdpSeen(slot))
            {
                Interlocked.Increment(ref _decisionsWaitedFor);
                return;
            }

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

    /// <summary>
    /// The decision for a UDP socket by family and port. An IPv4 datagram can also come from a
    /// dual-stack socket bound to the IPv6 wildcard, which the socket layer reported as IPv6.
    /// </summary>
    private bool TryGetUdpOwner(PortSlot slot, out UdpSocketDecision owner) =>
        _udpPortOwners.TryGetValue(slot, out owner) ||
        (!slot.IPv6 && _udpPortOwners.TryGetValue(slot with { IPv6 = true }, out owner) && owner.DualStack);

    private bool TryGetUdpFlow(PortSlot slot, out FlowDescriptor flow)
    {
        if (_udpFlows.TryGetValue(slot, out var found) ||
            (!slot.IPv6 && _udpFlows.TryGetValue(slot with { IPv6 = true }, out found) && found.DualStack))
        {
            flow = found.Flow;
            return true;
        }

        flow = default!;
        return false;
    }

    private PacketAction RestoreReply(Span<byte> packet, in PacketView view, ref WinDivertAddress address)
    {
        if (!_nat.TryGetRedirected(new PortSlot(view.IsIPv6, view.DestinationPort), out var entry))
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
    private bool HasDecision(FlowKey key, in PacketView view)
    {
        if (_nat.TryGet(key, out var entry) &&
            entry.OriginalDestinationPort == view.DestinationPort &&
            AddressMatches(view.DestinationAddress, entry.OriginalDestination))
        {
            return true;
        }

        return _nat.TryGetDirect(key, out var destination, out var port) &&
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

    /// <summary>
    /// Hands a DNS message to the observer with the endpoints it travelled between, which is what an
    /// answer is matched against (SL-SEC-003). A packet's claim to be DNS is not evidence on its own.
    /// </summary>
    private void ObserveDns(in PacketView view, bool isQuery)
    {
        var bytes = view.Bytes;
        var headerLength = view.Protocol == PacketView.ProtocolUdp ? 8 : (bytes[view.TransportOffset + 12] >> 4) * 4;
        if (headerLength < (view.Protocol == PacketView.ProtocolUdp ? 8 : 20) ||
            view.TransportOffset + headerLength >= bytes.Length)
        {
            return;
        }

        var source = new IPEndPoint(new IPAddress(view.SourceAddress), view.SourcePort);
        var destination = new IPEndPoint(new IPAddress(view.DestinationAddress), view.DestinationPort);
        var payload = bytes[(view.TransportOffset + headerLength)..];

        if (view.Protocol == PacketView.ProtocolUdp)
        {
            Observe(DnsTransport.Udp, payload);
            return;
        }

        // TCP DNS has a two-byte length prefix. Partial frames are not interpreted as evidence.
        while (payload.Length >= 2)
        {
            var length = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(payload);
            if (length == 0 || length > payload.Length - 2)
            {
                return;
            }

            Observe(DnsTransport.Tcp, payload.Slice(2, length));
            payload = payload[(2 + length)..];
        }

        void Observe(DnsTransport transport, ReadOnlySpan<byte> message)
        {
            if (isQuery)
            {
                _dns.ObserveQuery(transport, source, destination, message);
            }
            else
            {
                _dns.IngestResponse(transport, source, destination, message);
            }
        }
    }

    // ---- Shutdown ---------------------------------------------------------------------------

    /// <summary>Stops the threads and closes the handles.</summary>
    public async ValueTask DisposeAsync()
    {
        if (!_running && _socketHandle is null && _networkHandle is null)
        {
            return;
        }

        _running = false;

        if (Images is not null)
        {
            Images.Verified -= OnImageVerified;
        }

        // Shutdown before close: a thread parked inside WinDivertRecv must be released first, and
        // closing the handle underneath it is not defined behaviour.
        _heartbeat?.Dispose();
        _heartbeat = null;

        ShutDownHandle(_socketHandle, "socket");
        ShutDownHandle(_networkHandle, "network");
        ShutDownHandle(_traceHandle, "trace");

        await Task.WhenAll(
            JoinAsync(_socketThread),
            JoinAsync(_networkThread),
            JoinAsync(_traceThread)).ConfigureAwait(false);

        _socketHandle?.Dispose();
        _networkHandle?.Dispose();
        _traceHandle?.Dispose();

        _socketHandle = null;
        _networkHandle = null;
        _traceHandle = null;
        _socketThread = null;
        _networkThread = null;
        _traceThread = null;

        _udpPortOwners.Clear();
        _udpFlows.Clear();
        _udpSeen.Clear();
        _udpUnknownOwner.Clear();
        _udpOrigins.Clear();
        _pendingTcp.Clear();
        _pendingUdp.Clear();
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
