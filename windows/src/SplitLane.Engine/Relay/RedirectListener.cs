using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using SplitLane.Core.Logging;
using SplitLane.Core.Models;
using SplitLane.Core.Proxy.Socks5;
using SplitLane.Core.Rules;
using SplitLane.Engine.Flows;
using SplitLane.Engine.Runtime;

namespace SplitLane.Engine.Relay;

/// <summary>
/// The loopback endpoint every redirected connection lands on.
/// </summary>
/// <remarks>
/// <para>
/// The divert layer rewrites a selected application's SYN so that it arrives here instead of at its
/// real destination. This listener then answers the only question the rewrite destroyed — where was
/// it going? — by looking the connection's source port up in the NAT table, and relays it through
/// SOCKS5.
/// </para>
/// <para>
/// A connection whose source port is not in the table is <b>closed immediately</b>. That is not
/// defensive tidiness: the listener is a real TCP port on loopback that any local process can
/// connect to, and without this check it would be an open proxy that forwards anywhere the caller
/// names. Refusing unknown sources is what keeps it a private implementation detail rather than a
/// service.
/// </para>
/// </remarks>
public sealed class RedirectListener : IAsyncDisposable
{
    private readonly NatTable _nat;
    private readonly EngineStatistics _statistics;
    private readonly Func<ProxyConfiguration> _proxy;
    private readonly Func<Socks5Credential?> _credential;
    private readonly CancellationTokenSource _stopping = new();
    private readonly List<Socket> _listeners = [];
    private readonly List<Task> _acceptLoops = [];

    /// <summary>Builds a listener over the shared NAT table.</summary>
    public RedirectListener(
        NatTable nat,
        EngineStatistics statistics,
        Func<ProxyConfiguration> proxy,
        Func<Socks5Credential?> credential)
    {
        _nat = nat ?? throw new ArgumentNullException(nameof(nat));
        _statistics = statistics ?? throw new ArgumentNullException(nameof(statistics));
        _proxy = proxy ?? throw new ArgumentNullException(nameof(proxy));
        _credential = credential ?? throw new ArgumentNullException(nameof(credential));
    }

    private const string LogCategory = "redirect";

    /// <summary>The port the listener actually bound.</summary>
    public ushort Port { get; private set; }

    /// <summary>
    /// Whether to accept on every local address rather than loopback alone.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Needed only by the non-loopback redirect shape, where a redirected packet is addressed to the
    /// machine's own interface address. A listener bound to loopback would never see it.
    /// </para>
    /// <para>
    /// This does weaken W-5: the port becomes reachable from the local network rather than from this
    /// machine only. What still protects it is the check that matters — a connection whose source
    /// port has no NAT entry is closed immediately, and entries are only created for connections
    /// SplitLane itself decided to proxy. An uninvited caller, local or remote, gets nothing. The
    /// exposure is a port that accepts and instantly closes, not an open proxy.
    /// </para>
    /// </remarks>
    public bool AcceptOnAllAddresses { get; init; }

    /// <summary>Whether the accept loops are running.</summary>
    public bool IsRunning => _acceptLoops.Count > 0 && _acceptLoops.Exists(task => !task.IsCompleted);

    /// <summary>
    /// Binds and starts accepting.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Bound to loopback only, never to the wildcard address. A redirect listener reachable from the
    /// network would let a remote host make the engine dial arbitrary destinations through the user's
    /// proxy, which is a different product and a much worse one.
    /// </para>
    /// <para>
    /// That constraint is why there are two sockets rather than one dual-stack socket. A dual-stack
    /// listener has to be bound to <c>::</c>, the IPv6 <i>wildcard</i> — binding <c>::1</c> with
    /// <c>IPv6Only</c> off does not accept IPv4, it just listens on IPv6 loopback. Two explicitly
    /// loopback-bound sockets sharing one port number keep both families working without ever
    /// listening off-machine.
    /// </para>
    /// </remarks>
    public ushort Start(ushort requestedPort)
    {
        if (_listeners.Count > 0)
        {
            return Port;
        }

        // The IPv6 socket binds first because it is the one allowed to choose an ephemeral port; the
        // IPv4 socket must then take the same number so a single divert filter names one port.
        const int attempts = 8;
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                BindPair(requestedPort);
                break;
            }
            catch (SocketException ex) when (
                ex.SocketErrorCode == SocketError.AddressAlreadyInUse && requestedPort == 0 && attempt < attempts)
            {
                // Another process took the IPv4 side of the ephemeral port between the two binds.
                // Retrying picks a different number; it is a race, not a failure.
                CloseListeners();
            }
        }

        foreach (var listener in _listeners)
        {
            var socket = listener;
            _acceptLoops.Add(Task.Run(() => AcceptLoopAsync(socket, _stopping.Token)));
        }

        SplitLaneLog.Info(
            LogCategory,
            $"redirect listener bound to {(AcceptOnAllAddresses ? "all local addresses" : "loopback")} port {Port}");
        return Port;
    }

    private void BindPair(ushort requestedPort)
    {
        var v6Address = AcceptOnAllAddresses ? IPAddress.IPv6Any : IPAddress.IPv6Loopback;
        var v4Address = AcceptOnAllAddresses ? IPAddress.Any : IPAddress.Loopback;

        var v6 = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
        v6.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, true);
        v6.Bind(new IPEndPoint(v6Address, requestedPort));
        v6.Listen(512);
        _listeners.Add(v6);

        Port = (ushort)((IPEndPoint)v6.LocalEndPoint!).Port;

        var v4 = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        v4.Bind(new IPEndPoint(v4Address, Port));
        v4.Listen(512);
        _listeners.Add(v4);
    }

    private void CloseListeners()
    {
        foreach (var listener in _listeners)
        {
            listener.Dispose();
        }

        _listeners.Clear();
        Port = 0;
    }

    private async Task AcceptLoopAsync(Socket listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            Socket client;
            try
            {
                client = await listener.AcceptAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException ex)
            {
                SplitLaneLog.Warning(LogCategory, $"accept failed: {ex.SocketErrorCode}");
                continue;
            }

            // Each connection runs detached. One slow SOCKS5 handshake must not delay the next
            // application's connection.
            _ = Task.Run(() => HandleAsync(client, cancellationToken), CancellationToken.None);
        }
    }

    private async Task HandleAsync(Socket client, CancellationToken cancellationToken)
    {
        var started = Stopwatch.GetTimestamp();
        ConnectionEvent? record = null;

        try
        {
            client.NoDelay = true;

            if (client.RemoteEndPoint is not IPEndPoint remote)
            {
                client.Dispose();
                return;
            }

            var sourcePort = (ushort)remote.Port;

            if (!_nat.TryGet(sourcePort, out var entry))
            {
                // Not a connection SplitLane redirected. See the type-level remarks: this is the
                // check that stops the listener being an open proxy.
                SplitLaneLog.Debug(LogCategory, $"refused unrecognised local connection from port {sourcePort}");
                client.Dispose();
                return;
            }

            var proxy = _proxy();

            record = new ConnectionEvent
            {
                ExecutablePath = entry.ExecutablePath,
                ApplicationName = entry.ApplicationName,
                ProcessId = entry.ProcessId,
                DestinationHost = entry.Hostname ?? entry.OriginalDestination.ToString(),
                DestinationPort = entry.OriginalDestinationPort,
                Protocol = FlowProtocol.Tcp,
                Route = RouteAction.Proxy,
                State = ConnectionState.Connecting,
            };

            _statistics.Record(record);
            _statistics.MarkLive(record.Id);

            var destination = proxy.PreferHostnames
                ? Socks5Address.Destination(entry.Hostname, entry.OriginalDestination.ToString())
                : Socks5Address.Destination(null, entry.OriginalDestination.ToString());

            using var tunnel = await Socks5Client
                .ConnectAsync(proxy, destination, entry.OriginalDestinationPort, _credential(), cancellationToken)
                .ConfigureAwait(false);

            record = record with { State = ConnectionState.Active };
            _statistics.Update(record);

            SplitLaneLog.Debug(
                LogCategory,
                $"relaying {ExecutablePath.FileName(entry.ExecutablePath)} -> {destination}:{entry.OriginalDestinationPort} " +
                $"via {proxy.Endpoint.DisplayString} ({tunnel.ElapsedMilliseconds:F0}ms handshake)");

            var result = await TcpRelay
                .RunAsync(client, tunnel.Socket, tunnel.Info.LeftoverBytes, cancellationToken)
                .ConfigureAwait(false);

            _statistics.AddTransferred(result.BytesSent, result.BytesReceived);

            record = record with
            {
                State = ConnectionState.Closed,
                BytesSent = result.BytesSent,
                BytesReceived = result.BytesReceived,
                Duration = Stopwatch.GetElapsedTime(started),
            };
            _statistics.Update(record);
        }
        catch (Socks5Exception ex)
        {
            // Fail closed. The application's connection dies and the failure is visible, which is
            // the entire point: a silent fallback to DIRECT is a leak the user cannot see (ADR 0003).
            SplitLaneLog.Warning(LogCategory, $"proxy handshake failed: {ex}");

            if (record is not null)
            {
                _statistics.Update(record with
                {
                    State = ConnectionState.Failed,
                    Error = ex.Code.ToCategory(),
                    Duration = Stopwatch.GetElapsedTime(started),
                });
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            SplitLaneLog.Error(LogCategory, "relay failed", ex);

            if (record is not null)
            {
                _statistics.Update(record with
                {
                    State = ConnectionState.Failed,
                    Error = ConnectionErrorCategory.InternalError,
                    Duration = Stopwatch.GetElapsedTime(started),
                });
            }
        }
        finally
        {
            if (record is not null)
            {
                _statistics.MarkFinished(record.Id);
            }

            client.Dispose();
        }
    }

    /// <summary>Stops accepting and waits for the loops to finish.</summary>
    public async ValueTask DisposeAsync()
    {
        await _stopping.CancelAsync().ConfigureAwait(false);

        CloseListeners();

        try
        {
            await Task.WhenAll(_acceptLoops).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }

        _acceptLoops.Clear();
        _stopping.Dispose();
    }
}
