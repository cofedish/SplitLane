using System.Collections.Concurrent;
using System.Net;
using SplitLane.Core.Logging;
using SplitLane.Core.Models;
using SplitLane.Core.Proxy.Socks5;

namespace SplitLane.Engine.Relay;

/// <summary>
/// Carries selected applications' datagrams through the proxy, over loopback.
/// </summary>
/// <remarks>
/// <para>
/// A selected application's datagram is redirected to a loopback socket - a lane - instead of leaving
/// the machine. The lane relays it through a SOCKS5 UDP association and sends the answer back the
/// same way. The packet layer rewrites the addresses at both ends, so the application talks to what
/// it believes is the remote host throughout.
/// </para>
/// <para>
/// One association per application socket, because that is what the proxy charges for: a TCP control
/// channel held open. One lane per remote endpoint within it, because the port a reply arrives on is
/// the only thing the packet layer can use to know which remote to attribute it to.
/// </para>
/// <para>
/// A datagram that cannot be relayed is dropped, never sent unproxied. That is the promise this
/// exists to keep: an application the user selected does not quietly talk to the internet from their
/// own address.
/// </para>
/// </remarks>
public sealed class UdpRelay : IAsyncDisposable
{
    private const string LogCategory = "udp";

    /// <summary>How long a lane survives with nothing passing through it.</summary>
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(2);

    private readonly ConcurrentDictionary<(ushort Port, IPEndPoint Remote), UdpLane> _lanes = new();
    private readonly ConcurrentDictionary<ushort, UdpLane> _byLanePort = new();
    private readonly ConcurrentDictionary<ushort, Lazy<Task<UdpAssociation>>> _associations = new();
    private readonly CancellationTokenSource _stopping = new();
    private readonly UdpLanePool _pool;
    private readonly Func<ProxyConfiguration> _proxy;
    private readonly Func<Socks5Credential?> _credential;
    private readonly Timer _sweeper;

    private long _sent;
    private long _received;
    private long _refused;

    /// <summary>Builds a relay.</summary>
    /// <param name="pool">The block of loopback ports the divert filter names.</param>
    /// <param name="proxy">Reads the upstream freshly, because configuration changes underneath.</param>
    /// <param name="credential">Reads the credential the same way.</param>
    public UdpRelay(UdpLanePool pool, Func<ProxyConfiguration> proxy, Func<Socks5Credential?> credential)
    {
        _pool = pool ?? throw new ArgumentNullException(nameof(pool));
        _proxy = proxy ?? throw new ArgumentNullException(nameof(proxy));
        _credential = credential ?? throw new ArgumentNullException(nameof(credential));
        _sweeper = new Timer(_ => Sweep(), null, IdleTimeout, IdleTimeout);
    }

    /// <summary>Datagrams handed to the proxy.</summary>
    public long Sent => Interlocked.Read(ref _sent);

    /// <summary>Datagrams that came back.</summary>
    public long Received => Interlocked.Read(ref _received);

    /// <summary>Datagrams dropped because they could not be relayed.</summary>
    public long Refused => Interlocked.Read(ref _refused);

    /// <summary>Lanes currently open.</summary>
    public int Count => _lanes.Count;

    /// <summary>
    /// The loopback port an application's datagram to this destination should be sent to.
    /// </summary>
    /// <remarks>
    /// Synchronous and immediate: a lane is a socket, and opening one costs nothing worth deferring.
    /// The association behind it is opened in the background on first use, and datagrams wait in the
    /// lane's own receive buffer until it is ready - so unlike a design that waited, the first
    /// datagram of a conversation is not lost.
    /// </remarks>
    public ushort? LaneFor(ushort applicationPort, IPAddress destination, ushort destinationPort)
    {
        if (_stopping.IsCancellationRequested)
        {
            return null;
        }

        var remote = new IPEndPoint(destination, destinationPort);

        if (_lanes.TryGetValue((applicationPort, remote), out var existing))
        {
            existing.LastUsed = DateTimeOffset.UtcNow;
            return existing.Port;
        }

        var reserved = _pool.TryAcquire();

        if (reserved is null)
        {
            // The block is full. Refused, which means dropped - never forwarded unproxied.
            Interlocked.Increment(ref _refused);
            return null;
        }

        var lane = new UdpLane(reserved.Value.Socket, reserved.Value.Port, applicationPort, remote);

        if (!_lanes.TryAdd((applicationPort, remote), lane))
        {
            _pool.Release(lane.Port);
            return _lanes.TryGetValue((applicationPort, remote), out var raced) ? raced.Port : null;
        }

        _byLanePort[lane.Port] = lane;
        _ = Task.Run(() => PumpAsync(lane, _stopping.Token));

        return lane.Port;
    }

    /// <summary>The lane a loopback reply is coming from, when it is one of ours.</summary>
    public bool TryResolveLane(ushort lanePort, out ushort applicationPort, out IPEndPoint remote)
    {
        if (_byLanePort.TryGetValue(lanePort, out var lane))
        {
            applicationPort = lane.ApplicationPort;
            remote = lane.Remote;
            return true;
        }

        applicationPort = 0;
        remote = new IPEndPoint(IPAddress.Any, 0);
        return false;
    }

    /// <summary>Forgets an application socket that has closed, and every lane it owned.</summary>
    public void Forget(ushort applicationPort)
    {
        foreach (var (key, lane) in _lanes)
        {
            if (key.Port != applicationPort)
            {
                continue;
            }

            if (_lanes.TryRemove(key, out _))
            {
                _byLanePort.TryRemove(lane.Port, out _);
                _pool.Release(lane.Port);
            }
        }

        if (_associations.TryRemove(applicationPort, out var association))
        {
            _ = CloseAsync(association);
        }
    }

    /// <summary>
    /// Carries one lane's datagrams to the proxy and its answers back.
    /// </summary>
    /// <remarks>
    /// The association is asked for on the first datagram rather than when the lane opens, so an
    /// application that binds a socket and never sends costs nothing at the proxy.
    /// </remarks>
    private async Task PumpAsync(UdpLane lane, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            byte[] payload;

            try
            {
                var result = await lane.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                payload = result.Buffer;
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
            {
                return;
            }
            catch (System.Net.Sockets.SocketException)
            {
                continue;
            }

            UdpAssociation association;

            try
            {
                association = await AssociationFor(lane.ApplicationPort).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is Socks5Exception or System.Net.Sockets.SocketException
                                           or OperationCanceledException or IOException)
            {
                // Said once per socket rather than once per datagram: a proxy that refuses UDP
                // refuses all of them, and a log repeating itself for each would bury everything.
                Interlocked.Increment(ref _refused);
                _associations.TryRemove(lane.ApplicationPort, out _);

                SplitLaneLog.Warning(
                    LogCategory,
                    $"the proxy would not relay datagrams for :{lane.ApplicationPort} " +
                    $"({ex.Message}); they are dropped rather than sent unproxied");

                continue;
            }

            try
            {
                lane.LastUsed = DateTimeOffset.UtcNow;
                Interlocked.Increment(ref _sent);

                await association
                    .SendAsync(lane.Remote.Address, (ushort)lane.Remote.Port, payload)
                    .ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is System.Net.Sockets.SocketException or ObjectDisposedException)
            {
                SplitLaneLog.Debug(LogCategory, $"association for :{lane.ApplicationPort} failed: {ex.Message}");
                _associations.TryRemove(lane.ApplicationPort, out _);
            }
        }
    }

    private Task<UdpAssociation> AssociationFor(ushort applicationPort)
    {
        var lazy = _associations.GetOrAdd(applicationPort, port => new Lazy<Task<UdpAssociation>>(
            () => OpenAsync(port), LazyThreadSafetyMode.ExecutionAndPublication));

        return lazy.Value;
    }

    private async Task<UdpAssociation> OpenAsync(ushort applicationPort)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_stopping.Token);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));

        var association = await UdpAssociation.OpenAsync(
            _proxy(),
            _credential(),
            datagram => Deliver(applicationPort, datagram),
            timeout.Token).ConfigureAwait(false);

        SplitLaneLog.Debug(LogCategory, $"association opened for :{applicationPort}");
        return association;
    }

    /// <summary>Routes an answer back to the lane that asked for it.</summary>
    private void Deliver(ushort applicationPort, RelayedDatagram datagram)
    {
        var remote = new IPEndPoint(datagram.RemoteAddress, datagram.RemotePort);

        if (!_lanes.TryGetValue((applicationPort, remote), out var lane))
        {
            // An answer from somewhere the application never wrote to. Dropped: there is no lane to
            // attribute it to, so there is no address the packet layer could give it.
            Interlocked.Increment(ref _refused);
            return;
        }

        Interlocked.Increment(ref _received);
        _ = lane.SendToApplicationAsync(datagram.Payload);
    }

    private void Sweep()
    {
        var cutoff = DateTimeOffset.UtcNow - IdleTimeout;

        foreach (var (key, lane) in _lanes)
        {
            if (lane.LastUsed >= cutoff || !_lanes.TryRemove(key, out _))
            {
                continue;
            }

            _byLanePort.TryRemove(lane.Port, out _);
            _pool.Release(lane.Port);

            // The association goes when its last lane does; it holds a connection at the proxy.
            if (!_lanes.Keys.Any(k => k.Port == key.Port) &&
                _associations.TryRemove(key.Port, out var association))
            {
                _ = CloseAsync(association);
            }
        }
    }

    private static async Task CloseAsync(Lazy<Task<UdpAssociation>> association)
    {
        try
        {
            await (await association.Value.ConfigureAwait(false)).DisposeAsync().ConfigureAwait(false);
        }
        catch (Exception)
        {
            // It never opened, which is its own kind of closed.
        }
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await _stopping.CancelAsync().ConfigureAwait(false);
        await _sweeper.DisposeAsync().ConfigureAwait(false);

        foreach (var (key, lane) in _lanes)
        {
            _lanes.TryRemove(key, out _);
            _byLanePort.TryRemove(lane.Port, out _);
            _pool.Release(lane.Port);
        }

        foreach (var (port, association) in _associations)
        {
            _associations.TryRemove(port, out _);
            await CloseAsync(association).ConfigureAwait(false);
        }

        _stopping.Dispose();
    }
}
