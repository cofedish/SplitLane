using System.Net;
using System.Net.Sockets;

namespace SplitLane.Engine.Relay;

/// <summary>
/// One loopback socket standing in for one remote endpoint, for one application socket.
/// </summary>
/// <remarks>
/// <para>
/// The application's datagrams are redirected to this socket instead of leaving the machine, and its
/// replies are sent back from here. The packet layer rewrites the addresses at both ends, so the
/// application talks to what it believes is the remote host and never learns that it is talking to
/// loopback.
/// </para>
/// <para>
/// This is the shape the TCP side already uses, and it is used here for a reason that took a
/// measurement to find. The obvious alternative - relaying in the engine and injecting the reply as
/// if it had arrived from the remote host - produces a perfectly formed packet that WinDivert
/// accepts and the machine then discards: the outbound datagram never left, so Windows Firewall has
/// no state for the conversation, and an unsolicited inbound datagram to an ephemeral port is
/// exactly what it exists to drop. Nothing reports this. The counters said sent, returned and
/// injected, with no failures, and the application sat waiting.
/// </para>
/// <para>
/// One lane per remote endpoint, not per application socket. The port a reply arrives on is the only
/// thing the packet layer can use to know which remote to attribute it to, so a socket talking to
/// three hosts needs three lanes.
/// </para>
/// <para>
/// The socket comes from a block reserved before the divert filter was built, so the filter names
/// that block and nothing else. Capturing every loopback datagram on the machine instead - which is
/// what an unreserved port forced - pulled ten thousand packets a second into user mode and broke
/// the tunnel this machine's DNS runs through.
/// </para>
/// </remarks>
public sealed class UdpLane : IDisposable
{
    private readonly UdpClient _socket;

    /// <summary>Takes a lane from the reserved block.</summary>
    /// <param name="socket">A socket from the pool, already bound.</param>
    /// <param name="port">The port it is bound to.</param>
    /// <param name="applicationPort">The application socket this stands in for.</param>
    /// <param name="remote">The remote endpoint it is talking to.</param>
    public UdpLane(UdpClient socket, ushort port, ushort applicationPort, IPEndPoint remote)
    {
        ArgumentNullException.ThrowIfNull(socket);
        ArgumentNullException.ThrowIfNull(remote);

        _socket = socket;
        Port = port;
        ApplicationPort = applicationPort;
        Remote = remote;
    }

    /// <summary>The loopback port the application's datagrams are redirected to.</summary>
    public ushort Port { get; }

    /// <summary>The application socket's port.</summary>
    public ushort ApplicationPort { get; }

    /// <summary>The remote endpoint this lane stands in for.</summary>
    public IPEndPoint Remote { get; }

    /// <summary>When a datagram last passed, for idle eviction.</summary>
    public DateTimeOffset LastUsed { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Reads the next datagram the application sent to this lane.</summary>
    public Task<UdpReceiveResult> ReceiveAsync(CancellationToken cancellationToken) =>
        _socket.ReceiveAsync(cancellationToken).AsTask();

    /// <summary>
    /// Sends a reply to the application.
    /// </summary>
    /// <remarks>
    /// Addressed to loopback because that is where it has to start. The packet layer rewrites the
    /// source to the remote host and the destination to the application's own address on the way
    /// past, so what arrives looks like an answer from the host the application wrote to.
    /// </remarks>
    public Task SendToApplicationAsync(ReadOnlyMemory<byte> payload)
    {
        LastUsed = DateTimeOffset.UtcNow;

        return _socket.SendAsync(
            payload,
            new IPEndPoint(IPAddress.Loopback, ApplicationPort)).AsTask();
    }

    /// <summary>
    /// Gives the lane up.
    /// </summary>
    /// <remarks>
    /// The socket belongs to the pool, which replaces it rather than handing the same one out again -
    /// datagrams for this conversation may still be arriving, and a lane that inherited them would
    /// give one application another's traffic.
    /// </remarks>
    public void Dispose()
    {
    }
}
