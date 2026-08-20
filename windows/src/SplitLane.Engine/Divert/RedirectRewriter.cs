using System.Net;
using System.Net.Sockets;
using SplitLane.Engine.Net;

namespace SplitLane.Engine.Divert;

/// <summary>
/// The address arithmetic that moves a connection into, and back out of, the redirect listener.
/// </summary>
/// <remarks>
/// <para>
/// Windows has no equivalent of <c>NETransparentProxyProvider</c>: there is no supported way to hand
/// a user-mode process a connection's socket and let the kernel keep the flow. What there is, is the
/// ability to rewrite packets. So a selected application's connection is destination-NATed to a
/// loopback listener, relayed through SOCKS5, and the replies are source-NATed back so the
/// application's socket never learns that anything happened. See ADR W-0001.
/// </para>
/// <para>
/// Both endpoints move to loopback on the way in. Rewriting only the destination would leave a
/// packet addressed <c>192.168.1.5 → 127.0.0.1</c>, which the Windows stack drops as a martian: an
/// address in <c>127/8</c> is only valid paired with another one.
/// </para>
/// <para>
/// These two functions are pure and operate on a buffer, with no WinDivert types in the signature,
/// so the rewrite and the checksums can be proven against constructed packets in a unit test. That
/// separation is deliberate. A NAT bug reinjects a packet with a stale checksum, which does not
/// produce an error anywhere — it produces a connection that silently hangs, and is close to
/// undiagnosable from the outside.
/// </para>
/// </remarks>
public static class RedirectRewriter
{
    /// <summary>Loopback addresses used as both endpoints of a redirected connection.</summary>
    private static readonly byte[] LoopbackV4 = [127, 0, 0, 1];

    private static readonly byte[] LoopbackV6 =
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    /// <summary>What the original endpoints of a redirected packet were.</summary>
    /// <param name="SourceAddress">The address the application bound.</param>
    /// <param name="SourcePort">The port it bound — the NAT table key.</param>
    /// <param name="DestinationAddress">Where it thinks it is connected.</param>
    /// <param name="DestinationPort">The port it thinks it is connected to.</param>
    public readonly record struct Endpoints(
        IPAddress SourceAddress,
        ushort SourcePort,
        IPAddress DestinationAddress,
        ushort DestinationPort);

    /// <summary>
    /// Reads the endpoints of an outbound packet without changing it.
    /// </summary>
    public static bool TryReadEndpoints(Span<byte> packet, out Endpoints endpoints)
    {
        endpoints = default;

        if (!PacketView.TryParse(packet, out var view) || !view.HasPorts)
        {
            return false;
        }

        endpoints = new Endpoints(
            new IPAddress(view.SourceAddress),
            view.SourcePort,
            new IPAddress(view.DestinationAddress),
            view.DestinationPort);

        return true;
    }

    /// <summary>
    /// Rewrites an application's outbound packet so it arrives at the redirect listener.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The source <b>port</b> is deliberately left alone. It is the only field that survives the
    /// rewrite intact, and it is what both the listener and the return path use to find the
    /// connection's NAT entry.
    /// </para>
    /// <para>
    /// Two shapes, because the loopback one is not confirmed to work. See ADR W-0001 and
    /// docs/THREAT_MODEL.md.
    /// </para>
    /// </remarks>
    /// <param name="packet">The packet, rewritten in place.</param>
    /// <param name="listenerPort">Where the redirect listener is bound.</param>
    /// <param name="useLoopback">
    /// When true, both endpoints move to <c>127.0.0.1</c>. When false, only the destination changes,
    /// to the address the application already bound — which is a local address on this machine, so
    /// the packet is delivered locally without involving the loopback path at all.
    /// </param>
    public static bool TryRedirectToListener(Span<byte> packet, ushort listenerPort, bool useLoopback = true)
    {
        if (!PacketView.TryParse(packet, out var view) || !view.HasPorts)
        {
            return false;
        }

        if (useLoopback)
        {
            // Both endpoints move together. Rewriting only the destination would leave a packet
            // addressed 192.168.1.5 -> 127.0.0.1, which the stack drops as a martian: an address in
            // 127/8 is only valid paired with another one.
            var loopback = view.IsIPv6 ? LoopbackV6 : LoopbackV4;
            view.SetSourceAddress(loopback);
            view.SetDestinationAddress(loopback);
        }
        else
        {
            // Send it to the machine's own address - the one the application is already sending
            // from. Source and destination are then the same local address, which is an ordinary
            // local delivery the stack handles without the loopback fast path.
            Span<byte> local = stackalloc byte[view.IsIPv6 ? 16 : 4];
            view.SourceAddress.CopyTo(local);
            view.SetDestinationAddress(local);
        }

        view.DestinationPort = listenerPort;
        view.RecomputeChecksums();
        return true;
    }

    /// <summary>
    /// Rewrites the listener's reply so the application sees it coming from the real destination.
    /// </summary>
    /// <remarks>
    /// The application's socket is in <c>ESTABLISHED</c> against the original four-tuple. A reply
    /// that did not carry exactly that tuple would be answered with a reset by the application's own
    /// stack, so this is not cosmetic: it is what makes the redirect invisible.
    /// </remarks>
    public static bool TryRestoreFromListener(
        Span<byte> packet,
        IPAddress originalDestination,
        ushort originalDestinationPort,
        IPAddress originalSource)
    {
        ArgumentNullException.ThrowIfNull(originalDestination);
        ArgumentNullException.ThrowIfNull(originalSource);

        if (!PacketView.TryParse(packet, out var view) || !view.HasPorts)
        {
            return false;
        }

        // A packet cannot change family mid-connection. If the NAT entry disagrees with the packet
        // on the wire, something is wrong upstream of here and rewriting would corrupt the header.
        var expectedFamily = view.IsIPv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;
        if (originalDestination.AddressFamily != expectedFamily ||
            originalSource.AddressFamily != expectedFamily)
        {
            return false;
        }

        Span<byte> destination = stackalloc byte[view.IsIPv6 ? 16 : 4];
        Span<byte> source = stackalloc byte[view.IsIPv6 ? 16 : 4];

        if (!originalDestination.TryWriteBytes(destination, out _) ||
            !originalSource.TryWriteBytes(source, out _))
        {
            return false;
        }

        view.SetSourceAddress(destination);
        view.SetDestinationAddress(source);
        view.SourcePort = originalDestinationPort;
        view.RecomputeChecksums();
        return true;
    }
}
