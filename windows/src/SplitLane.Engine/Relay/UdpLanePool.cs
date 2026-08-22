using System.Net;
using System.Net.Sockets;

namespace SplitLane.Engine.Relay;

/// <summary>
/// A contiguous block of loopback ports reserved for relaying datagrams.
/// </summary>
/// <remarks>
/// <para>
/// The ports are bound before the divert filter is built, so the filter can name the block and
/// nothing else. That is the entire reason this type exists, and it was learned the hard way: a
/// filter that captured every loopback datagram on the machine pulled ten thousand packets a second
/// into user mode and broke the tunnel this machine's DNS runs through. TCP by address still worked,
/// so what the user saw was an internet that had simply gone, with no error anywhere.
/// </para>
/// <para>
/// A contiguous block rather than a list of ports, because the filter then costs two comparisons
/// instead of one per port - WinDivert compiles filters to a bounded number of instructions, and a
/// pool large enough to be useful would not fit as a list.
/// </para>
/// <para>
/// Reserved up front rather than bound on demand for the same reason: a port discovered later could
/// not be added to a filter that is already open.
/// </para>
/// </remarks>
public sealed class UdpLanePool : IDisposable
{
    /// <summary>The first port tried. Inside the ephemeral range Windows itself hands out.</summary>
    private const ushort SearchBase = 49152;

    private readonly UdpClient?[] _sockets;
    private readonly bool[] _taken;
    private readonly Lock _gate = new();

    /// <summary>Reserves a block.</summary>
    /// <param name="size">How many lanes can exist at once.</param>
    /// <exception cref="IOException">No free block of this size could be found.</exception>
    public UdpLanePool(int size = 64)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(size, 1);

        _sockets = new UdpClient?[size];
        _taken = new bool[size];

        for (var candidate = SearchBase; candidate < 65535 - size; candidate = (ushort)(candidate + size))
        {
            if (TryBindBlock(candidate, size))
            {
                BasePort = candidate;
                return;
            }
        }

        throw new IOException(
            $"no free block of {size} consecutive loopback ports could be reserved for relaying datagrams");
    }

    /// <summary>The first port of the block.</summary>
    public ushort BasePort { get; }

    /// <summary>How many ports the block holds.</summary>
    public int Size => _sockets.Length;

    /// <summary>The last port of the block.</summary>
    public ushort LastPort => (ushort)(BasePort + Size - 1);

    /// <summary>Whether a port belongs to this block.</summary>
    public bool Contains(ushort port) => port >= BasePort && port <= LastPort;

    /// <summary>Takes a free socket from the block, or null when they are all in use.</summary>
    public (UdpClient Socket, ushort Port)? TryAcquire()
    {
        lock (_gate)
        {
            for (var i = 0; i < _sockets.Length; i++)
            {
                if (_taken[i] || _sockets[i] is null)
                {
                    continue;
                }

                _taken[i] = true;
                return (_sockets[i]!, (ushort)(BasePort + i));
            }
        }

        return null;
    }

    /// <summary>
    /// Hands a socket back.
    /// </summary>
    /// <remarks>
    /// The socket is replaced rather than reused. Datagrams for the previous conversation may still
    /// be in flight, and a lane that inherited them would hand one application another's traffic.
    /// </remarks>
    public void Release(ushort port)
    {
        if (!Contains(port))
        {
            return;
        }

        var index = port - BasePort;

        lock (_gate)
        {
            if (!_taken[index])
            {
                return;
            }

            _sockets[index]?.Dispose();
            _sockets[index] = TryBind(port);
            _taken[index] = false;
        }
    }

    private bool TryBindBlock(ushort start, int size)
    {
        var bound = new UdpClient?[size];

        for (var i = 0; i < size; i++)
        {
            var socket = TryBind((ushort)(start + i));

            if (socket is null)
            {
                foreach (var opened in bound)
                {
                    opened?.Dispose();
                }

                return false;
            }

            bound[i] = socket;
        }

        bound.CopyTo(_sockets, 0);
        return true;
    }

    private static UdpClient? TryBind(ushort port)
    {
        try
        {
            return new UdpClient(new IPEndPoint(IPAddress.Loopback, port));
        }
        catch (SocketException)
        {
            return null;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        lock (_gate)
        {
            for (var i = 0; i < _sockets.Length; i++)
            {
                _sockets[i]?.Dispose();
                _sockets[i] = null;
            }
        }
    }
}
