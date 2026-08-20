namespace SplitLane.Core.Proxy.Socks5;

/// <summary>
/// A bounds-checked cursor over a buffer of received bytes.
/// </summary>
/// <remarks>
/// Every read either succeeds or throws <see cref="Socks5ErrorCode.IncompleteResponse"/>, and the
/// offset only advances on success. That contract is what lets the negotiator re-parse a message
/// from the top each time more bytes arrive without tracking partial state: a truncated read is a
/// signal to wait, not a failure, and it cannot leave the reader half-consumed.
///
/// <para>
/// It is a <c>ref struct</c> so it cannot outlive or escape the buffer it points at, and so parsing
/// a handshake allocates nothing at all.
/// </para>
/// </remarks>
internal ref struct ByteReader(ReadOnlySpan<byte> buffer)
{
    private readonly ReadOnlySpan<byte> _buffer = buffer;

    /// <summary>How many bytes have been consumed.</summary>
    public int Offset { get; private set; }

    /// <summary>Bytes not yet consumed.</summary>
    public readonly int Remaining => _buffer.Length - Offset;

    /// <summary>Reads one byte.</summary>
    public byte ReadUInt8()
    {
        if (Remaining < 1)
        {
            throw Socks5Exception.Incomplete();
        }

        return _buffer[Offset++];
    }

    /// <summary>Reads a big-endian 16-bit value, which is the only width SOCKS5 uses for ports.</summary>
    public ushort ReadUInt16()
    {
        if (Remaining < 2)
        {
            throw Socks5Exception.Incomplete();
        }

        var value = (ushort)((_buffer[Offset] << 8) | _buffer[Offset + 1]);
        Offset += 2;
        return value;
    }

    /// <summary>Reads a fixed number of bytes.</summary>
    public byte[] ReadBytes(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);

        if (Remaining < count)
        {
            throw Socks5Exception.Incomplete();
        }

        var slice = _buffer.Slice(Offset, count).ToArray();
        Offset += count;
        return slice;
    }

    /// <summary>
    /// Reads a single-byte length followed by that many bytes.
    /// </summary>
    /// <remarks>
    /// The length is chosen by the server. Because <see cref="ReadBytes"/> bounds-checks it against
    /// what actually arrived, a hostile length can only produce an "incomplete" signal — never an
    /// over-read, and never an allocation the server controls the size of beyond 255 bytes.
    /// </remarks>
    public byte[] ReadLengthPrefixedBytes()
    {
        var length = ReadUInt8();
        return ReadBytes(length);
    }
}
