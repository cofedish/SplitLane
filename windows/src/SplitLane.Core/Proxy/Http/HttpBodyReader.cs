using System.Globalization;

namespace SplitLane.Core.Proxy.Http;

/// <summary>
/// Reads past the body of a proxy's refusal, so the next request on the same connection starts at
/// a message boundary.
/// </summary>
/// <remarks>
/// <para>
/// Only needed for a 407 that is answered on the same connection - which NTLM and Negotiate require,
/// because the proxy ties their challenge to the connection that asked. The bytes are counted and
/// thrown away; nothing about them is kept.
/// </para>
/// <para>
/// A pure state machine like the rest of the protocol code: bytes in, how many were consumed out,
/// whether the body is over. Every split point of a chunked body is then a unit test.
/// </para>
/// </remarks>
public sealed class HttpBodyReader
{
    private enum Phase
    {
        Fixed,
        ChunkSize,
        ChunkData,
        ChunkDataEnd,
        Trailer,
        Done,
    }

    /// <summary>Longest chunk-size line accepted, extensions included.</summary>
    private const int MaxLineBytes = 4096;

    private readonly List<byte> _line = [];
    private Phase _phase;
    private long _remaining;

    private HttpBodyReader(Phase phase, long remaining)
    {
        _phase = phase;
        _remaining = remaining;
    }

    /// <summary>A body of exactly this many bytes.</summary>
    public static HttpBodyReader ForLength(long length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        return new HttpBodyReader(length == 0 ? Phase.Done : Phase.Fixed, length);
    }

    /// <summary>A chunked body, RFC 9112 §7.1.</summary>
    public static HttpBodyReader Chunked() => new(Phase.ChunkSize, 0);

    /// <summary>Whether the whole body has been read.</summary>
    public bool IsComplete => _phase == Phase.Done;

    /// <summary>Body bytes seen so far, framing excluded.</summary>
    public long BodyBytes { get; private set; }

    /// <summary>
    /// Consumes body bytes from the start of <paramref name="data"/>.
    /// </summary>
    /// <returns>How many bytes belonged to the body. Anything after them is the next message.</returns>
    /// <exception cref="FormatException">The chunked framing is broken.</exception>
    public int Consume(ReadOnlySpan<byte> data)
    {
        var used = 0;

        while (used < data.Length && _phase != Phase.Done)
        {
            switch (_phase)
            {
                case Phase.Fixed:
                {
                    var take = (int)Math.Min(_remaining, data.Length - used);
                    used += take;
                    _remaining -= take;
                    BodyBytes += take;
                    if (_remaining == 0)
                    {
                        _phase = Phase.Done;
                    }

                    break;
                }

                case Phase.ChunkData:
                {
                    var take = (int)Math.Min(_remaining, data.Length - used);
                    used += take;
                    _remaining -= take;
                    BodyBytes += take;
                    if (_remaining == 0)
                    {
                        _phase = Phase.ChunkDataEnd;
                    }

                    break;
                }

                case Phase.ChunkSize:
                case Phase.ChunkDataEnd:
                case Phase.Trailer:
                {
                    var b = data[used++];
                    if (b != (byte)'\n')
                    {
                        if (_line.Count >= MaxLineBytes)
                        {
                            throw new FormatException("Chunk framing line is too long");
                        }

                        _line.Add(b);
                        break;
                    }

                    var line = LineText();
                    _line.Clear();
                    EndOfLine(line);
                    break;
                }
            }
        }

        return used;
    }

    private string LineText()
    {
        var count = _line.Count > 0 && _line[^1] == (byte)'\r' ? _line.Count - 1 : _line.Count;
        var chars = new char[count];
        for (var i = 0; i < count; i++)
        {
            chars[i] = (char)_line[i];
        }

        return new string(chars);
    }

    private void EndOfLine(string line)
    {
        switch (_phase)
        {
            case Phase.ChunkSize:
            {
                var semicolon = line.IndexOf(';');
                var size = (semicolon >= 0 ? line[..semicolon] : line).Trim(' ', '\t');

                if (size.Length is 0 or > 15 ||
                    !long.TryParse(size, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var length))
                {
                    throw new FormatException("Chunk size is not a hexadecimal number");
                }

                _remaining = length;
                _phase = length == 0 ? Phase.Trailer : Phase.ChunkData;
                break;
            }

            case Phase.ChunkDataEnd:
                if (line.Length != 0)
                {
                    throw new FormatException("Chunk data is not followed by a line break");
                }

                _phase = Phase.ChunkSize;
                break;

            case Phase.Trailer:
                // Trailer fields are skipped; the empty line ends the message.
                if (line.Length == 0)
                {
                    _phase = Phase.Done;
                }

                break;
        }
    }
}
