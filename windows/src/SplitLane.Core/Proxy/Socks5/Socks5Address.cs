using System.Net;
using System.Text;
using SplitLane.Core.Rules;

namespace SplitLane.Core.Proxy.Socks5;

/// <summary>A SOCKS5 destination or bound address.</summary>
public readonly struct Socks5Address : IEquatable<Socks5Address>
{
    private readonly byte[]? _bytes;
    private readonly string? _domain;

    private Socks5Address(Socks5AddressType type, byte[]? bytes, string? domain)
    {
        Type = type;
        _bytes = bytes;
        _domain = domain;
    }

    /// <summary>Which of the three forms this is.</summary>
    public Socks5AddressType Type { get; }

    /// <summary>Raw address octets for the literal forms; empty for a domain.</summary>
    public ReadOnlySpan<byte> Octets => _bytes ?? [];

    /// <summary>The hostname for <see cref="Socks5AddressType.Domain"/>; null otherwise.</summary>
    public string? Domain => _domain;

    /// <summary>Builds an IPv4 address from exactly four octets.</summary>
    public static Socks5Address FromIPv4(ReadOnlySpan<byte> octets)
    {
        if (octets.Length != 4)
        {
            throw Socks5Exception.Malformed("IPv4 address must be 4 bytes");
        }

        return new Socks5Address(Socks5AddressType.IPv4, octets.ToArray(), null);
    }

    /// <summary>Builds an IPv6 address from exactly sixteen octets.</summary>
    public static Socks5Address FromIPv6(ReadOnlySpan<byte> octets)
    {
        if (octets.Length != 16)
        {
            throw Socks5Exception.Malformed("IPv6 address must be 16 bytes");
        }

        return new Socks5Address(Socks5AddressType.IPv6, octets.ToArray(), null);
    }

    /// <summary>Builds a domain address, enforcing the single-byte length limit.</summary>
    public static Socks5Address FromDomain(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        var byteCount = Encoding.UTF8.GetByteCount(name);
        if (byteCount == 0)
        {
            throw Socks5Exception.InvalidDestination(name);
        }

        if (byteCount > 255)
        {
            throw Socks5Exception.DomainTooLong();
        }

        return new Socks5Address(Socks5AddressType.Domain, null, name);
    }

    /// <summary>Builds an address from an IP literal, or null if the string is not one.</summary>
    public static Socks5Address? Literal(string? address)
    {
        if (NetworkAddress.TryParseIPv4(address, out var v4))
        {
            return FromIPv4(v4);
        }

        if (NetworkAddress.TryParseIPv6(address, out var v6))
        {
            return FromIPv6(v6);
        }

        return null;
    }

    /// <summary>
    /// Builds the address to put in a CONNECT request.
    /// </summary>
    /// <remarks>
    /// A hostname is preferred over an IP whenever one is available, so that the <i>upstream</i>
    /// resolves the name. The alternative — sending the IP the client already resolved locally —
    /// pins the connection to whatever the local resolver returned, which for a CDN means the proxy
    /// connects to an edge node chosen for the client's location rather than its own.
    ///
    /// <para>
    /// A hostname that happens to be an IP literal is emitted as that literal, because
    /// <c>ATYP=DOMAIN</c> carrying "93.184.216.34" makes the server do a pointless lookup.
    /// </para>
    /// </remarks>
    public static Socks5Address Destination(string? hostname, string? address)
    {
        if (!string.IsNullOrEmpty(hostname))
        {
            var literal = Literal(hostname);
            if (literal.HasValue)
            {
                return literal.Value;
            }

            return FromDomain(hostname);
        }

        if (!string.IsNullOrEmpty(address))
        {
            var literal = Literal(address);
            if (literal.HasValue)
            {
                return literal.Value;
            }
        }

        throw Socks5Exception.InvalidDestination(address ?? hostname ?? "<none>");
    }

    /// <summary>Wire encoding of the address, excluding the type tag and the port.</summary>
    public byte[] EncodeBody()
    {
        switch (Type)
        {
            case Socks5AddressType.IPv4:
            case Socks5AddressType.IPv6:
                return _bytes ?? throw Socks5Exception.Malformed("literal address has no octets");

            case Socks5AddressType.Domain:
                var name = _domain ?? throw Socks5Exception.InvalidDestination("<null>");
                var utf8 = Encoding.UTF8.GetBytes(name);
                if (utf8.Length == 0)
                {
                    throw Socks5Exception.InvalidDestination(name);
                }

                if (utf8.Length > 255)
                {
                    throw Socks5Exception.DomainTooLong();
                }

                var encoded = new byte[utf8.Length + 1];
                encoded[0] = (byte)utf8.Length;
                utf8.CopyTo(encoded, 1);
                return encoded;

            default:
                throw Socks5Exception.UnsupportedAddressType((byte)Type);
        }
    }

    /// <summary>Type tag followed by the encoded body.</summary>
    public byte[] Encode()
    {
        var body = EncodeBody();
        var encoded = new byte[body.Length + 1];
        encoded[0] = (byte)Type;
        body.CopyTo(encoded, 1);
        return encoded;
    }

    /// <summary>Parses an address from a reply. Advances the reader only on success.</summary>
    internal static Socks5Address Decode(ref ByteReader reader)
    {
        var rawType = reader.ReadUInt8();
        if (!Enum.IsDefined(typeof(Socks5AddressType), rawType))
        {
            throw Socks5Exception.UnsupportedAddressType(rawType);
        }

        switch ((Socks5AddressType)rawType)
        {
            case Socks5AddressType.IPv4:
                return FromIPv4(reader.ReadBytes(4));

            case Socks5AddressType.IPv6:
                return FromIPv6(reader.ReadBytes(16));

            case Socks5AddressType.Domain:
                var bytes = reader.ReadLengthPrefixedBytes();
                try
                {
                    var name = new UTF8Encoding(false, true).GetString(bytes);
                    return new Socks5Address(Socks5AddressType.Domain, null, name);
                }
                catch (DecoderFallbackException)
                {
                    throw Socks5Exception.Malformed("domain name is not valid UTF-8");
                }

            default:
                throw Socks5Exception.UnsupportedAddressType(rawType);
        }
    }

    /// <summary>
    /// Human-readable form for logging. Contains no secrets — destinations are loggable, payloads
    /// and credentials are not.
    /// </summary>
    public override string ToString() => Type switch
    {
        Socks5AddressType.Domain => _domain ?? string.Empty,
        Socks5AddressType.IPv4 or Socks5AddressType.IPv6 when _bytes is not null => new IPAddress(_bytes).ToString(),
        _ => string.Empty,
    };

    /// <inheritdoc />
    public bool Equals(Socks5Address other)
    {
        if (Type != other.Type)
        {
            return false;
        }

        return Type == Socks5AddressType.Domain
            ? string.Equals(_domain, other._domain, StringComparison.Ordinal)
            : Octets.SequenceEqual(other.Octets);
    }

    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is Socks5Address other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Type);
        if (_domain is not null)
        {
            hash.Add(_domain, StringComparer.Ordinal);
        }

        if (_bytes is not null)
        {
            hash.AddBytes(_bytes);
        }

        return hash.ToHashCode();
    }

    /// <summary>Equality operator.</summary>
    public static bool operator ==(Socks5Address left, Socks5Address right) => left.Equals(right);

    /// <summary>Inequality operator.</summary>
    public static bool operator !=(Socks5Address left, Socks5Address right) => !left.Equals(right);
}
