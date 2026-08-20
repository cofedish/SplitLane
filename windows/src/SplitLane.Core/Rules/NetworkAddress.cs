using System.Net;
using System.Net.Sockets;

namespace SplitLane.Core.Rules;

/// <summary>
/// Address classification used by the router.
/// </summary>
/// <remarks>
/// The only questions asked here are "is this destination on this machine or this link?", which is
/// the third layer of proxy-loop defence: a selected app talking to <c>127.0.0.1</c> is never
/// proxied, so even a mistaken divert filter degrades to "not proxied" rather than recursion.
///
/// <para>
/// IPv4 parsing deliberately does <b>not</b> use <c>IPAddress.TryParse</c>. .NET's parser is
/// strict, and <c>127.1</c>, <c>0177.0.0.1</c> and <c>0x7f000001</c> are all spellings of loopback
/// that the Windows resolver and <c>connect()</c> accept. A strict parser classifies them as "not
/// loopback", which is the dangerous direction to be wrong in: it would let a selected app's
/// loopback traffic be proxied and loop. So this implements <c>inet_aton</c> semantics, exactly as
/// the macOS core does, and errs toward "local".
/// </para>
/// </remarks>
public static class NetworkAddress
{
    /// <summary>True for IPv4 <c>127.0.0.0/8</c>, IPv6 <c>::1</c>, and IPv4-mapped forms of either.</summary>
    public static bool IsLoopbackAddress(string? address)
    {
        if (TryParseIPv4(address, out var v4))
        {
            return v4[0] == 127;
        }

        if (TryParseIPv6(address, out var v6))
        {
            if (TryGetIPv4Mapped(v6, out var mapped))
            {
                return mapped[0] == 127;
            }

            for (var i = 0; i < 15; i++)
            {
                if (v6[i] != 0)
                {
                    return false;
                }
            }

            return v6[15] == 1;
        }

        return false;
    }

    /// <summary>
    /// True for IPv4 <c>169.254.0.0/16</c> and IPv6 <c>fe80::/10</c>.
    /// </summary>
    /// <remarks>
    /// Link-local is grouped with loopback for routing purposes: it never makes sense to send
    /// link-scoped traffic to a proxy. On Windows this also covers the addresses Hyper-V, WSL and
    /// the Windows internal switch hand out before DHCP settles.
    /// </remarks>
    public static bool IsLinkLocalAddress(string? address)
    {
        if (TryParseIPv4(address, out var v4))
        {
            return v4[0] == 169 && v4[1] == 254;
        }

        if (TryParseIPv6(address, out var v6))
        {
            if (TryGetIPv4Mapped(v6, out var mapped))
            {
                return mapped[0] == 169 && mapped[1] == 254;
            }

            return v6[0] == 0xFE && (v6[1] & 0xC0) == 0x80;
        }

        return false;
    }

    /// <summary>Destinations that must never enter the proxy lane, whatever the rules say.</summary>
    public static bool IsLocalDestination(string? address)
        => IsLoopbackAddress(address) || IsLinkLocalAddress(address);

    /// <summary>
    /// Hostname-or-address form of <see cref="IsLoopbackAddress"/>, accepting the textual names the
    /// system resolves to loopback.
    /// </summary>
    public static bool IsLoopbackHost(string? host)
    {
        if (string.IsNullOrEmpty(host))
        {
            return false;
        }

        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return IsLoopbackAddress(host);
    }

    /// <summary>True if the string parses as an IP literal in either family.</summary>
    public static bool IsIPLiteral(string? address)
        => TryParseIPv4(address, out _) || TryParseIPv6(address, out _);

    /// <summary>
    /// Parses a dotted-quad or any of the abbreviated <c>inet_aton</c> forms into four octets.
    /// </summary>
    /// <remarks>
    /// Accepts 1 to 4 parts. The final part absorbs all remaining octets, so <c>127.1</c> is
    /// 127.0.0.1 and <c>2130706433</c> is the same address. Each part may be decimal, hexadecimal
    /// (<c>0x</c> prefix) or octal (leading zero), which is what <c>inet_aton</c> does and
    /// therefore what an application's own <c>connect()</c> will do.
    /// </remarks>
    public static bool TryParseIPv4(string? address, out byte[] octets)
    {
        octets = [];
        if (string.IsNullOrWhiteSpace(address) || address.Contains(':'))
        {
            return false;
        }

        var parts = address.Trim().Split('.');
        if (parts.Length is < 1 or > 4)
        {
            return false;
        }

        Span<ulong> values = stackalloc ulong[4];
        for (var i = 0; i < parts.Length; i++)
        {
            if (!TryParseNumericPart(parts[i], out values[i]))
            {
                return false;
            }
        }

        var last = parts.Length - 1;
        for (var i = 0; i < last; i++)
        {
            if (values[i] > 0xFF)
            {
                return false;
            }
        }

        var maxTail = last switch
        {
            0 => 0xFFFFFFFFUL,
            1 => 0xFFFFFFUL,
            2 => 0xFFFFUL,
            _ => 0xFFUL,
        };

        if (values[last] > maxTail)
        {
            return false;
        }

        var raw = values[last];
        for (var i = last - 1; i >= 0; i--)
        {
            raw |= values[i] << (8 * (3 - i));
        }

        octets =
        [
            (byte)((raw >> 24) & 0xFF),
            (byte)((raw >> 16) & 0xFF),
            (byte)((raw >> 8) & 0xFF),
            (byte)(raw & 0xFF),
        ];
        return true;
    }

    /// <summary>Parses an IPv6 literal into 16 bytes. A zone suffix is stripped first.</summary>
    public static bool TryParseIPv6(string? address, out byte[] bytes)
    {
        bytes = [];
        if (string.IsNullOrWhiteSpace(address))
        {
            return false;
        }

        var trimmed = address.Trim();

        // Bracketed literals arrive from URL-shaped input; strip before parsing.
        if (trimmed.Length > 1 && trimmed[0] == '[' && trimmed[^1] == ']')
        {
            trimmed = trimmed[1..^1];
        }

        var percent = trimmed.IndexOf('%');
        if (percent >= 0)
        {
            trimmed = trimmed[..percent];
        }

        if (!trimmed.Contains(':'))
        {
            return false;
        }

        if (!IPAddress.TryParse(trimmed, out var parsed) ||
            parsed.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return false;
        }

        bytes = parsed.GetAddressBytes();
        return bytes.Length == 16;
    }

    /// <summary>Extracts the embedded IPv4 address from an IPv4-mapped IPv6 address.</summary>
    private static bool TryGetIPv4Mapped(byte[] v6, out byte[] mapped)
    {
        mapped = [];
        if (v6.Length != 16)
        {
            return false;
        }

        for (var i = 0; i < 10; i++)
        {
            if (v6[i] != 0)
            {
                return false;
            }
        }

        if (v6[10] != 0xFF || v6[11] != 0xFF)
        {
            return false;
        }

        mapped = [v6[12], v6[13], v6[14], v6[15]];
        return true;
    }

    private static bool TryParseNumericPart(string part, out ulong value)
    {
        value = 0;
        if (part.Length == 0)
        {
            return false;
        }

        int radix;
        ReadOnlySpan<char> digits;

        if (part.Length > 2 && part[0] == '0' && (part[1] is 'x' or 'X'))
        {
            radix = 16;
            digits = part.AsSpan(2);
        }
        else if (part.Length > 1 && part[0] == '0')
        {
            radix = 8;
            digits = part.AsSpan(1);
        }
        else
        {
            radix = 10;
            digits = part.AsSpan();
        }

        if (digits.Length == 0)
        {
            return false;
        }

        foreach (var c in digits)
        {
            var digit = c switch
            {
                >= '0' and <= '9' => c - '0',
                >= 'a' and <= 'f' => c - 'a' + 10,
                >= 'A' and <= 'F' => c - 'A' + 10,
                _ => -1,
            };

            if (digit < 0 || digit >= radix)
            {
                return false;
            }

            value = (value * (ulong)radix) + (ulong)digit;
            if (value > 0xFFFFFFFFUL)
            {
                return false;
            }
        }

        return true;
    }
}
