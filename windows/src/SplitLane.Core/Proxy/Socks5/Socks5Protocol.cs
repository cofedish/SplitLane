namespace SplitLane.Core.Proxy.Socks5;

/// <summary>
/// Wire constants and vocabulary for SOCKS5 (RFC 1928) and its username/password authentication
/// sub-negotiation (RFC 1929).
/// </summary>
public static class Socks5
{
    /// <summary>Protocol version byte, present in every SOCKS5 message.</summary>
    public const byte Version = 0x05;

    /// <summary>
    /// Version byte of the username/password sub-negotiation.
    /// </summary>
    /// <remarks>
    /// Note this is <c>0x01</c>, <b>not</b> <c>0x05</c> — RFC 1929 versions itself independently, and
    /// conflating the two is a classic bug.
    /// </remarks>
    public const byte AuthSubnegotiationVersion = 0x01;

    /// <summary>Reserved byte, must be zero in requests and is required to be zero in replies.</summary>
    public const byte Reserved = 0x00;

    /// <summary>RFC 1929 authentication succeeded when the status byte is zero.</summary>
    public const byte AuthenticationSuccessStatus = 0x00;
}

/// <summary>Authentication methods offered and selected during the greeting.</summary>
public enum Socks5Method : byte
{
    /// <summary>No authentication required.</summary>
    NoAuthentication = 0x00,

    /// <summary>GSSAPI. Never offered by this client.</summary>
    Gssapi = 0x01,

    /// <summary>Username and password, RFC 1929.</summary>
    UsernamePassword = 0x02,

    /// <summary>Returned by the server when it accepts none of the offered methods.</summary>
    NoAcceptableMethods = 0xFF,
}

/// <summary>
/// Request command. Only <see cref="Connect"/> is implemented; the others are listed because a reply
/// may reference them and the parser should be able to name what it saw.
/// </summary>
public enum Socks5Command : byte
{
    /// <summary>Open an outbound TCP connection.</summary>
    Connect = 0x01,

    /// <summary>Accept an inbound connection.</summary>
    Bind = 0x02,

    /// <summary>Establish a UDP relay.</summary>
    UdpAssociate = 0x03,
}

/// <summary>Address type tag.</summary>
public enum Socks5AddressType : byte
{
    /// <summary>Four raw octets.</summary>
    IPv4 = 0x01,

    /// <summary>Length-prefixed hostname.</summary>
    Domain = 0x03,

    /// <summary>Sixteen raw octets.</summary>
    IPv6 = 0x04,
}

/// <summary>Reply status from the server (RFC 1928 §6).</summary>
public enum Socks5ReplyCode : byte
{
    /// <summary>The request was granted.</summary>
    Succeeded = 0x00,

    /// <summary>General SOCKS server failure.</summary>
    GeneralFailure = 0x01,

    /// <summary>Connection not allowed by ruleset.</summary>
    ConnectionNotAllowed = 0x02,

    /// <summary>Network unreachable.</summary>
    NetworkUnreachable = 0x03,

    /// <summary>Host unreachable.</summary>
    HostUnreachable = 0x04,

    /// <summary>Connection refused.</summary>
    ConnectionRefused = 0x05,

    /// <summary>TTL expired.</summary>
    TtlExpired = 0x06,

    /// <summary>Command not supported.</summary>
    CommandNotSupported = 0x07,

    /// <summary>Address type not supported.</summary>
    AddressTypeNotSupported = 0x08,
}

/// <summary>Text for reply codes.</summary>
public static class Socks5ReplyCodeExtensions
{
    /// <summary>Whether the reply means the tunnel is open.</summary>
    public static bool IsSuccess(this Socks5ReplyCode code) => code == Socks5ReplyCode.Succeeded;

    /// <summary>One line the UI can show verbatim.</summary>
    public static string Describe(this Socks5ReplyCode code) => code switch
    {
        Socks5ReplyCode.Succeeded => "Succeeded",
        Socks5ReplyCode.GeneralFailure => "General SOCKS server failure",
        Socks5ReplyCode.ConnectionNotAllowed => "Connection not allowed by ruleset",
        Socks5ReplyCode.NetworkUnreachable => "Network unreachable",
        Socks5ReplyCode.HostUnreachable => "Host unreachable",
        Socks5ReplyCode.ConnectionRefused => "Connection refused",
        Socks5ReplyCode.TtlExpired => "TTL expired",
        Socks5ReplyCode.CommandNotSupported => "Command not supported",
        Socks5ReplyCode.AddressTypeNotSupported => "Address type not supported",
        _ => "Unknown reply code",
    };
}
