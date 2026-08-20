namespace SplitLane.Core.Proxy.Socks5;

/// <summary>
/// Failures the SOCKS5 layer can produce.
/// </summary>
/// <remarks>
/// Structured rather than stringly-typed because the UI reports these per application, and
/// "authentication failed" and "the proxy is not running" call for very different user actions.
/// </remarks>
public enum Socks5ErrorCode
{
    /// <summary>Server replied with a SOCKS version byte other than 0x05.</summary>
    UnexpectedVersion,

    /// <summary>Server accepted none of the methods offered.</summary>
    NoAcceptableAuthenticationMethod,

    /// <summary>Server selected a method that was never offered, or one this client cannot perform.</summary>
    UnsupportedAuthenticationMethod,

    /// <summary>Server requires authentication but no credential is configured.</summary>
    AuthenticationRequired,

    /// <summary>RFC 1929 sub-negotiation returned a non-zero status.</summary>
    AuthenticationFailed,

    /// <summary>Username or password does not fit RFC 1929's single length byte.</summary>
    CredentialTooLong,

    /// <summary>Server returned a non-success reply code.</summary>
    RequestRejected,

    /// <summary>Server returned a reply code outside the RFC 1928 range.</summary>
    UnknownReplyCode,

    /// <summary>Server sent an address type tag this client does not recognise.</summary>
    UnsupportedAddressType,

    /// <summary>Fewer bytes have arrived than the message needs. Recoverable: the caller waits.</summary>
    IncompleteResponse,

    /// <summary>Bytes arrived but violate the protocol.</summary>
    MalformedResponse,

    /// <summary>Destination hostname exceeds the 255 bytes a single length byte can express.</summary>
    DomainNameTooLong,

    /// <summary>Destination address could not be encoded.</summary>
    InvalidDestinationAddress,

    /// <summary>Handshake exceeded the configured timeout.</summary>
    TimedOut,

    /// <summary>The operation was cancelled (engine stopping, flow closed).</summary>
    Cancelled,

    /// <summary>The underlying transport failed.</summary>
    TransportFailure,

    /// <summary>Bytes were received in a state that expects none.</summary>
    ProtocolViolation,
}

/// <summary>A SOCKS5 failure, carrying a closed-vocabulary code plus enough detail to explain it.</summary>
public sealed class Socks5Exception : Exception
{
    /// <summary>Builds a failure.</summary>
    public Socks5Exception(Socks5ErrorCode code, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        Code = code;
    }

    /// <summary>What went wrong, as a value the UI can switch on.</summary>
    public Socks5ErrorCode Code { get; }

    /// <summary>Set when <see cref="Code"/> is <see cref="Socks5ErrorCode.RequestRejected"/>.</summary>
    public Socks5ReplyCode? ReplyCode { get; init; }

    /// <summary>
    /// Whether retrying could plausibly succeed.
    /// </summary>
    /// <remarks>
    /// Used to decide log level, never to silently downgrade a selected app to DIRECT — that never
    /// happens (ADR 0003).
    /// </remarks>
    public bool IsTransient => Code switch
    {
        Socks5ErrorCode.TimedOut or Socks5ErrorCode.TransportFailure or Socks5ErrorCode.IncompleteResponse => true,
        Socks5ErrorCode.RequestRejected => ReplyCode is Socks5ReplyCode.TtlExpired
            or Socks5ReplyCode.NetworkUnreachable
            or Socks5ReplyCode.HostUnreachable,
        _ => false,
    };

    /// <summary>The message is safe to show: it never contains payload bytes or credentials.</summary>
    public override string ToString() => $"{Code}: {Message}";

    // ---- Factories -------------------------------------------------------------------------

    internal static Socks5Exception UnexpectedVersion(byte value)
        => new(Socks5ErrorCode.UnexpectedVersion, $"Proxy replied with SOCKS version {value}, expected 5");

    internal static Socks5Exception NoAcceptableMethod()
        => new(Socks5ErrorCode.NoAcceptableAuthenticationMethod, "Proxy rejected all offered authentication methods");

    internal static Socks5Exception UnsupportedMethod(byte value)
        => new(Socks5ErrorCode.UnsupportedAuthenticationMethod, $"Proxy selected unsupported authentication method 0x{value:x2}");

    internal static Socks5Exception AuthenticationRequired()
        => new(Socks5ErrorCode.AuthenticationRequired, "Proxy requires authentication but none is configured");

    internal static Socks5Exception AuthenticationFailed()
        => new(Socks5ErrorCode.AuthenticationFailed, "Proxy rejected the credentials");

    internal static Socks5Exception CredentialTooLong()
        => new(Socks5ErrorCode.CredentialTooLong, "Username or password exceeds 255 bytes");

    internal static Socks5Exception RequestRejected(Socks5ReplyCode code)
        => new(Socks5ErrorCode.RequestRejected, $"Proxy rejected the connection: {code.Describe()}") { ReplyCode = code };

    internal static Socks5Exception UnknownReply(byte value)
        => new(Socks5ErrorCode.UnknownReplyCode, $"Proxy returned unknown reply code 0x{value:x2}");

    internal static Socks5Exception UnsupportedAddressType(byte value)
        => new(Socks5ErrorCode.UnsupportedAddressType, $"Proxy returned unsupported address type 0x{value:x2}");

    internal static Socks5Exception Incomplete()
        => new(Socks5ErrorCode.IncompleteResponse, "Proxy response was truncated");

    internal static Socks5Exception Malformed(string detail)
        => new(Socks5ErrorCode.MalformedResponse, $"Malformed proxy response: {detail}");

    internal static Socks5Exception DomainTooLong()
        => new(Socks5ErrorCode.DomainNameTooLong, "Destination hostname exceeds 255 bytes");

    internal static Socks5Exception InvalidDestination(string address)
        => new(Socks5ErrorCode.InvalidDestinationAddress, $"Invalid destination address: {address}");

    internal static Socks5Exception TimedOut()
        => new(Socks5ErrorCode.TimedOut, "Proxy handshake timed out");

    internal static Socks5Exception Cancelled()
        => new(Socks5ErrorCode.Cancelled, "Proxy connection cancelled");

    internal static Socks5Exception Transport(string detail, Exception? inner = null)
        => new(Socks5ErrorCode.TransportFailure, $"Proxy transport failure: {detail}", inner);

    internal static Socks5Exception ProtocolViolation(string detail)
        => new(Socks5ErrorCode.ProtocolViolation, $"Proxy protocol violation: {detail}");
}
