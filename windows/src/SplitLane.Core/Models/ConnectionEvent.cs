using System.Text.Json.Serialization;
using SplitLane.Core.Proxy.Socks5;
using SplitLane.Core.Rules;

namespace SplitLane.Core.Models;

/// <summary>Lifecycle state of a single connection.</summary>
public enum ConnectionState
{
    /// <summary>Decision made, upstream handshake not finished.</summary>
    Connecting = 0,

    /// <summary>Relaying.</summary>
    Active = 1,

    /// <summary>Finished normally.</summary>
    Closed = 2,

    /// <summary>
    /// Ended with an error. For a selected application this means the connection failed rather than
    /// fell back — fail-closed (ADR 0003).
    /// </summary>
    Failed = 3,

    /// <summary>Refused before it began: selected-app UDP.</summary>
    Blocked = 4,
}

/// <summary>
/// Error categories shown in the Activity list.
/// </summary>
/// <remarks>
/// A closed vocabulary rather than free text, so the UI can group and explain failures instead of
/// echoing a message. The categories map onto distinct user actions: start the proxy, fix the
/// credentials, or accept that this app cannot be proxied yet.
/// </remarks>
public enum ConnectionErrorCategory
{
    /// <summary>The upstream did not answer.</summary>
    UpstreamUnreachable = 0,

    /// <summary>The upstream rejected the credentials.</summary>
    AuthenticationFailed = 1,

    /// <summary>No shared authentication method.</summary>
    AuthenticationUnsupported = 2,

    /// <summary>The upstream refused the destination.</summary>
    RejectedByProxy = 3,

    /// <summary>Connect plus handshake exceeded the timeout.</summary>
    TimedOut = 4,

    /// <summary>Selected-app UDP, refused by design.</summary>
    UdpNotSupported = 5,

    /// <summary>The client side of the relay failed.</summary>
    FlowError = 6,

    /// <summary>The engine is stopping, or the flow was closed.</summary>
    Cancelled = 7,

    /// <summary>A bug, or a protocol violation by the upstream.</summary>
    InternalError = 8,
}

/// <summary>Human-readable text for the closed error vocabulary.</summary>
public static class ConnectionErrorCategoryExtensions
{
    /// <summary>One line the UI can show verbatim.</summary>
    public static string Describe(this ConnectionErrorCategory category) => category switch
    {
        ConnectionErrorCategory.UpstreamUnreachable => "Proxy unreachable",
        ConnectionErrorCategory.AuthenticationFailed => "Proxy rejected credentials",
        ConnectionErrorCategory.AuthenticationUnsupported => "No shared authentication method",
        ConnectionErrorCategory.RejectedByProxy => "Proxy refused the connection",
        ConnectionErrorCategory.TimedOut => "Timed out",
        ConnectionErrorCategory.UdpNotSupported => "UDP is not proxied yet — connection refused",
        ConnectionErrorCategory.FlowError => "Flow error",
        ConnectionErrorCategory.Cancelled => "Cancelled",
        ConnectionErrorCategory.InternalError => "Internal error",
        _ => "Unknown error",
    };

    /// <summary>Maps a SOCKS5 failure onto a user-facing category.</summary>
    public static ConnectionErrorCategory ToCategory(this Socks5ErrorCode code) => code switch
    {
        Socks5ErrorCode.TransportFailure or Socks5ErrorCode.IncompleteResponse
            => ConnectionErrorCategory.UpstreamUnreachable,
        Socks5ErrorCode.AuthenticationFailed or Socks5ErrorCode.CredentialTooLong
            => ConnectionErrorCategory.AuthenticationFailed,
        Socks5ErrorCode.NoAcceptableAuthenticationMethod
            or Socks5ErrorCode.UnsupportedAuthenticationMethod
            or Socks5ErrorCode.AuthenticationRequired
            => ConnectionErrorCategory.AuthenticationUnsupported,
        Socks5ErrorCode.RequestRejected or Socks5ErrorCode.UnknownReplyCode
            => ConnectionErrorCategory.RejectedByProxy,
        Socks5ErrorCode.TimedOut => ConnectionErrorCategory.TimedOut,
        Socks5ErrorCode.Cancelled => ConnectionErrorCategory.Cancelled,
        _ => ConnectionErrorCategory.InternalError,
    };
}

/// <summary>
/// One connection, as shown in Activity.
/// </summary>
/// <remarks>
/// Metadata only. No payload is ever captured, and there is nowhere in this type to put any — which
/// is deliberate, because "we only log a little of the traffic" is not a property that survives
/// contact with a feature request.
/// </remarks>
public sealed record ConnectionEvent
{
    /// <summary>Stable identity.</summary>
    public Guid Id { get; init; } = Guid.NewGuid();

    /// <summary>When the decision was made.</summary>
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;

    /// <summary>Display name of the source app when a rule matched it; null for unattributed flows.</summary>
    public string? ApplicationName { get; init; }

    /// <summary>
    /// The executable path the flow actually carried.
    /// </summary>
    /// <remarks>
    /// Worth showing verbatim: for a family match this is the helper or updater, not the executable
    /// the user picked, and seeing that is what explains family matching (ADR W-0003).
    /// </remarks>
    public required string ExecutablePath { get; init; }

    /// <summary>Owning process id at decision time. Diagnostic.</summary>
    public uint ProcessId { get; init; }

    /// <summary>Hostname when the DNS observer knew one, otherwise the IP literal.</summary>
    public required string DestinationHost { get; init; }

    /// <summary>Remote port.</summary>
    public ushort DestinationPort { get; init; }

    /// <summary>TCP or UDP.</summary>
    public FlowProtocol Protocol { get; init; }

    /// <summary>The lane the flow was put in.</summary>
    public RouteAction Route { get; init; }

    /// <summary>Why. Shown as a tooltip in the Activity list.</summary>
    public string? Reason { get; init; }

    /// <summary>Lifecycle state.</summary>
    public ConnectionState State { get; init; } = ConnectionState.Connecting;

    /// <summary>Bytes relayed from the application to the upstream.</summary>
    public ulong BytesSent { get; init; }

    /// <summary>Bytes relayed from the upstream to the application.</summary>
    public ulong BytesReceived { get; init; }

    /// <summary>Set when the connection ended badly.</summary>
    public ConnectionErrorCategory? Error { get; init; }

    /// <summary>Set when the connection reaches a terminal state.</summary>
    public TimeSpan? Duration { get; init; }

    /// <summary>Printable <c>host:port</c>, bracketing IPv6.</summary>
    [JsonIgnore]
    public string DestinationDisplay =>
        DestinationHost.Contains(':') ? $"[{DestinationHost}]:{DestinationPort}" : $"{DestinationHost}:{DestinationPort}";

    /// <summary>Whether the connection has finished, one way or another.</summary>
    [JsonIgnore]
    public bool IsTerminal => State is ConnectionState.Closed or ConnectionState.Failed or ConnectionState.Blocked;
}
