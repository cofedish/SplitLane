namespace SplitLane.Core.Rules;

/// <summary>
/// Transport of a flow.
/// </summary>
public enum FlowProtocol
{
    /// <summary>TCP.</summary>
    Tcp = 6,

    /// <summary>UDP.</summary>
    Udp = 17,
}

/// <summary>
/// The facts about a flow that the routing decision depends on.
/// </summary>
/// <remarks>
/// A plain value with no WinDivert types in it, which is what lets <see cref="RuleEngine"/> be
/// exercised exhaustively by <c>dotnet test</c> with no driver installed, no elevation, and no
/// network. The engine builds one of these from a socket-layer event and hands it over; that
/// translation is the only divert-aware code in the routing path.
/// </remarks>
/// <param name="ProcessId">
/// Owning process id from the socket-layer event. Diagnostic — routing never keys on it, because a
/// pid is reused within seconds and means nothing across a restart.
/// </param>
/// <param name="ExecutablePath">
/// Normalised image path of the owning process. The routing key. Empty when the process exited
/// before it could be resolved, or when it could not be opened at all, both of which route DIRECT.
/// </param>
/// <param name="RemoteAddress">Remote IP literal. Always known on Windows: the socket layer reports the address the process asked to connect to.</param>
/// <param name="RemotePort">Remote port, host byte order.</param>
/// <param name="Protocol">TCP or UDP.</param>
/// <param name="RemoteHostname">
/// Hostname the destination address was most recently resolved from, when the DNS observer saw the
/// answer. Null otherwise, and null is the common case for an address the application had cached.
/// Used only to prefer <c>ATYP=DOMAIN</c> in the SOCKS5 request; never used for routing, because a
/// name is what the application asked for rather than where the packet goes.
/// </param>
/// <param name="IsEngineTraffic">
/// True when the flow belongs to the SplitLane engine itself. First layer of proxy-loop defence.
/// </param>
public readonly record struct FlowDescriptor(
    uint ProcessId,
    string ExecutablePath,
    string? RemoteAddress,
    ushort RemotePort,
    FlowProtocol Protocol,
    string? RemoteHostname = null,
    bool IsEngineTraffic = false)
{
    /// <summary>
    /// True when the destination is on this machine or this link.
    /// </summary>
    /// <remarks>
    /// The address is checked first because it is authoritative; the hostname is consulted only when
    /// no address is available, which on Windows should never happen and is handled anyway.
    /// </remarks>
    public bool HasLocalDestination
    {
        get
        {
            if (!string.IsNullOrEmpty(RemoteAddress))
            {
                return NetworkAddress.IsLocalDestination(RemoteAddress);
            }

            return RemoteHostname is not null && NetworkAddress.IsLoopbackHost(RemoteHostname);
        }
    }

    /// <summary>Hostname when one is known, otherwise the IP literal. For display and for SOCKS5.</summary>
    public string DestinationHost =>
        !string.IsNullOrEmpty(RemoteHostname) ? RemoteHostname : RemoteAddress ?? string.Empty;

    /// <summary>Printable <c>host:port</c>, bracketing IPv6.</summary>
    public string DestinationDisplay =>
        DestinationHost.Contains(':') ? $"[{DestinationHost}]:{RemotePort}" : $"{DestinationHost}:{RemotePort}";
}
