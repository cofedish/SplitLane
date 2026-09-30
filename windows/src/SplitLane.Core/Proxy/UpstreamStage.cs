namespace SplitLane.Core.Proxy;

/// <summary>
/// Where the connection to the upstream proxy had got to.
/// </summary>
/// <remarks>
/// Carried by every upstream failure, because "Timed out" on its own names no culprit: a proxy host
/// that does not resolve, a proxy that does not accept, one that accepts and never answers, and one
/// that answers a CONNECT only after its own attempt to reach the destination gave up are four
/// different problems with four different owners.
/// </remarks>
public enum UpstreamStage
{
    /// <summary>Looking up the proxy's own hostname.</summary>
    Resolve,

    /// <summary>Opening TCP to the proxy.</summary>
    TcpConnect,

    /// <summary>SOCKS5 greeting sent, waiting for the method selection.</summary>
    Greeting,

    /// <summary>Credentials, or an authentication token, sent and waiting for the verdict.</summary>
    Authentication,

    /// <summary>
    /// The tunnel request - SOCKS5 CONNECT or HTTP CONNECT - sent, waiting for the reply. For HTTP
    /// this includes the proxy's own connection to the destination.
    /// </summary>
    Connect,
}

/// <summary>Names for logs.</summary>
public static class UpstreamStageExtensions
{
    /// <summary>A stable, greppable name: <c>proxy.tcp_connect</c>, <c>proxy.auth</c>, ...</summary>
    public static string LogName(this UpstreamStage stage) => stage switch
    {
        UpstreamStage.Resolve => "proxy.resolve",
        UpstreamStage.TcpConnect => "proxy.tcp_connect",
        UpstreamStage.Greeting => "proxy.greeting",
        UpstreamStage.Authentication => "proxy.auth",
        UpstreamStage.Connect => "proxy.connect",
        _ => "proxy.unknown",
    };
}
