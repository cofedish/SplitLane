using System.Text.Json.Serialization;
using SplitLane.Core.Rules;

namespace SplitLane.Core.Models;

/// <summary>
/// Upstream proxy protocol. Only SOCKS5 is implemented; the enum exists so that adding HTTP CONNECT
/// later does not require reshaping stored configuration.
/// </summary>
public enum ProxyProtocolType
{
    /// <summary>SOCKS5, RFC 1928.</summary>
    Socks5 = 0,
}

/// <summary>Where the upstream proxy lives.</summary>
public sealed record ProxyEndpoint
{
    /// <summary>Hostname or IP literal.</summary>
    public required string Host { get; init; }

    /// <summary>TCP port.</summary>
    public required ushort Port { get; init; }

    /// <summary>SplitLane's first target: a local SOCKS5 listener.</summary>
    public static ProxyEndpoint LocalSocks5 { get; } = new() { Host = "127.0.0.1", Port = 10808 };

    /// <summary>
    /// True when the endpoint is on this machine. Used to decide whether plaintext SOCKS5
    /// username/password authentication is a real exposure or a non-issue.
    /// </summary>
    [JsonIgnore]
    public bool IsLoopback => NetworkAddress.IsLoopbackHost(Host);

    /// <summary>Printable <c>host:port</c>, bracketing IPv6.</summary>
    [JsonIgnore]
    public string DisplayString => Host.Contains(':') ? $"[{Host}]:{Port}" : $"{Host}:{Port}";
}

/// <summary>
/// Reference to the proxy credential, which is stored apart from the configuration.
/// </summary>
/// <remarks>
/// <para>
/// This type carries <b>no secret material</b>, only a username, and that is the whole point.
/// Configuration is a JSON file under <c>%ProgramData%\SplitLane</c> that every local user can read;
/// a password in it would be a password on disk in the clear.
/// <c>ConfigurationTests.EncodedConfigurationNeverContainsSecrets</c> enforces that no serialised
/// configuration ever contains one.
/// </para>
/// <para>
/// The password lives in <c>%ProgramData%\SplitLane\credential.bin</c>, a DPAPI blob with
/// <c>LocalMachine</c> scope. That makes it meaningless on another machine, not private on this one:
/// any process here that can read the file can decrypt it, and no code sets an ACL on it - it has
/// whatever permissions it inherits from the folder (THREAT_MODEL W-9).
/// </para>
/// </remarks>
public sealed record CredentialReference
{
    /// <summary>The SOCKS5 username. Not a secret.</summary>
    public required string Username { get; init; }

    /// <summary>
    /// Opaque key meant to name the protected blob that holds the password.
    /// </summary>
    /// <remarks>
    /// Written by the app and not read by the engine, which always takes the password from
    /// <c>credential.bin</c> when a username is present. Nothing depends on its value.
    /// </remarks>
    public string? SecretKey { get; init; }
}

/// <summary>The upstream proxy the PROXY lane points at.</summary>
public sealed record ProxyConfiguration
{
    /// <summary>Stable identity.</summary>
    public Guid Id { get; init; } = Guid.NewGuid();

    /// <summary>User-facing name.</summary>
    public string DisplayName { get; init; } = "Local SOCKS5";

    /// <summary>Protocol spoken to the upstream.</summary>
    public ProxyProtocolType Type { get; init; } = ProxyProtocolType.Socks5;

    /// <summary>Where it lives.</summary>
    public ProxyEndpoint Endpoint { get; init; } = ProxyEndpoint.LocalSocks5;

    /// <summary>Null when the proxy needs no authentication.</summary>
    public CredentialReference? Credential { get; init; }

    /// <summary>Whether this proxy definition is usable.</summary>
    public bool IsEnabled { get; init; } = true;

    /// <summary>Milliseconds allowed for TCP connect plus the full SOCKS5 handshake.</summary>
    public int HandshakeTimeoutMilliseconds { get; init; } = 10_000;

    /// <summary>
    /// Reserved for letting a selected application whose flow cannot be proxied fall back to DIRECT
    /// instead of failing. Not implemented.
    /// </summary>
    /// <remarks>
    /// <b>Defaults to false, has no UI, and is not read by the engine.</b> A selected application's
    /// connection that cannot be proxied fails whatever this says. Silent fallback turns a visible
    /// error into an invisible leak, which is the exact failure this product exists to prevent
    /// (ADR 0003). The field exists so that a future opt-in would be a deliberate, documented
    /// downgrade rather than a retrofit; nothing implements it today.
    /// </remarks>
    public bool AllowDirectFallback { get; init; }

    /// <summary>
    /// Whether to send <c>ATYP=DOMAIN</c> when the DNS observer knows a name for the destination.
    /// </summary>
    /// <remarks>
    /// On by default. Sending the IP the client already resolved locally pins the connection to
    /// whatever the local resolver returned, which for a CDN means the upstream connects to an edge
    /// node chosen for the client's location rather than its own.
    /// </remarks>
    public bool PreferHostnames { get; init; } = true;

    /// <summary>Whether authentication is configured.</summary>
    [JsonIgnore]
    public bool RequiresAuthentication => Credential is not null;

    /// <summary>
    /// True when credentials would cross a real network in the clear. RFC 1929 sends the username
    /// and password unencrypted, which is irrelevant on loopback and not irrelevant anywhere else.
    /// </summary>
    [JsonIgnore]
    public bool HasPlaintextCredentialExposure => RequiresAuthentication && !Endpoint.IsLoopback;

    /// <summary>The MVP default: SOCKS5 on 127.0.0.1:10808, no auth, fail closed.</summary>
    public static ProxyConfiguration Default { get; } = new();
}
