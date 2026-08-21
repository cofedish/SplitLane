using System.Text.Json.Serialization;

namespace SplitLane.Core.Models;

/// <summary>
/// Schema and generation stamp carried by every configuration.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item><see cref="SchemaVersion"/> is the wire format. An engine that understands version <i>n</i>
/// <b>refuses</b> a configuration stamped <i>n+1</i> rather than guessing at fields it does not
/// know.</item>
/// <item><see cref="Generation"/> is a monotonic counter bumped on every user-visible change, used
/// to detect and discard out-of-order reload messages.</item>
/// </list>
/// </remarks>
public readonly record struct ConfigurationVersion(int SchemaVersion, ulong Generation)
    : IComparable<ConfigurationVersion>
{
    /// <summary>Wire format understood by this build.</summary>
    public const int CurrentSchema = 1;

    /// <summary>A fresh stamp at the current schema.</summary>
    public ConfigurationVersion()
        : this(CurrentSchema, 0)
    {
    }

    /// <summary>Whether an engine built against <see cref="CurrentSchema"/> can safely read this.</summary>
    [JsonIgnore]
    public bool IsReadable => SchemaVersion <= CurrentSchema;

    /// <summary>The next generation, restamped at the current schema.</summary>
    public ConfigurationVersion NextGeneration() => new(CurrentSchema, Generation + 1);

    /// <inheritdoc />
    public int CompareTo(ConfigurationVersion other)
    {
        var bySchema = SchemaVersion.CompareTo(other.SchemaVersion);
        return bySchema != 0 ? bySchema : Generation.CompareTo(other.Generation);
    }
}

/// <summary>
/// The complete, immutable configuration the engine routes against.
/// </summary>
/// <remarks>
/// The engine holds exactly one of these. Reload replaces the whole value in a single volatile
/// store; nothing is mutated in place, so a flow that started under generation <i>n</i> keeps
/// reading a coherent generation <i>n</i> for its lifetime.
/// </remarks>
public sealed record RuntimeConfiguration
{
    /// <summary>Schema and generation stamp.</summary>
    public ConfigurationVersion Version { get; init; } = new();

    /// <summary>The user's rules.</summary>
    public IReadOnlyList<AppRule> Rules { get; init; } = [];

    /// <summary>The upstream the PROXY lane points at.</summary>
    public ProxyConfiguration Proxy { get; init; } = ProxyConfiguration.Default;

    /// <summary>
    /// Master switch. When false the engine routes everything DIRECT while staying installed and
    /// running — a paused state that is honest about being paused, unlike a stopped service that
    /// merely looks the same from the outside.
    /// </summary>
    public bool IsRoutingEnabled { get; init; } = true;

    /// <summary>
    /// Whether to emit a log line for DIRECT decisions.
    /// </summary>
    /// <remarks>
    /// Off by default: the engine is consulted for every connection on the system, so logging each
    /// DIRECT decision is high volume and low value. Counters are always maintained; enumeration is
    /// the diagnostic mode.
    /// </remarks>
    public bool LogsDirectFlows { get; init; }

    /// <summary>
    /// Whether a selected application's UDP is relayed through the proxy rather than refused.
    /// </summary>
    /// <remarks>
    /// <para>
    /// On by default, because the alternative breaks things people notice. Refusing UDP was chosen
    /// so that QUIC would fail closed and fall back to TCP, which works - and does nothing for
    /// anything with no TCP path at all. Discord voice is the plain example: it sits on "Connecting
    /// to RTC" forever, because there is no second way for it to try.
    /// </para>
    /// <para>
    /// Turning this off returns to refusing, which is the safe behaviour and never the leaky one.
    /// Neither setting sends a selected application's datagrams out unproxied: a proxy that will not
    /// relay them means they are dropped, exactly as before.
    /// </para>
    /// </remarks>
    public bool ProxiesUdp { get; init; } = true;

    /// <summary>
    /// Local TCP port the redirector listens on, or 0 to pick an ephemeral port at start.
    /// </summary>
    /// <remarks>
    /// Ephemeral is the default and the better choice: a fixed port is a fixed target that any local
    /// process can connect to directly, and the redirector's original-destination table is keyed by
    /// the client's source port, so an uninvited connection has no entry and is refused. Pinning is
    /// offered anyway because firewall rules sometimes need a stable number.
    /// </remarks>
    public ushort RedirectPort { get; init; }

    /// <summary>An empty configuration. Every flow goes DIRECT.</summary>
    public static RuntimeConfiguration Empty { get; } = new();

    /// <summary>Rules currently routing to the PROXY lane.</summary>
    [JsonIgnore]
    public IEnumerable<AppRule> ProxiedRules =>
        Rules.Where(rule => rule.IsEnabled && rule.Action == RouteAction.Proxy);

    /// <summary>Returns a copy with the generation advanced.</summary>
    public RuntimeConfiguration WithNextGeneration() => this with { Version = Version.NextGeneration() };
}
