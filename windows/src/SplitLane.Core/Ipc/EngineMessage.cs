using System.Text.Json.Serialization;
using SplitLane.Core.Models;

namespace SplitLane.Core.Ipc;

/// <summary>Well-known names shared by both ends of the control channel.</summary>
public static class EngineChannel
{
    /// <summary>
    /// Named pipe the engine listens on.
    /// </summary>
    /// <remarks>
    /// The engine runs elevated and the app does not, so the pipe is the trust boundary. The engine
    /// creates it with an ACL granting the interactive user read/write and nobody else, and it
    /// refuses every message that is not one of the shapes below. There is deliberately no message
    /// that makes the engine run a command, open a path, or load a library.
    /// </remarks>
    public const string PipeName = "SplitLane.Engine.Control";

    /// <summary>Maximum bytes accepted for a single framed message.</summary>
    /// <remarks>
    /// A length prefix an attacker controls is an allocation an attacker controls. One megabyte is
    /// far beyond any real configuration and small enough that a hostile prefix cannot exhaust the
    /// elevated process.
    /// </remarks>
    public const int MaxMessageBytes = 1024 * 1024;
}

/// <summary>What the app is asking the engine to do.</summary>
public enum EngineRequestKind
{
    /// <summary>Report engine state, flow counts, and the last error.</summary>
    RequestStatus,

    /// <summary>Re-read configuration from disk and swap the runtime snapshot atomically.</summary>
    ReloadConfiguration,

    /// <summary>Apply a configuration carried in the message itself, and persist it.</summary>
    ApplyConfiguration,

    /// <summary>Verify the upstream proxy is reachable and speaks SOCKS5.</summary>
    TestProxyConnection,

    /// <summary>Reset the counters shown in the UI.</summary>
    ResetStatistics,

    /// <summary>Turn DIRECT-decision logging on or off without a configuration round-trip.</summary>
    SetDirectFlowLogging,

    /// <summary>Return recent connection events for the Activity list.</summary>
    RequestActivity,

    /// <summary>Start diverting. Idempotent.</summary>
    StartRouting,

    /// <summary>Stop diverting, leaving the engine running and inert. Idempotent.</summary>
    StopRouting,

    /// <summary>Ask the engine to look for a newer release now.</summary>
    /// <remarks>
    /// The engine looks on its own once a day; this is the button. Neither this nor
    /// <see cref="ApplyUpdate"/> carries a version, a URL or a file name - what gets installed is
    /// decided entirely by the signed manifest the engine fetched, so an unelevated caller cannot
    /// name it. The vocabulary stays a closed enum for exactly this reason.
    /// </remarks>
    CheckForUpdate,

    /// <summary>Install the release the engine has already found and verified.</summary>
    /// <remarks>
    /// Separate from checking because installing restarts the service and drops every relayed
    /// connection. The engine finds updates; the person decides when to take one.
    /// </remarks>
    ApplyUpdate,
}

/// <summary>
/// A request from the app to the engine.
/// </summary>
/// <remarks>
/// One flat shape with optional payload fields rather than a polymorphic hierarchy: the engine is
/// the elevated side of the boundary, and a flat record is something it can validate exhaustively by
/// reading it, without a converter that resolves a type name from attacker-controlled JSON.
/// </remarks>
/// <param name="Kind">What is being asked.</param>
/// <param name="Generation">
/// Configuration generation the request refers to, so the engine can ignore a reload that arrives
/// after a newer one has already been applied. Requests are not ordered with respect to file writes.
/// </param>
/// <param name="Configuration">Payload for <see cref="EngineRequestKind.ApplyConfiguration"/>.</param>
/// <param name="Enabled">Payload for <see cref="EngineRequestKind.SetDirectFlowLogging"/>.</param>
/// <param name="Limit">How many events <see cref="EngineRequestKind.RequestActivity"/> should return.</param>
public sealed record EngineRequest(
    EngineRequestKind Kind,
    ulong Generation = 0,
    RuntimeConfiguration? Configuration = null,
    bool Enabled = false,
    int Limit = 200);

/// <summary>Whether the engine did what was asked.</summary>
public enum EngineResponseKind
{
    /// <summary>Done.</summary>
    Acknowledged,

    /// <summary>Payload is <see cref="EngineResponse.Status"/>.</summary>
    Status,

    /// <summary>Payload is <see cref="EngineResponse.ProxyTest"/>.</summary>
    ProxyTestResult,

    /// <summary>Payload is <see cref="EngineResponse.Activity"/>.</summary>
    Activity,

    /// <summary>Payload is <see cref="EngineResponse.Reason"/>.</summary>
    Failure,
}

/// <summary>The engine's reply.</summary>
/// <param name="Kind">Which payload is populated.</param>
/// <param name="Status">Engine state.</param>
/// <param name="ProxyTest">Reachability result.</param>
/// <param name="Activity">Recent connections.</param>
/// <param name="Reason">Failure text, already redacted for display.</param>
public sealed record EngineResponse(
    EngineResponseKind Kind,
    EngineStatus? Status = null,
    ProxyTestResult? ProxyTest = null,
    IReadOnlyList<ConnectionEvent>? Activity = null,
    string? Reason = null)
{
    /// <summary>A bare acknowledgement.</summary>
    public static EngineResponse Ok { get; } = new(EngineResponseKind.Acknowledged);

    /// <summary>A failure with a display-safe reason.</summary>
    public static EngineResponse Failed(string reason) => new(EngineResponseKind.Failure, Reason: reason);
}

/// <summary>How the engine's divert layer is doing.</summary>
public enum DivertState
{
    /// <summary>Not started.</summary>
    Stopped,

    /// <summary>Starting: opening handles, installing the driver service.</summary>
    Starting,

    /// <summary>Diverting.</summary>
    Running,

    /// <summary>Running but not diverting, because the master switch is off.</summary>
    Paused,

    /// <summary>Failed to start, or stopped because of an error.</summary>
    Faulted,
}

/// <summary>A snapshot of what the engine is doing.</summary>
public sealed record EngineStatus
{
    /// <summary>Divert layer state.</summary>
    public DivertState State { get; init; } = DivertState.Stopped;

    /// <summary>
    /// Generation of the configuration currently in force. If this trails what the app persisted, a
    /// reload was missed.
    /// </summary>
    public ulong ConfigurationGeneration { get; init; }

    /// <summary>Master switch, as the engine currently sees it.</summary>
    public bool IsRoutingEnabled { get; init; }

    /// <summary>Number of rules that can currently route traffic.</summary>
    public int ActiveRuleCount { get; init; }

    /// <summary>TCP connections currently relayed through the proxy.</summary>
    public int ActiveProxiedFlows { get; init; }

    /// <summary>
    /// Connections left alone since start. Counted rather than enumerated: the engine sees every
    /// connection on the system, so enumerating DIRECT decisions is high-volume and low-value.
    /// </summary>
    public ulong DirectFlowCount { get; init; }

    /// <summary>Connections relayed since start.</summary>
    public ulong ProxiedFlowCount { get; init; }

    /// <summary>
    /// Selected-app UDP datagrams refused. A non-zero value here explains "the app is broken since I
    /// enabled it".
    /// </summary>
    public ulong BlockedFlowCount { get; init; }

    /// <summary>Bytes relayed application-to-upstream.</summary>
    public ulong BytesSent { get; init; }

    /// <summary>Bytes relayed upstream-to-application.</summary>
    public ulong BytesReceived { get; init; }

    /// <summary>Local port the redirector is listening on, or 0 when it is not running.</summary>
    public ushort RedirectPort { get; init; }

    /// <summary>Most recent failure, already redacted for display.</summary>
    public string? LastError { get; init; }

    /// <summary>When the engine started diverting.</summary>
    public DateTimeOffset? StartedAt { get; init; }

    /// <summary>Version of the divert driver the engine is bound to, when known.</summary>
    public string? DriverVersion { get; init; }

    /// <summary>Version of the engine itself, so the window can show what is actually running.</summary>
    public string? EngineVersion { get; init; }

    /// <summary>Where the last update check or install got to. Names an UpdateState.</summary>
    public string? UpdateState { get; init; }

    /// <summary>The release waiting to be installed, when there is one.</summary>
    public string? UpdateVersion { get; init; }

    /// <summary>A sentence about the waiting release, from its manifest.</summary>
    public string? UpdateNotes { get; init; }

    /// <summary>Why the last check or install failed, when it did.</summary>
    public string? UpdateError { get; init; }

    /// <summary>How long the engine has been diverting.</summary>
    [JsonIgnore]
    public TimeSpan? Uptime => StartedAt is { } started ? DateTimeOffset.UtcNow - started : null;
}

/// <summary>Outcome of a proxy reachability test.</summary>
/// <param name="Succeeded">Whether connect plus handshake completed.</param>
/// <param name="LatencyMilliseconds">Round-trip for connect plus handshake.</param>
/// <param name="Detail">
/// A display-safe explanation. Never contains the credential — a failed authentication reports that
/// authentication failed, not what was sent.
/// </param>
public sealed record ProxyTestResult(bool Succeeded, double? LatencyMilliseconds = null, string? Detail = null);
