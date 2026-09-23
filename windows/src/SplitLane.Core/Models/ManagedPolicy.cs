namespace SplitLane.Core.Models;

/// <summary>
/// Rules and settings an administrator puts in place for a machine, which its users cannot change.
/// </summary>
/// <remarks>
/// <para>
/// Delivered as a file the engine only trusts when it is owned by, and writable only by, SYSTEM or
/// Administrators - which is what Intune, Configuration Manager or Group Policy produce when they place
/// a file. The user's own configuration is writable by any interactive user, so it cannot carry anything
/// an organisation needs to be true.
/// </para>
/// <para>
/// Managed rules name an application by identity - signer and product, package family, or file hash -
/// and never by path. That is what makes one rule mean the same application on ten thousand machines
/// with ten thousand different user profiles and install drives, and keep meaning it after every update.
/// Removing a rule from the policy revokes it on every machine at the next reload.
/// </para>
/// </remarks>
public sealed record ManagedPolicy
{
    /// <summary>Policy format understood by this build.</summary>
    public const int CurrentSchema = 1;

    /// <summary>Format of this document. A newer one is refused, not guessed at.</summary>
    public int SchemaVersion { get; init; } = CurrentSchema;

    /// <summary>
    /// Rules that take precedence over anything the user configures. Each must carry an identity; a
    /// path rule is ignored and reported.
    /// </summary>
    public IReadOnlyList<AppRule> Rules { get; init; } = [];

    /// <summary>
    /// Whether the user's own rules apply alongside the managed ones. They never override a managed
    /// rule either way.
    /// </summary>
    public bool AllowUserRules { get; init; } = true;

    /// <summary>
    /// Whether routing stays on regardless of the user's master switch, and cannot be stopped through
    /// the app.
    /// </summary>
    public bool ForceRoutingEnabled { get; init; }

    /// <summary>The upstream the proxy lane must use, replacing the user's, when set.</summary>
    public ProxyConfiguration? Proxy { get; init; }

    /// <summary>
    /// Whether the engine's own update check is off. An organisation that deploys releases itself
    /// does not want machines fetching and offering a different one.
    /// </summary>
    public bool DisableSelfUpdate { get; init; }
}
