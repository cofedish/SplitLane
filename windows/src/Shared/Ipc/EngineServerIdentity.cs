using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SplitLane.Platform;

/// <summary>
/// Decides whether the other end of the control pipe is the SplitLane service (SL-SEC-010).
/// </summary>
/// <remarks>
/// <para>
/// The pipe's ACL protects the engine from the wrong clients. Nothing protected the window from the
/// wrong server: a pipe name is first come, first served, and while the engine is not listening - the
/// service stopped, restarting after a crash, or replaced during an update - any local account can
/// create <c>SplitLane.Engine.Control</c> and receive what the window sends, answer with whatever it
/// likes, and, with the client's default impersonation level, act as the user who connected.
/// </para>
/// <para>
/// The check is the pipe object's owner. Whoever creates a pipe owns it, and an account without
/// administrative privileges cannot make an object owned by LocalSystem or Administrators. The service
/// runs as LocalSystem; an engine run by hand from an elevated prompt creates the pipe owned by
/// Administrators. Nothing else is accepted. The owner is read from the connected handle, so what is
/// judged is what is talked to.
/// </para>
/// <para>
/// The client also connects at the Identification impersonation level, so even a server that has not
/// been rejected yet - the check runs after the connection is made - can learn who connected but cannot
/// act as them.
/// </para>
/// </remarks>
internal static class EngineServerIdentity
{
    private static readonly string[] Trusted =
    [
        "S-1-5-18",     // LocalSystem
        "S-1-5-32-544", // BUILTIN\Administrators
    ];

    /// <summary>The impersonation level every engine client connects with.</summary>
    public const System.Security.Principal.TokenImpersonationLevel ClientImpersonation =
        System.Security.Principal.TokenImpersonationLevel.Identification;

    /// <summary>
    /// Connects to the engine's control pipe and proves the other end is the service before anything
    /// is sent.
    /// </summary>
    /// <returns>
    /// The connected pipe, or a refusal when the other end is not the engine (the pipe is then
    /// already closed). Throws <see cref="TimeoutException"/> when nothing is listening.
    /// </returns>
    public static Task<(NamedPipeClientStream? Pipe, string? Refusal)> ConnectAsync(
        string pipeName, int timeoutMilliseconds, CancellationToken cancellationToken) =>
        ConnectAsync(pipeName, timeoutMilliseconds, Trusted, cancellationToken);

    /// <summary>The same, against an explicit set of trusted owners. Tests name their own account.</summary>
    internal static async Task<(NamedPipeClientStream? Pipe, string? Refusal)> ConnectAsync(
        string pipeName,
        int timeoutMilliseconds,
        IReadOnlyCollection<string> trustedOwners,
        CancellationToken cancellationToken)
    {
        var pipe = new NamedPipeClientStream(
            ".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous, ClientImpersonation);

        try
        {
            await pipe.ConnectAsync(timeoutMilliseconds, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        if (Problem(pipe, trustedOwners) is { } refusal)
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            return (null, refusal);
        }

        return (pipe, null);
    }

    /// <summary>Why the server end of a connected pipe is not the engine, or null when it is.</summary>
    public static string? Problem(PipeStream pipe) => Problem(pipe, Trusted);

    /// <summary>The same check against an explicit set of trusted owners. Tests name their own account.</summary>
    internal static string? Problem(PipeStream pipe, IReadOnlyCollection<string> trustedOwners)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        ArgumentNullException.ThrowIfNull(trustedOwners);

        string owner;

        try
        {
            owner = pipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier))?.Value ?? string.Empty;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidOperationException or IOException)
        {
            return $"the owner of the control channel could not be read ({ex.Message})";
        }

        return trustedOwners.Contains(owner, StringComparer.OrdinalIgnoreCase)
            ? null
            : $"the control channel is owned by {owner}, not by the SplitLane service";
    }
}
