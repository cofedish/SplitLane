using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using SplitLane.Core.Configuration;
using SplitLane.Core.Ipc;
using SplitLane.Core.Logging;
using SplitLane.Core.Models;
using SplitLane.Engine.Runtime;

namespace SplitLane.Engine.Ipc;

/// <summary>
/// The control channel: a named pipe the app talks to the elevated engine over.
/// </summary>
/// <remarks>
/// <para>
/// This is the trust boundary of the whole product. The engine runs with administrative rights; the
/// app does not, and should not. Everything the app can make the engine do is enumerated by
/// <see cref="EngineRequestKind"/>, and there is deliberately no member that names a file to open, a
/// command to run, or a library to load.
/// </para>
/// <para>
/// The pipe's ACL grants the interactive user and administrators, and nobody else. Without an
/// explicit ACL a named pipe created by a service is reachable by every account on the machine,
/// which would let any local user reconfigure the proxy or read the rule set.
/// </para>
/// <para>
/// Messages are length-prefixed, and the prefix is bounded before a single byte is allocated. A
/// length an unprivileged caller controls is an allocation an unprivileged caller controls.
/// </para>
/// </remarks>
public sealed class ControlServer : IAsyncDisposable
{
    private const string LogCategory = "ipc";

    private readonly EngineRuntime _runtime;
    private readonly ConfigurationStore _store;
    private readonly CancellationTokenSource _stopping = new();
    private Task? _loop;

    /// <summary>Builds a server over a runtime.</summary>
    public ControlServer(EngineRuntime runtime, ConfigurationStore store)
    {
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    /// <summary>Starts accepting connections.</summary>
    public void Start()
    {
        _loop ??= Task.Run(() => AcceptLoopAsync(_stopping.Token));
        SplitLaneLog.Info(LogCategory, $"control channel listening on \\\\.\\pipe\\{EngineChannel.PipeName}");
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        NamedPipeServerStream? pipe = null;

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    // The first instance claims the name, or fails if someone else already holds it
                    // (SL-SEC-010). After that a listening instance always exists: the next one is
                    // created before the one just connected is served and closed, so the name is never
                    // free for another process to take while the engine runs.
                    pipe ??= await CreateFirstPipeAsync(cancellationToken).ConfigureAwait(false);
                    await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);

                    var connected = pipe;
                    pipe = CreatePipe(firstInstance: false);

                    try
                    {
                        // One request per connection. A long-lived multiplexed session would need its
                        // own framing state machine on the elevated side, and the app polls rarely
                        // enough that the extra connection costs nothing worth optimising.
                        await ServeAsync(connected, cancellationToken).ConfigureAwait(false);
                    }
                    finally
                    {
                        await connected.DisposeAsync().ConfigureAwait(false);
                    }
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (IOException ex)
                {
                    SplitLaneLog.Debug(LogCategory, $"client disconnected: {ex.Message}");
                }
                catch (Exception ex)
                {
                    SplitLaneLog.Error(LogCategory, "control channel error", ex);
                }
            }
        }
        finally
        {
            if (pipe is not null)
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    /// <summary>Claims the pipe name, retrying while another process holds it.</summary>
    private static async Task<NamedPipeServerStream> CreateFirstPipeAsync(CancellationToken cancellationToken)
    {
        var reported = false;

        while (true)
        {
            try
            {
                return CreatePipe(firstInstance: true);
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
            {
                if (!reported)
                {
                    // Not a transient error to swallow: something else is answering as the engine. The
                    // window refuses to talk to it (it is not owned by SYSTEM), so it is visible there
                    // too, but this is where the cause is named.
                    SplitLaneLog.Error(
                        LogCategory,
                        $"the control channel name is held by another process ({ex.Message}); retrying");
                    reported = true;
                }

                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static NamedPipeServerStream CreatePipe(bool firstInstance)
    {
        var security = new PipeSecurity();

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            EngineChannel.PipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            firstInstance ? PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance : PipeOptions.Asynchronous,
            inBufferSize: 0,
            outBufferSize: 0,
            security);
    }

    private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken cancellationToken)
    {
        var payload = await ReadFrameAsync(pipe, cancellationToken).ConfigureAwait(false);
        if (payload is null)
        {
            return;
        }

        EngineResponse response;

        try
        {
            var request = JsonSerializer.Deserialize<EngineRequest>(payload, ConfigurationCodec.Options);
            response = request is null
                ? EngineResponse.Failed("Empty request")
                : await HandleAsync(request, Interop.ProcessSessions.OfClient(pipe), cancellationToken).ConfigureAwait(false);
        }
        catch (JsonException ex)
        {
            response = EngineResponse.Failed($"Malformed request: {ex.Message}");
        }
        catch (ConfigurationValidationException ex)
        {
            response = EngineResponse.Failed(ex.Message);
        }
        catch (Exception ex)
        {
            SplitLaneLog.Error(LogCategory, "request failed", ex);
            response = EngineResponse.Failed(ex.Message);
        }

        await WriteFrameAsync(pipe, JsonSerializer.SerializeToUtf8Bytes(response, ConfigurationCodec.Options), cancellationToken)
            .ConfigureAwait(false);

        await pipe.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<EngineResponse> HandleAsync(EngineRequest request, uint? callerSession, CancellationToken cancellationToken)
    {
        switch (request.Kind)
        {
            case EngineRequestKind.RequestStatus:
                return new EngineResponse(EngineResponseKind.Status, Status: _runtime.Status());

            case EngineRequestKind.RequestActivity:
                // The control channel is open to every interactive user; each sees the connections of
                // their own session, not what other people on the machine are doing (SL-SEC-018).
                return new EngineResponse(
                    EngineResponseKind.Activity,
                    Activity: ForSession(_runtime.Activity(Math.Clamp(request.Limit, 1, 1000)), callerSession));

            case EngineRequestKind.ReloadConfiguration:
                // An out-of-order reload is discarded rather than applied. Requests are not ordered
                // with respect to the file write that produced them.
                if (request.Generation != 0 &&
                    request.Generation < _runtime.Configuration.Version.Generation)
                {
                    SplitLaneLog.Debug(
                        LogCategory,
                        $"ignoring stale reload for generation {request.Generation}");
                    return EngineResponse.Ok;
                }

                _runtime.LoadConfiguration();
                return EngineResponse.Ok;

            case EngineRequestKind.ApplyConfiguration:
                if (request.Configuration is null)
                {
                    return EngineResponse.Failed("ApplyConfiguration carried no configuration");
                }

                _runtime.Save(request.Configuration);
                return EngineResponse.Ok;

            case EngineRequestKind.TestProxyConnection:
                var result = await _runtime.TestProxyAsync(cancellationToken).ConfigureAwait(false);
                return new EngineResponse(EngineResponseKind.ProxyTestResult, ProxyTest: result);

            case EngineRequestKind.ResetStatistics:
                _runtime.ResetStatistics();
                return EngineResponse.Ok;

            case EngineRequestKind.SetDirectFlowLogging:
                _runtime.SetDirectFlowLogging(request.Enabled);
                return EngineResponse.Ok;

            case EngineRequestKind.StartRouting:
                await _runtime.StartAsync().ConfigureAwait(false);
                return EngineResponse.Ok;

            case EngineRequestKind.StopRouting:
                // The control channel is open to every interactive user. When the organisation's
                // policy says routing stays on, a request from that channel is not the organisation.
                if (_runtime.IsRoutingLockedByPolicy)
                {
                    return EngineResponse.Failed(
                        "Routing is required by your organisation's policy and cannot be stopped from here.");
                }

                await _runtime.StopAsync().ConfigureAwait(false);
                return EngineResponse.Ok;

            case EngineRequestKind.CheckForUpdate:
                await _runtime.Updates.CheckAsync().ConfigureAwait(false);
                return EngineResponse.Ok;

            case EngineRequestKind.ApplyUpdate:
                // Nothing from the request reaches this. What gets installed was decided by a
                // manifest the engine fetched and verified against the release key; the caller is
                // only choosing when.
                //
                // Kept open to interactive users on purpose: the window that offers the update runs
                // unelevated, and the only effect a caller has is "install the official release now"
                // (a service restart). Choosing *what* is installed is impossible from here, and
                // changing the package between verification and msiexec is closed separately by
                // UpdateStaging (SL-SEC-001). A managed policy can still turn self-update off.
                return await _runtime.Updates.ApplyAsync().ConfigureAwait(false)
                    ? EngineResponse.Ok
                    : EngineResponse.Failed(_runtime.Updates.LastError ?? "the update could not be applied");

            case EngineRequestKind.SetProxyCredential:
                if (request.ProxyCredential is not { } credential)
                {
                    return EngineResponse.Failed("SetProxyCredential carried no credential");
                }

                if (!ProxyCredentialAcceptable(credential, out var refusal))
                {
                    return EngineResponse.Failed(refusal);
                }

                // Bound to exactly what was entered for; used only while that is the proxy in force.
                _runtime.SetProxyCredential(
                    new ProxyCredentialBinding(credential.Type, credential.Host.Trim(), credential.Port, credential.Username.Trim()),
                    credential.Password,
                    credential.AllowPlaintextBasic);
                return EngineResponse.Ok;

            case EngineRequestKind.ClearProxyCredential:
                _runtime.ClearProxyCredential();
                return EngineResponse.Ok;

            default:
                return EngineResponse.Failed($"Unsupported request {request.Kind}");
        }
    }

    /// <summary>
    /// The events a caller in a session may see: those of processes in the same session. An unknown
    /// caller session, or an event whose session is unknown, shows nothing.
    /// </summary>
    internal static IReadOnlyList<ConnectionEvent> ForSession(IReadOnlyList<ConnectionEvent> events, uint? session) =>
        session is { } caller ? [.. events.Where(e => e.SessionId == caller)] : [];

    /// <summary>Checks a credential before the service stores it. The message never names the password.</summary>
    internal static bool ProxyCredentialAcceptable(ProxyCredentialUpdate credential, out string refusal)
    {
        refusal = string.Empty;

        if (!Enum.IsDefined(credential.Type) || credential.Port == 0)
        {
            refusal = "the credential names no valid proxy";
        }
        else if (string.IsNullOrWhiteSpace(credential.Host) || credential.Host.Length > 253 ||
                 credential.Host.Any(char.IsControl))
        {
            refusal = "the credential names no valid proxy host";
        }
        else if (string.IsNullOrWhiteSpace(credential.Username) || credential.Username.Length > 256 ||
                 credential.Username.Any(char.IsControl))
        {
            refusal = "the credential names no valid account";
        }
        else if (credential.Password is not { Length: > 0 and <= ProxyCredentialStore.MaxPasswordLength } ||
                 credential.Password.Contains('\0', StringComparison.Ordinal))
        {
            refusal = "the password is empty or too long";
        }

        return refusal.Length == 0;
    }

    /// <summary>Reads one length-prefixed frame, or null when the peer went away.</summary>
    internal static async Task<byte[]?> ReadFrameAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        if (!await ReadExactlyAsync(stream, header, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);

        // Bound before allocating. This is the only place an unprivileged caller influences an
        // allocation in the elevated process.
        if (length <= 0 || length > EngineChannel.MaxMessageBytes)
        {
            throw new IOException($"Frame length {length} is out of range");
        }

        var payload = new byte[length];
        return await ReadExactlyAsync(stream, payload, cancellationToken).ConfigureAwait(false) ? payload : null;
    }

    /// <summary>Writes one length-prefixed frame.</summary>
    internal static async Task WriteFrameAsync(Stream stream, byte[] payload, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);

        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<bool> ReadExactlyAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return false;
            }

            offset += read;
        }

        return true;
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await _stopping.CancelAsync().ConfigureAwait(false);

        if (_loop is not null)
        {
            try
            {
                await _loop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }

            _loop = null;
        }

        _stopping.Dispose();
    }
}
