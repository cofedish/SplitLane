using System.Buffers.Binary;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using SplitLane.Core.Configuration;
using SplitLane.Core.Ipc;
using SplitLane.Core.Logging;
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
        while (!cancellationToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;

            try
            {
                pipe = CreatePipe();
                await pipe.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);

                // One request per connection. A long-lived multiplexed session would need its own
                // framing state machine on the elevated side, and the app polls rarely enough that
                // the extra connection costs nothing worth optimising.
                await ServeAsync(pipe, cancellationToken).ConfigureAwait(false);
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
            finally
            {
                if (pipe is not null)
                {
                    await pipe.DisposeAsync().ConfigureAwait(false);
                }
            }
        }
    }

    private static NamedPipeServerStream CreatePipe()
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
            PipeOptions.Asynchronous,
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
                : await HandleAsync(request, cancellationToken).ConfigureAwait(false);
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

    private async Task<EngineResponse> HandleAsync(EngineRequest request, CancellationToken cancellationToken)
    {
        switch (request.Kind)
        {
            case EngineRequestKind.RequestStatus:
                return new EngineResponse(EngineResponseKind.Status, Status: _runtime.Status());

            case EngineRequestKind.RequestActivity:
                return new EngineResponse(
                    EngineResponseKind.Activity,
                    Activity: _runtime.Activity(Math.Clamp(request.Limit, 1, 1000)));

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
                return await _runtime.Updates.ApplyAsync().ConfigureAwait(false)
                    ? EngineResponse.Ok
                    : EngineResponse.Failed(_runtime.Updates.LastError ?? "the update could not be applied");

            default:
                return EngineResponse.Failed($"Unsupported request {request.Kind}");
        }
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
