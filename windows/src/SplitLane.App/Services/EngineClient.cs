using System.Buffers.Binary;
using System.IO;
using System.IO.Pipes;
using System.Text.Json;
using SplitLane.Core.Configuration;
using SplitLane.Core.Ipc;
using SplitLane.Core.Models;

namespace SplitLane.App.Services;

/// <summary>Whether the engine answered, and what it said.</summary>
/// <param name="Connected">False when the engine is not running at all.</param>
/// <param name="Response">The reply, when there was one.</param>
/// <param name="Error">A display-safe explanation when there was not.</param>
public readonly record struct EngineReply(bool Connected, EngineResponse? Response = null, string? Error = null)
{
    /// <summary>True when the engine answered without reporting a failure.</summary>
    public bool Succeeded => Connected && Response is not null && Response.Kind != EngineResponseKind.Failure;

    /// <summary>The best single line to show the user about this exchange.</summary>
    public string? Message => Error ?? Response?.Reason;
}

/// <summary>
/// The app's end of the control channel.
/// </summary>
/// <remarks>
/// <para>
/// Every call is allowed to fail with "the engine is not running", and that is treated as an ordinary
/// state rather than an error. It is the normal state on a machine where the user has not started the
/// elevated engine yet, and an app that threw a dialog at it would be unusable at exactly the moment
/// the user most needs to be told what to do.
/// </para>
/// <para>
/// A short connect timeout matters for the same reason: the UI polls status, and a poll that blocks
/// for the default pipe timeout would freeze the window every second on a machine with no engine.
/// </para>
/// </remarks>
public sealed class EngineClient
{
    private const int ConnectTimeoutMilliseconds = 400;

    /// <summary>Asks the engine for its status.</summary>
    public Task<EngineReply> StatusAsync(CancellationToken cancellationToken = default)
        => SendAsync(new EngineRequest(EngineRequestKind.RequestStatus), cancellationToken);

    /// <summary>Asks for the recent connection list.</summary>
    public Task<EngineReply> ActivityAsync(int limit, CancellationToken cancellationToken = default)
        => SendAsync(new EngineRequest(EngineRequestKind.RequestActivity, Limit: limit), cancellationToken);

    /// <summary>Tells the engine that the configuration file changed.</summary>
    public Task<EngineReply> ReloadAsync(ulong generation, CancellationToken cancellationToken = default)
        => SendAsync(new EngineRequest(EngineRequestKind.ReloadConfiguration, generation), cancellationToken);

    /// <summary>Hands the engine a configuration to persist and apply.</summary>
    public Task<EngineReply> ApplyAsync(RuntimeConfiguration configuration, CancellationToken cancellationToken = default)
        => SendAsync(
            new EngineRequest(EngineRequestKind.ApplyConfiguration, configuration.Version.Generation, configuration),
            cancellationToken);

    /// <summary>Asks the engine to verify the upstream proxy.</summary>
    public Task<EngineReply> TestProxyAsync(CancellationToken cancellationToken = default)
        => SendAsync(new EngineRequest(EngineRequestKind.TestProxyConnection), cancellationToken);

    /// <summary>Zeroes the counters.</summary>
    public Task<EngineReply> ResetStatisticsAsync(CancellationToken cancellationToken = default)
        => SendAsync(new EngineRequest(EngineRequestKind.ResetStatistics), cancellationToken);

    /// <summary>Turns DIRECT-decision logging on or off.</summary>
    public Task<EngineReply> SetDirectLoggingAsync(bool enabled, CancellationToken cancellationToken = default)
        => SendAsync(new EngineRequest(EngineRequestKind.SetDirectFlowLogging, Enabled: enabled), cancellationToken);

    /// <summary>Starts routing.</summary>
    public Task<EngineReply> StartRoutingAsync(CancellationToken cancellationToken = default)
        => SendAsync(new EngineRequest(EngineRequestKind.StartRouting), cancellationToken);

    /// <summary>Stops routing.</summary>
    public Task<EngineReply> StopRoutingAsync(CancellationToken cancellationToken = default)
        => SendAsync(new EngineRequest(EngineRequestKind.StopRouting), cancellationToken);

    private static async Task<EngineReply> SendAsync(EngineRequest request, CancellationToken cancellationToken)
    {
        try
        {
            await using var pipe = new NamedPipeClientStream(
                ".", EngineChannel.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

            try
            {
                await pipe.ConnectAsync(ConnectTimeoutMilliseconds, cancellationToken).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                return new EngineReply(false, Error: "The SplitLane engine is not running.");
            }

            var payload = JsonSerializer.SerializeToUtf8Bytes(request, ConfigurationCodec.Options);
            await WriteFrameAsync(pipe, payload, cancellationToken).ConfigureAwait(false);

            var replyBytes = await ReadFrameAsync(pipe, cancellationToken).ConfigureAwait(false);
            if (replyBytes is null)
            {
                return new EngineReply(true, Error: "The engine closed the connection without replying.");
            }

            var response = JsonSerializer.Deserialize<EngineResponse>(replyBytes, ConfigurationCodec.Options);
            return new EngineReply(true, response);
        }
        catch (OperationCanceledException)
        {
            return new EngineReply(false, Error: "Cancelled.");
        }
        catch (IOException ex)
        {
            return new EngineReply(false, Error: $"Control channel error: {ex.Message}");
        }
        catch (UnauthorizedAccessException)
        {
            return new EngineReply(
                false,
                Error: "Access to the engine's control channel was denied. It may be running for a different user.");
        }
        catch (JsonException ex)
        {
            return new EngineReply(true, Error: $"The engine sent a reply this build could not read: {ex.Message}");
        }
    }

    private static async Task WriteFrameAsync(Stream stream, byte[] payload, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);

        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]?> ReadFrameAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        if (!await ReadExactlyAsync(stream, header, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > EngineChannel.MaxMessageBytes)
        {
            throw new IOException($"Frame length {length} is out of range");
        }

        var payload = new byte[length];
        return await ReadExactlyAsync(stream, payload, cancellationToken).ConfigureAwait(false) ? payload : null;
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
}
