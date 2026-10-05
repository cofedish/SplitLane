using System.IO.Pipes;
using System.Security.Principal;
using SplitLane.Platform;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-010: the window talks to the control pipe only if the pipe was created by the service, and
/// connects at a level that does not let the server act as the user.
/// </summary>
/// <remarks>
/// Each test creates its own rogue server under a unique name, owned by the account running the tests
/// - exactly what any local account squatting the engine's name would create.
/// </remarks>
[Trait("Category", "Security")]
public sealed class PipeServerIdentitySecurityTests
{
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(5);

    private static string UniqueName() => "sl-sec010-" + Guid.NewGuid().ToString("N");

    private static string OwnerOf(PipeStream pipe) =>
        pipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier))!.Value;

    [Fact]
    public async Task A_pipe_squatted_by_an_ordinary_account_is_refused_before_anything_is_sent()
    {
        var name = UniqueName();
        await using var rogue = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var accepted = rogue.WaitForConnectionAsync();

        // Only SYSTEM is trusted here, so the outcome does not depend on whether the test process
        // happens to run elevated (an elevated creator would make the owner Administrators).
        var (pipe, refusal) = await EngineServerIdentity.ConnectAsync(name, 2000, ["S-1-5-18"], CancellationToken.None);
        await accepted.WaitAsync(Wait);

        Assert.Null(pipe);
        Assert.NotNull(refusal);
        Assert.Contains(OwnerOf(rogue), refusal, StringComparison.OrdinalIgnoreCase);

        // The client closed without writing a byte.
        var buffer = new byte[16];
        Assert.Equal(0, await rogue.ReadAsync(buffer).AsTask().WaitAsync(Wait));
    }

    [Fact]
    public async Task A_pipe_owned_by_a_trusted_principal_is_accepted()
    {
        var name = UniqueName();
        await using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var accepted = server.WaitForConnectionAsync();

        var (pipe, refusal) = await EngineServerIdentity.ConnectAsync(name, 2000, [OwnerOf(server)], CancellationToken.None);
        await accepted.WaitAsync(Wait);

        Assert.Null(refusal);
        Assert.NotNull(pipe);
        await pipe.DisposeAsync();
    }

    [Fact]
    public void Only_SYSTEM_and_Administrators_are_trusted_by_default()
    {
        var me = WindowsIdentity.GetCurrent().User!.Value;
        var name = UniqueName();
        using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1);
        using var client = new NamedPipeClientStream(".", name, PipeDirection.InOut);
        client.Connect(2000);
        server.WaitForConnection();

        var owner = OwnerOf(server);
        var verdict = EngineServerIdentity.Problem(client);

        if (owner is "S-1-5-18" or "S-1-5-32-544")
        {
            Assert.Null(verdict);
        }
        else
        {
            Assert.Equal(me, owner);
            Assert.NotNull(verdict);
        }
    }

    [Fact]
    public async Task A_server_cannot_act_as_the_connected_user()
    {
        var name = UniqueName();
        await using var rogue = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var accepted = rogue.WaitForConnectionAsync();

        await using var client = new NamedPipeClientStream(
            ".", name, PipeDirection.InOut, PipeOptions.Asynchronous, EngineServerIdentity.ClientImpersonation);
        await client.ConnectAsync(2000);
        await accepted.WaitAsync(Wait);

        // The pipe is unbuffered, as the engine's is: a write completes only once the other end
        // reads, so the read is started first.
        var buffer = new byte[1];
        var read = rogue.ReadAsync(buffer).AsTask();
        await client.WriteAsync(new byte[] { 1 }).AsTask().WaitAsync(Wait);
        Assert.Equal(1, await read.WaitAsync(Wait));

        // Loaded before impersonating: under an Identification token the runtime cannot even open the
        // assembly file as the client - which is the point - and a failed load would be cached.
        using (WindowsIdentity.GetCurrent())
        {
        }

        TokenImpersonationLevel? level = null;
        rogue.RunAsClient(() => level = WindowsIdentity.GetCurrent(ifImpersonating: true)?.ImpersonationLevel);

        Assert.Equal(TokenImpersonationLevel.Identification, level);
    }

    [Fact]
    public async Task Nothing_listening_is_reported_as_a_timeout_not_a_refusal()
    {
        await Assert.ThrowsAsync<TimeoutException>(
            () => EngineServerIdentity.ConnectAsync(UniqueName(), 200, CancellationToken.None));
    }
}
