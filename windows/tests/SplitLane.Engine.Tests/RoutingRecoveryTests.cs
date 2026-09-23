using SplitLane.Core.Ipc;
using SplitLane.Engine.Runtime;

namespace SplitLane.Engine.Tests;

/// <summary>
/// Routing that stops working while it should be on is brought back, and routing stopped on purpose
/// is left stopped.
/// </summary>
/// <remarks>
/// The divert layer needs a driver and elevation, so these run the engine without it and stand in
/// for its fault report. What they establish is the runtime's side: that a fault leads to a restart,
/// that a burst of faults backs off, and that an explicit stop is final.
/// </remarks>
public sealed class RoutingRecoveryTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "splitlane-recovery-" + Guid.NewGuid().ToString("N")[..8]);

    public RoutingRecoveryTests() => Directory.CreateDirectory(_root);

    private EngineRuntime Runtime() => new(
        new ConfigurationStore(Path.Combine(_root, "configuration.v2.json"), Path.Combine(_root, "credential.bin")),
        new EngineOptions(EnableDivert: false),
        new Flows.ImageCatalog(workers: 1),
        Platform.WindowsImageInspector.Instance)
    {
        RecoveryBackoff = [TimeSpan.FromMilliseconds(20), TimeSpan.FromMilliseconds(200)],
    };

    private static async Task Until(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException("condition not reached");
            }

            await Task.Delay(10);
        }
    }

    [Fact]
    public async Task AFaultWhileRoutingIsWantedIsFollowedByARestart()
    {
        await using var runtime = Runtime();
        runtime.LoadConfiguration();
        await runtime.StartAsync();

        runtime.ReportRoutingFault("simulated: the socket pump stopped");
        Assert.Equal(DivertState.Faulted, runtime.State);

        await Until(() => runtime.Recoveries == 1, TimeSpan.FromSeconds(10));
        Assert.Equal(DivertState.Running, runtime.State);
    }

    [Fact]
    public async Task RoutingStoppedOnPurposeStaysStopped()
    {
        await using var runtime = Runtime();
        runtime.LoadConfiguration();
        await runtime.StartAsync();
        await runtime.StopAsync();

        runtime.ReportRoutingFault("a late report from the pipeline that was just taken down");
        await Task.Delay(300);

        Assert.Equal(DivertState.Stopped, runtime.State);
        Assert.Equal(0, runtime.Recoveries);
    }

    [Fact]
    public async Task ASecondFaultSoonAfterRecoveryIsAlsoRecovered()
    {
        await using var runtime = Runtime();
        runtime.LoadConfiguration();
        await runtime.StartAsync();

        runtime.ReportRoutingFault("first");
        await Until(() => runtime.Recoveries == 1, TimeSpan.FromSeconds(10));
        runtime.ReportRoutingFault("second, within the burst window, so it waits longer");
        await Until(() => runtime.Recoveries == 2, TimeSpan.FromSeconds(10));

        Assert.Equal(DivertState.Running, runtime.State);
    }

    [Fact]
    public async Task APipelineThatDiesAsItIsRestartedIsRestartedAgain()
    {
        // The report arrives while the first recovery still holds its slot, so it cannot schedule a
        // second one itself. Before this was handled it was dropped: Faulted, and never retried.
        await using var runtime = Runtime();
        runtime.LoadConfiguration();
        await runtime.StartAsync();

        var failed = 0;
        runtime.Recovered += () =>
        {
            if (Interlocked.Exchange(ref failed, 1) == 0)
            {
                runtime.ReportRoutingFault("simulated: the restarted pipeline died at once");
            }
        };

        runtime.ReportRoutingFault("first");
        await Until(() => runtime.Recoveries == 2, TimeSpan.FromSeconds(10));

        Assert.Equal(DivertState.Running, runtime.State);
    }

    [Fact]
    public async Task RoutingThatCannotStartIsRetriedUntilItCan()
    {
        // What the service does at boot when routing fails to start: it stays up with its control
        // channel, and the engine keeps trying. The service manager restarts nothing here, because
        // nothing crashed. A driver that is not there cannot be simulated; the redirect port held by
        // another program fails the same start.
        using var holder = new System.Net.Sockets.Socket(
            System.Net.Sockets.AddressFamily.InterNetworkV6,
            System.Net.Sockets.SocketType.Stream,
            System.Net.Sockets.ProtocolType.Tcp)
        {
            DualMode = true,
            ExclusiveAddressUse = true,
        };
        holder.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.IPv6Any, 0));
        holder.Listen();
        var port = (ushort)((System.Net.IPEndPoint)holder.LocalEndPoint!).Port;

        new ConfigurationStore(Path.Combine(_root, "configuration.v2.json"), Path.Combine(_root, "credential.bin"))
            .Save(Core.Models.RuntimeConfiguration.Empty with { RedirectPort = port });

        await using var runtime = Runtime();
        runtime.LoadConfiguration();

        await Assert.ThrowsAnyAsync<Exception>(runtime.StartAsync);
        Assert.Equal(DivertState.Faulted, runtime.State);

        holder.Close();
        await Until(() => runtime.Recoveries == 1, TimeSpan.FromSeconds(10));

        Assert.Equal(DivertState.Running, runtime.State);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}
