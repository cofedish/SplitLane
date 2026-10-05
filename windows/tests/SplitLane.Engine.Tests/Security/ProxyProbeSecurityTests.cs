using System.Net;
using System.Net.Sockets;
using SplitLane.Core.Models;
using SplitLane.Core.Proxy;
using SplitLane.Engine.Runtime;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-019: the proxy test that any interactive user can ask the service to run tells them whether
/// and where it failed, never what the far end said, and cannot be run in a tight loop.
/// </summary>
[Trait("Category", "Security")]
public sealed class ProxyProbeSecurityTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "sl-sec019-" + Guid.NewGuid().ToString("N"));

    public ProxyProbeSecurityTests() => Directory.CreateDirectory(_root);

    [Fact]
    public void A_failure_reported_to_the_window_carries_nothing_the_far_end_wrote()
    {
        var failure = new UpstreamProxyException(
            ConnectionErrorCategory.RejectedByProxy,
            UpstreamStage.Connect,
            "The proxy answered: SSH-2.0-OpenSSH_9.6 internal-admin-host\r\n")
        {
            StatusCode = 400,
            AuthenticationScheme = "X-Banner-From-Peer",
        };

        var shown = EngineRuntime.CoarseFailure(failure);

        Assert.DoesNotContain("SSH-2.0", shown, StringComparison.Ordinal);
        Assert.DoesNotContain("internal-admin-host", shown, StringComparison.Ordinal);
        Assert.DoesNotContain("X-Banner", shown, StringComparison.Ordinal);
        Assert.Contains("HTTP 400", shown, StringComparison.Ordinal);
    }

    [Fact]
    public async Task The_test_cannot_be_run_in_a_tight_loop()
    {
        // A closed port on loopback: each attempt fails fast, which is exactly what a scan would do.
        var closed = ClosedPort();
        await using var runtime = Runtime();
        runtime.Save(RuntimeConfiguration.Empty with
        {
            Proxy = ProxyConfiguration.Default with
            {
                Endpoint = new ProxyEndpoint { Host = "127.0.0.1", Port = closed },
                HandshakeTimeoutMilliseconds = 1000,
            },
        });

        var first = await runtime.TestProxyAsync(CancellationToken.None);
        var second = await runtime.TestProxyAsync(CancellationToken.None);

        Assert.False(first.Succeeded);
        Assert.False(second.Succeeded);
        Assert.Contains("Wait a moment", second.Detail, StringComparison.Ordinal);

        // The status every interactive user can read says no more than the test result did.
        Assert.Equal(first.Detail, runtime.Status().LastError);
    }

    private EngineRuntime Runtime() => new(
        new ConfigurationStore(Path.Combine(_root, "configuration.v2.json"), Path.Combine(_root, "credential.bin")),
        new EngineOptions(EnableDivert: false),
        new Flows.ImageCatalog(workers: 1),
        Platform.WindowsImageInspector.Instance);

    private static ushort ClosedPort()
    {
        using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return (ushort)((IPEndPoint)probe.LocalEndPoint!).Port;
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
