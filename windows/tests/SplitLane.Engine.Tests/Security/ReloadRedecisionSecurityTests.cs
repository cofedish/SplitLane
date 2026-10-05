using System.Net;
using SplitLane.Core.Configuration;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;
using SplitLane.Engine.Divert;
using SplitLane.Engine.Flows;
using SplitLane.Engine.Interop;
using SplitLane.Engine.Runtime;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-023: a configuration change applies to UDP sockets that are already open, in both directions.
/// </summary>
[Trait("Category", "Security")]
public sealed class ReloadRedecisionSecurityTests
{
    private const string Path = @"C:\Apps\voice.exe";
    private static readonly string Hash = new('a', 64);

    private static readonly IPEndPoint App = new(IPAddress.Parse("192.168.0.84"), 55000);
    private static readonly IPEndPoint Remote = new(IPAddress.Parse("203.0.113.10"), 3478);

    private static readonly FlowDescriptor Flow = new(7, Path, "203.0.113.1", 0, FlowProtocol.Udp, Image: new ImageEvidence
    {
        ExecutablePath = Path,
        Signature = SignatureStatus.Unsigned,
        Sha256 = Hash,
        HasVersionInfo = true,
    });

    private static RuleEngine With(RouteAction? action) => new(ConfigurationValidator.Sanitize(action is { } chosen
        ? new RuntimeConfiguration
        {
            Rules =
            [
                new AppRule
                {
                    Identity = new AppIdentity { ExecutablePath = Path, DisplayName = "voice", FileSha256 = Hash },
                    Action = chosen,
                },
            ],
        }
        : RuntimeConfiguration.Empty));

    [Fact]
    public async Task An_open_socket_of_an_application_blocked_afterwards_is_blocked_now()
    {
        var engine = With(null);
        await using var pipeline = Pipeline(() => engine);
        pipeline.RecordUdpDecision(new PortSlot(false, (ushort)App.Port), 1, false, Flow, RouteAction.Direct, pending: null);

        var datagram = TestPackets.Udp(App, Remote, [1]);
        var address = new WinDivertAddress { Outbound = true };
        Assert.Equal(DivertPipeline.PacketAction.Forward, pipeline.Classify(datagram, ref address));

        engine = With(RouteAction.Block);
        Assert.Equal(1, pipeline.RedecideUdp());

        Assert.Equal(DivertPipeline.PacketAction.Drop, pipeline.Classify(datagram, ref address));
    }

    [Fact]
    public async Task An_open_socket_released_by_a_change_flows_again()
    {
        var engine = With(RouteAction.Block);
        await using var pipeline = Pipeline(() => engine);
        pipeline.RecordUdpDecision(new PortSlot(false, (ushort)App.Port), 1, false, Flow, RouteAction.Block, pending: null);

        var datagram = TestPackets.Udp(App, Remote, [1]);
        var address = new WinDivertAddress { Outbound = true };
        Assert.Equal(DivertPipeline.PacketAction.Drop, pipeline.Classify(datagram, ref address));

        engine = With(null);
        pipeline.RedecideUdp();

        Assert.Equal(DivertPipeline.PacketAction.Forward, pipeline.Classify(datagram, ref address));
    }

    [Fact]
    public async Task A_socket_that_closed_is_not_brought_back_by_a_change()
    {
        var engine = With(null);
        await using var pipeline = Pipeline(() => engine);
        var slot = new PortSlot(false, (ushort)App.Port);
        pipeline.RecordUdpDecision(slot, 1, false, Flow, RouteAction.Direct, pending: null);
        pipeline.CloseUdp(slot, 1);

        engine = With(RouteAction.Block);

        Assert.Equal(0, pipeline.RedecideUdp());
    }

    private static DivertPipeline Pipeline(Func<RuleEngine> engine) =>
        new(new NatTable(), new DnsObserver(), new ProcessResolver(), new EngineStatistics(), engine)
        {
            UdpOwnerLookup = (_, _) => null,
        };
}
