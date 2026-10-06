using System.Net;
using System.Reflection;
using SplitLane.Core.Configuration;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;
using SplitLane.Engine.Divert;
using SplitLane.Engine.Flows;
using SplitLane.Engine.Interop;
using SplitLane.Engine.Runtime;
using SplitLane.Platform;

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

    private static DivertPipeline Pipeline(Func<RuleEngine> engine, ImageCatalog? images = null) =>
        new(new NatTable(), new DnsObserver(), new ProcessResolver(), new EngineStatistics(), engine)
        {
            UdpOwnerLookup = (_, _) => null,
            Images = images,
        };

    [Fact]
    public async Task Verification_is_queued_only_after_the_redecision_hold_is_published()
    {
        var stamp = new FileStamp(1000, 1, 1, 11);
        using var reachedRefresh = new ManualResetEventSlim();
        await using var images = ImageCatalog.ForVerifiedVersions((_, _) => (Flow.Image, stamp), _ => { reachedRefresh.Set(); return stamp; }, workers: 1);
        var engine = new RuleEngine(RuntimeConfiguration.Empty);
        await using var pipeline = Pipeline(() => engine, images);
        var waitingFlow = Flow with { Image = new ImageEvidence { ExecutablePath = Path, FileSize = 1000 } };
        pipeline.RecordUdpDecision(new PortSlot(false, (ushort)App.Port), 1, false, waitingFlow, RouteAction.Direct, pending: null);
        engine = new RuleEngine(ConfigurationValidator.Sanitize(new RuntimeConfiguration {
            Rules = [new AppRule { Identity = new AppIdentity { ExecutablePath = Path, DisplayName = "voice",
                Kind = IdentityKind.Unsigned, FileSha256 = Hash, FileSize = 1000 }, Action = RouteAction.Block }]
        }));
        Assert.Equal(RouteReasonKind.IdentityPending, engine.Decide(waitingFlow).Reason);
        // Run the real completion callback without opening a driver, then force exactly the
        // queue-before-publication interleaving by holding the same gate the publisher needs.
        typeof(DivertPipeline).GetField("_running", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(pipeline, true);
        var onVerified = typeof(DivertPipeline).GetMethod("OnImageVerified", BindingFlags.Instance | BindingFlags.NonPublic)!
            .CreateDelegate<Action<ImageRecord>>(pipeline);
        using var finished = new ManualResetEventSlim();
        images.Verified += onVerified;
        images.Verified += _ => finished.Set();
        var gate = (System.Threading.Lock)typeof(DivertPipeline).GetField("_udpGate", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(pipeline)!;
        Task<int> redecision;
        bool finishedBeforePublication;
        using (gate.EnterScope())
        {
            redecision = Task.Run(pipeline.RedecideUdp);
            Assert.True(reachedRefresh.Wait(TimeSpan.FromSeconds(5)));
            finishedBeforePublication = finished.Wait(TimeSpan.FromSeconds(1));
        }
        await redecision.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(finished.Wait(TimeSpan.FromSeconds(5)));
        images.Verified -= onVerified;
        Assert.False(finishedBeforePublication);
        Assert.Equal(0, pipeline.HeldCount);
        var packet = TestPackets.Udp(App, Remote, [1]);
        var address = new WinDivertAddress { Outbound = true };
        Assert.Equal(DivertPipeline.PacketAction.Drop, pipeline.Classify(packet, ref address));
    }

    [Fact]
    public async Task Verification_of_a_replaced_socket_cannot_restore_its_flow_over_the_new_owner()
    {
        var stamp = new FileStamp(1000, 1, 1, 11);
        await using var images = ImageCatalog.ForVerifiedVersions((_, _) => (Flow.Image, stamp), _ => stamp);
        const string newPath = @"C:\Apps\new-owner.exe";
        var engine = new RuleEngine(ConfigurationValidator.Sanitize(new RuntimeConfiguration {
            Rules = [new AppRule { Identity = new AppIdentity { ExecutablePath = newPath, DisplayName = "new owner" },
                Action = RouteAction.Block, MatchMode = MatchMode.Exact }]
        }));
        await using var pipeline = Pipeline(() => engine, images);
        var slot = new PortSlot(false, (ushort)App.Port);
        var oldImage = images.Refresh(Path);
        images.VerifyNow(oldImage, EvidenceNeeds.Hash);
        var oldHold = new PendingBind(Flow, oldImage, null, 1, false);
        Assert.True(pipeline.RecordUdpDecision(slot, 1, false, Flow, RouteAction.Block, oldHold));
        var replacement = new FlowDescriptor(8, newPath, "203.0.113.10", 0, FlowProtocol.Udp);
        Assert.Equal(RouteAction.Block, engine.Decide(replacement).Action);
        Assert.True(pipeline.RecordUdpDecision(slot, 2, false, replacement, RouteAction.Block, pending: null));
        typeof(DivertPipeline).GetField("_running", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(pipeline, true);
        typeof(DivertPipeline).GetMethod("OnImageVerified", BindingFlags.Instance | BindingFlags.NonPublic)!
            .CreateDelegate<Action<ImageRecord>>(pipeline)(oldImage);
        pipeline.RedecideUdp();
        var packet = TestPackets.Udp(App, Remote, [1]);
        var address = new WinDivertAddress { Outbound = true };
        Assert.Equal(DivertPipeline.PacketAction.Drop, pipeline.Classify(packet, ref address));
        Assert.Equal(0, pipeline.HeldCount);
    }
}
