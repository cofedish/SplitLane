using System.Buffers.Binary;
using System.Net;
using SplitLane.Core.Configuration;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;
using SplitLane.Engine.Divert;
using SplitLane.Engine.Flows;
using SplitLane.Engine.Interop;
using SplitLane.Engine.Net;
using SplitLane.Engine.Runtime;

namespace SplitLane.Engine.Tests.Security;

/// <summary>
/// SL-SEC-022: a later IPv4 fragment is never read as if it had ports, and the later fragments of a
/// datagram whose first fragment was refused or redirected are refused too - not sent DIRECT.
/// Whether Windows hands outbound fragments to the WinDivert network layer at all requires isolated
/// runtime validation; this proves what the classifier does when it does.
/// </summary>
[Trait("Category", "Security")]
public sealed class FragmentSecurityTests
{
    private static readonly IPEndPoint App = new(IPAddress.Parse("192.168.0.84"), 54000);
    private static readonly IPEndPoint Remote = new(IPAddress.Parse("203.0.113.10"), 443);

    [Fact]
    public void A_later_fragment_is_not_read_as_having_ports()
    {
        var tail = Fragment(TestPackets.Udp(App, Remote, new byte[64]), id: 7, offsetUnits: 3, more: false);

        Assert.True(PacketView.TryParse(tail, out var view));
        Assert.True(view.IsFragmentTail);
        Assert.False(view.HasPorts);
    }

    [Fact]
    public void A_very_short_later_fragment_is_still_recognised_as_one()
    {
        // Shorter than a UDP header: used to fail to parse and be forwarded without a second look.
        var packet = TestPackets.Udp(App, Remote)[..24];
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), 24);
        var tail = Fragment(packet, id: 7, offsetUnits: 5, more: false);

        Assert.True(PacketView.TryParse(tail, out var view));
        Assert.True(view.IsFragmentTail);
    }

    [Fact]
    public async Task The_rest_of_a_refused_datagram_is_refused_too()
    {
        await using var pipeline = Pipeline();
        pipeline.RecordUdpDecision(new PortSlot(false, (ushort)App.Port), 1, false,
            new FlowDescriptor(7, @"C:\Apps\selected.exe", "203.0.113.1", 0, FlowProtocol.Udp), RouteAction.Block, pending: null);

        var address = new WinDivertAddress { Outbound = true };
        var first = Fragment(TestPackets.Udp(App, Remote, new byte[64]), id: 0x4242, offsetUnits: 0, more: true);
        var tail = Fragment(TestPackets.Udp(App, Remote, new byte[64]), id: 0x4242, offsetUnits: 9, more: false);

        Assert.Equal(DivertPipeline.PacketAction.Drop, pipeline.Classify(first, ref address));
        Assert.Equal(DivertPipeline.PacketAction.Drop, pipeline.Classify(tail, ref address));
    }

    [Fact]
    public async Task The_rest_of_an_untouched_datagram_is_left_alone()
    {
        await using var pipeline = Pipeline();
        pipeline.RecordUdpDecision(new PortSlot(false, (ushort)App.Port), 1, false,
            new FlowDescriptor(9, @"C:\Apps\other.exe", "203.0.113.1", 0, FlowProtocol.Udp), RouteAction.Direct, pending: null);

        var address = new WinDivertAddress { Outbound = true };
        var first = Fragment(TestPackets.Udp(App, Remote, new byte[64]), id: 0x1111, offsetUnits: 0, more: true);
        var tail = Fragment(TestPackets.Udp(App, Remote, new byte[64]), id: 0x1111, offsetUnits: 9, more: false);

        Assert.Equal(DivertPipeline.PacketAction.Forward, pipeline.Classify(first, ref address));
        Assert.Equal(DivertPipeline.PacketAction.Forward, pipeline.Classify(tail, ref address));
    }

    private static byte[] Fragment(byte[] packet, ushort id, int offsetUnits, bool more)
    {
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), id);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(6), (ushort)((more ? 0x2000 : 0) | (offsetUnits & 0x1FFF)));
        return packet;
    }

    private static DivertPipeline Pipeline()
    {
        var engine = new RuleEngine(ConfigurationValidator.Sanitize(RuntimeConfiguration.Empty));
        return new DivertPipeline(new NatTable(), new DnsObserver(), new ProcessResolver(), new EngineStatistics(), () => engine)
        {
            UdpOwnerLookup = (_, _) => null,
        };
    }
}
