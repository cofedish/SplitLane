namespace SplitLane.Engine.Net;

/// <summary>Address configuration belongs to the host stack, never an application proxy lane.</summary>
internal static class DhcpTraffic
{
    // Both directions and unicast renewals matter. Do not exempt a single source/destination port:
    // ordinary application traffic using one of these port numbers still follows its rules.
    internal const string Filter =
        "udp and ((ip and ((udp.SrcPort = 68 and udp.DstPort = 67) or " +
        "(udp.SrcPort = 67 and udp.DstPort = 68))) or " +
        "(ipv6 and ((udp.SrcPort = 546 and udp.DstPort = 547) or " +
        "(udp.SrcPort = 547 and udp.DstPort = 546))))";

    internal static bool IsClientExchange(in PacketView packet)
        => packet.Protocol == PacketView.ProtocolUdp && packet.HasPorts &&
           ((packet.IsIPv4 && ((packet.SourcePort == 68 && packet.DestinationPort == 67) ||
                              (packet.SourcePort == 67 && packet.DestinationPort == 68))) ||
            (packet.IsIPv6 && ((packet.SourcePort == 546 && packet.DestinationPort == 547) ||
                              (packet.SourcePort == 547 && packet.DestinationPort == 546))));
}
