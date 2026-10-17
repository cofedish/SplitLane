using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using SplitLane.Engine.Divert;
using SplitLane.Engine.Interop;
using SplitLane.Engine.Relay;

namespace SplitLane.Engine.Tests.Security;

public sealed class DhcpWindowsFactAttribute : FactAttribute
{
    public DhcpWindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows()) Skip = "Requires the Windows WinDivert user-mode filter helper; no driver is opened.";
    }
}

public sealed class DhcpNativeFilterTests
{
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Ansi, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool Compile(string filter, WinDivertLayer layer, nint output, uint length,
        out nint error, out uint position);

    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Ansi, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool Evaluate(string filter, byte[] packet, uint length, ref WinDivertAddress address);

    [DhcpWindowsFact]
    public void KernelFilterExcludesDhcpButStillCapturesOtherUdpAndRelayReplies()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "WinDivert.dll");
        Assert.True(File.Exists(path), "Fetch the pinned WinDivert DLL before building the Windows tests.");
        var library = NativeLibrary.Load(path);
        try
        {
            var compile = Marshal.GetDelegateForFunctionPointer<Compile>(NativeLibrary.GetExport(library, "WinDivertHelperCompileFilter"));
            var evaluate = Marshal.GetDelegateForFunctionPointer<Evaluate>(NativeLibrary.GetExport(library, "WinDivertHelperEvalFilter"));
            using var lanes = new UdpLanePool(size: 1);
            foreach (var filter in new[] { DivertPipeline.NetworkFilter(40000), DivertPipeline.NetworkFilter(40000, lanes) })
            {
                var valid = compile(filter, WinDivertLayer.Network, 0, 0, out var error, out var position);
                Assert.True(valid, $"Filter error at {position}: {Marshal.PtrToStringAnsi(error)}");
                foreach (var (source, sourcePort, destination, destinationPort) in DhcpBootstrapTests.Exchanges)
                {
                    var local = new IPEndPoint(IPAddress.Parse(source), sourcePort);
                    var remote = new IPEndPoint(IPAddress.Parse(destination), destinationPort);
                    var packet = TestPackets.Udp(local, remote, new byte[300]);
                    var address = new WinDivertAddress { Outbound = true, IPv6 = local.AddressFamily == AddressFamily.InterNetworkV6 };
                    // The old broad UDP clause really does capture these packets.
                    Assert.True(evaluate("outbound and udp and not loopback", packet, (uint)packet.Length, ref address));
                    Assert.False(evaluate(filter, packet, (uint)packet.Length, ref address));
                    Assert.Equal(0, Marshal.GetLastWin32Error());
                    address.Outbound = false;
                    Assert.False(evaluate(filter, packet, (uint)packet.Length, ref address));
                }
                foreach (var (sourcePort, destinationPort) in new[] { (68, 443), (40000, 67), (67, 67), (546, 547), (40000, 443) })
                {
                    var packet = TestPackets.Udp(new IPEndPoint(IPAddress.Parse("192.0.2.20"), sourcePort),
                        new IPEndPoint(IPAddress.Parse("203.0.113.1"), destinationPort));
                    var address = new WinDivertAddress { Outbound = true };
                    Assert.True(evaluate(filter, packet, (uint)packet.Length, ref address));
                }
            }
            var reply = TestPackets.Udp(new IPEndPoint(IPAddress.Loopback, lanes.BasePort), new IPEndPoint(IPAddress.Loopback, 52000));
            var replyAddress = new WinDivertAddress { Outbound = true, Loopback = true };
            Assert.True(evaluate(DivertPipeline.NetworkFilter(40000, lanes), reply, (uint)reply.Length, ref replyAddress));
        }
        finally { NativeLibrary.Free(library); }
    }
}
