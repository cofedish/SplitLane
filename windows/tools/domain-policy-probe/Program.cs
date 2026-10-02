using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SplitLane.Core.Logging;
using SplitLane.Core.Models;
using SplitLane.Core.Rules;
using SplitLane.Engine.Divert;
using SplitLane.Engine.Flows;
using SplitLane.Engine.Relay;
using SplitLane.Engine.Runtime;
using SplitLane.Engine.Interop;
using SplitLane.Engine.Net;
using SplitLane.Testbed.Socks5;

// Opt-in, elevated live probe. Configuration stays in memory; no service/config/credential writes.
// pktmon must be stopped and have no filters before invocation. The script owning this process
// checks those conditions; capture files are retained, and only this probe's filter is removed.
if (args.Length == 2 && args[0] == "--client")
{
    var target = IPAddress.Parse(args[1]);
    using var udp = new UdpClient(target.AddressFamily);
    for (var i = 0; i < 3; i++)
    {
        await udp.SendAsync("SplitLane-domain-probe"u8.ToArray(), new IPEndPoint(target, 443));
        await Task.Delay(100);
    }

    using var tcp = new TcpClient(target.AddressFamily);
    try
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        await tcp.ConnectAsync(target, 80, deadline.Token);
        Console.WriteLine("TCP connected");
    }
    catch (Exception exception) when (exception is SocketException or OperationCanceledException)
    {
        Console.WriteLine($"TCP refused/timed out: {exception.GetType().Name}");
    }
    return;
}

if (args.Length != 4)
{
    throw new ArgumentException("Usage: probe <new-artifact-directory> <physical-pktmon-component-id> <DNS-IP> <hostname>");
}
if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
{
    throw new InvalidOperationException("An elevated session is required");
}
if (Process.GetProcessesByName("SplitLane.Engine").Length != 0)
{
    throw new InvalidOperationException("Another SplitLane engine is running; refusing concurrent interception");
}
var monitorStatus = await CommandAsync("pktmon.exe", "status");
if (!monitorStatus.Contains("not running", StringComparison.OrdinalIgnoreCase) &&
    !monitorStatus.Contains("не запущен", StringComparison.OrdinalIgnoreCase))
{
    throw new InvalidOperationException("pktmon must be stopped; its existing session will not be touched");
}
var filters = await CommandAsync("pktmon.exe", "filter", "list");
if (Regex.IsMatch(filters, @"^\s*\d+\s+", RegexOptions.Multiline))
{
    throw new InvalidOperationException("pktmon has existing filters; refusing to replace them");
}
var output = Path.GetFullPath(args[0]);
if (Directory.Exists(output))
{
    throw new IOException("Artifact directory must be new; refusing to overwrite previous evidence");
}
Directory.CreateDirectory(output);
var component = int.Parse(args[1], System.Globalization.CultureInfo.InvariantCulture);
var resolver = IPAddress.Parse(args[2]);
var hostname = args[3];
if (!DomainPattern.TryParse("*.example.com", out var pattern, out _) || !pattern.Matches(hostname))
{
    throw new ArgumentException("This probe only accepts subdomains of example.com");
}
SplitLaneLog.MinimumLevel = LogLevel.Debug;
SplitLaneLog.AddSink(new ProbeLogSink());

var response = await QueryAsync(resolver, hostname);
var targetAddress = FirstAddress(response);
Console.WriteLine($"Probe target: {hostname} -> {targetAddress}, physical component: {component}");
var filterCreated = false;
var captureRunning = false;
try
{
    await CommandAsync("pktmon.exe", "filter", "add", "SplitLaneDomainProbe", "-i", targetAddress.ToString());
    filterCreated = true;
    await CaptureAsync("direct-control", async () => await ClientAsync(targetAddress));

    await using var proxy = new Socks5TestServer(new Socks5TestServerOptions { StallAfterGreeting = true });
    using var unavailable = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
    unavailable.Bind(new IPEndPoint(IPAddress.Loopback, 0));
    var proxyConfiguration = ProxyConfiguration.Default with
    {
        Endpoint = new ProxyEndpoint { Host = "127.0.0.1", Port = (ushort)((IPEndPoint)unavailable.LocalEndPoint!).Port },
        HandshakeTimeoutMilliseconds = 1000,
    };
    var configuration = new RuntimeConfiguration
    {
        DomainRules = [new DomainRule { Pattern = "*.example.com", Action = RouteAction.ProxyOnly }],
        Proxy = proxyConfiguration,
    };
    var engine = new RuleEngine(configuration);
    SplitLane.Core.Proxy.Socks5.Socks5Credential? proxyCredential = null;
    var nat = new NatTable();
    var dns = new DnsObserver();
    var statistics = new EngineStatistics();
    await using var listener = new RedirectListener(nat, statistics, () => proxyConfiguration, () => proxyCredential);
    listener.Start(0);
    await using var pipeline = new DivertPipeline(nat, dns, new ProcessResolver(), statistics, () => engine)
    {
        Proxy = () => proxyConfiguration,
        Credential = () => proxyCredential,
    };
    pipeline.Start(listener.Port);
    Console.WriteLine($"Live WinDivert: {pipeline.DriverVersion}, listener: {listener.Port}");

    // Fresh wire response through the existing resolver. Do not seed the live observer manually.
    await QueryAsync(resolver, hostname);
    await Task.Delay(100);
    if (dns.Lookup(targetAddress) != hostname)
    {
        throw new InvalidOperationException($"DNS was not attributed by the live packet path: {dns.Lookup(targetAddress) ?? "null"}");
    }
    Console.WriteLine($"Live DNS evidence: {dns.Lookup(targetAddress)}");
    await CaptureAsync("proxy-unreachable", async () => await ClientAsync(targetAddress));

    proxyConfiguration = proxyConfiguration with
    {
        Endpoint = new ProxyEndpoint { Host = "127.0.0.1", Port = proxy.Port },
    };
    await CaptureAsync("proxy-timeout", async () => await ClientAsync(targetAddress));
    await using var authProxy = new Socks5TestServer(new Socks5TestServerOptions
    {
        RequireAuthentication = true,
        Username = "probe-user",
        Password = "correct-probe-password",
    });
    proxyConfiguration = proxyConfiguration with
    {
        Endpoint = new ProxyEndpoint { Host = "127.0.0.1", Port = authProxy.Port },
        Credential = new CredentialReference { Username = "probe-user" },
    };
    proxyCredential = new("probe-user", "wrong-probe-password");
    await CaptureAsync("proxy-authentication", async () => await ClientAsync(targetAddress));
    if (!statistics.RecentActivity(20).Any(record => record.Error == ConnectionErrorCategory.AuthenticationFailed))
    {
        throw new IOException("Expected proxy authentication refusal was not observed");
    }
    await using var healthyProxy = new Socks5TestServer(new Socks5TestServerOptions { ServePayloadBytes = 1024 });
    proxyConfiguration = proxyConfiguration with
    {
        Endpoint = new ProxyEndpoint { Host = "127.0.0.1", Port = healthyProxy.Port },
        Credential = null,
    };
    proxyCredential = null;
    await CaptureAsync("proxy-healthy", async () => await ClientAsync(targetAddress));
    if (healthyProxy.LastRequestedHost != hostname || healthyProxy.LastRequestedPort != 80)
    {
        throw new IOException("Healthy proxy did not receive the expected domain CONNECT");
    }
    Console.WriteLine($"Healthy proxy received CONNECT {healthyProxy.LastRequestedHost}:{healthyProxy.LastRequestedPort}");
    Console.WriteLine($"Statistics: {System.Text.Json.JsonSerializer.Serialize(statistics.RecentActivity(20))}");
    Console.WriteLine("PASS: protected phases had zero physical outbound and zero post-routing origin packets.");
}
finally
{
    if (captureRunning)
    {
        await CommandAsync("pktmon.exe", "stop");
    }
    if (filterCreated)
    {
        await CommandAsync("pktmon.exe", "filter", "remove");
    }
}

async Task CaptureAsync(string name, Func<Task> exercise)
{
    ulong outgoing = 0;
    using var sniff = DivertHandle.Open($"outbound and ip.DstAddr == {targetAddress} and (tcp or udp)",
        WinDivertLayer.Network, -100, WinDivertFlags.Sniff | WinDivertFlags.RecvOnly);
    var packets = new List<byte[]>();
    var receiving = Task.Run(() =>
    {
        var buffer = new byte[65535];
        while (sniff.Receive(buffer, out var length, out _, out _))
        {
            packets.Add(buffer.AsSpan(0, length).ToArray());
        }
    });
    var etl = Path.Combine(output, name + ".etl");
    await CommandAsync("pktmon.exe", "start", "--capture", "--comp", component.ToString(System.Globalization.CultureInfo.InvariantCulture),
        "--pkt-size", "0", "--file-name", etl, "--file-size", "16");
    captureRunning = true;
    try
    {
        await exercise();
        await Task.Delay(1500);
        var counters = await CommandAsync("pktmon.exe", "counters", "--json", "--zero");
        await File.WriteAllTextAsync(Path.Combine(output, name + ".counters.json"), counters);
        using var document = JsonDocument.Parse(counters);
        var foundComponent = false;
        foreach (var group in document.RootElement.EnumerateArray())
        {
            foreach (var entry in group.GetProperty("Components").EnumerateArray())
            {
                if (entry.GetProperty("Id").GetInt32() != component)
                {
                    continue;
                }
                foreach (var counter in entry.GetProperty("Counters").EnumerateArray())
                {
                    if (counter.GetProperty("Name").GetString() == "Lower")
                    {
                        foundComponent = true;
                        outgoing = counter.GetProperty("Outbound").GetProperty("Packets").GetUInt64();
                    }
                }
            }
        }
        if (!foundComponent)
        {
            throw new IOException("Physical Lower counter missing; capture is inconclusive");
        }
    }
    finally
    {
        sniff.Shutdown();
        await receiving.WaitAsync(TimeSpan.FromSeconds(5));
        using (var writer = new BinaryWriter(File.Create(Path.Combine(output, name + ".post-routing.pcap"))))
        {
            writer.Write(0xa1b2c3d4u);
            writer.Write((ushort)2);
            writer.Write((ushort)4);
            writer.Write(0);
            writer.Write(0u);
            writer.Write(65535u);
            writer.Write(101u); // DLT_RAW: IP packet, no Ethernet header.
            foreach (var bytes in packets)
            {
                writer.Write((uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
                writer.Write(0u);
                writer.Write((uint)bytes.Length);
                writer.Write((uint)bytes.Length);
                writer.Write(bytes);
                if (PacketView.TryParse(bytes, out var view))
                {
                    Console.WriteLine($"POST-ROUTING {name}: protocol={view.Protocol} source={view.SourcePort} " +
                        $"destination={view.DestinationPort} TCP-flags={(view.Protocol == 6 ? bytes[view.TransportOffset + 13] : 0):X2}");
                }
            }
        }
        await CommandAsync("pktmon.exe", "stop");
        captureRunning = false;
    }
    await CommandAsync("pktmon.exe", "etl2pcap", etl, "--out", Path.Combine(output, name + ".pcapng"));
    if (name == "direct-control")
    {
        if (outgoing == 0 || !packets.Any(bytes => bytes[9] == 17) || !packets.Any(bytes => bytes[9] == 6))
        {
            throw new IOException("Positive control did not demonstrate both TCP and UDP capture");
        }
    }
    else if (outgoing != 0 || packets.Count != 0)
    {
        throw new IOException($"Leak in {name}: physical outbound={outgoing}, post-routing={packets.Count}");
    }
}

static async Task ClientAsync(IPAddress target)
{
    await CommandAsync(Environment.ProcessPath!, "--client", target.ToString());
}

static async Task<string> CommandAsync(string file, params string[] arguments)
{
    var start = new ProcessStartInfo(file)
    {
        UseShellExecute = false,
        CreateNoWindow = true,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
    };
    foreach (var argument in arguments)
    {
        start.ArgumentList.Add(argument);
    }
    using var process = Process.Start(start) ?? throw new IOException($"Could not start {file}");
    var output = process.StandardOutput.ReadToEndAsync();
    var error = process.StandardError.ReadToEndAsync();
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
    try
    {
        await process.WaitForExitAsync(deadline.Token);
    }
    catch
    {
        if (!process.HasExited)
        {
            process.Kill(entireProcessTree: true);
        }
        throw;
    }
    if (process.ExitCode != 0)
    {
        throw new IOException($"{file} exited with {process.ExitCode}: {await error}");
    }
    var result = await output;
    Console.WriteLine(result);
    return result;
}

static async Task<byte[]> QueryAsync(IPAddress resolver, string hostname)
{
    var query = new List<byte> { 0x53, 0x4c, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    foreach (var label in hostname.Split('.'))
    {
        query.Add((byte)label.Length);
        query.AddRange(Encoding.ASCII.GetBytes(label));
    }
    query.AddRange([0, 0, 1, 0, 1]);
    using var socket = new UdpClient(resolver.AddressFamily);
    socket.Connect(resolver, 53);
    await socket.SendAsync(query.ToArray());
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
    return (await socket.ReceiveAsync(deadline.Token)).Buffer;
}

static IPAddress FirstAddress(byte[] response)
{
    var cursor = 12;
    SkipName(response, ref cursor);
    cursor += 4;
    var answers = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(6));
    for (var i = 0; i < answers; i++)
    {
        SkipName(response, ref cursor);
        var type = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(cursor));
        var length = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(cursor + 8));
        cursor += 10;
        if (type == 1 && length == 4)
        {
            return new IPAddress(response.AsSpan(cursor, 4));
        }
        cursor += length;
    }
    throw new IOException("Resolver returned no A record");
}

static void SkipName(byte[] response, ref int cursor)
{
    while (cursor < response.Length)
    {
        var length = response[cursor++];
        if (length == 0)
        {
            return;
        }
        if ((length & 0xc0) == 0xc0)
        {
            cursor++;
            return;
        }
        cursor += length;
    }
    throw new IOException("Malformed DNS response");
}

sealed class ProbeLogSink : ILogSink
{
    public void Write(LogLevel level, string category, string message) => Console.WriteLine($"[{level}] [{category}] {message}");
}
