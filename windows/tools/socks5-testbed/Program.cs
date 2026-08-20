using SplitLane.Testbed.Socks5;

// A SOCKS5 server that logs every CONNECT, and can answer as the origin as well.
//
// The log is how interception is proved: it is the upstream's own account of what it was asked to
// reach. Answering as the origin is what makes a load test unambiguous - requests can then be aimed
// at an address that routes nowhere, so success is only possible through the proxy and the
// unselected control is required to fail.
//
// It prints its port on the first line so a script can pick it up without being told.

var requireAuth = args.Contains("--auth", StringComparer.OrdinalIgnoreCase);
var servePayloadKb = ArgumentValue("--serve-payload-kb", 0);

var stopping = new TaskCompletionSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    stopping.TrySetResult();
};

await using var server = new Socks5TestServer(new Socks5TestServerOptions
{
    RequireAuthentication = requireAuth,
    Username = requireAuth ? "splitlane" : null,
    Password = requireAuth ? "testbed" : null,
    ServePayloadBytes = servePayloadKb > 0 ? servePayloadKb * 1024 : null,
});

server.ConnectRequested += (host, port) =>
    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] CONNECT {host}:{port}");

Console.WriteLine($"SOCKS5 testbed listening on 127.0.0.1:{server.Port}");

if (requireAuth)
{
    Console.WriteLine("Authentication required — username 'splitlane', password 'testbed'");
}

if (servePayloadKb > 0)
{
    Console.WriteLine(
        $"Answering as the origin too: {servePayloadKb} KB per request, destination never dialled.");
}

Console.WriteLine("Press Ctrl+C to stop.");

await stopping.Task;

Console.WriteLine($"Accepted {server.AcceptedConnections} connections.");

int ArgumentValue(string name, int fallback)
{
    var index = Array.FindIndex(args, a => a.Equals(name, StringComparison.OrdinalIgnoreCase));
    return index >= 0 && index + 1 < args.Length && int.TryParse(args[index + 1], out var value)
        ? value
        : fallback;
}
