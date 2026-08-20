using SplitLane.Testbed.Socks5;

// Standalone runner, so the same server the tests use can be pointed at by a real browser or by
// SplitLane itself during manual verification. Without this, proving the engine works end to end
// would need a third-party proxy installed first.

var requireAuth = args.Contains("--auth", StringComparer.OrdinalIgnoreCase);

await using var server = new Socks5TestServer(new Socks5TestServerOptions
{
    RequireAuthentication = requireAuth,
    Username = requireAuth ? "splitlane" : null,
    Password = requireAuth ? "testbed" : null,
});

server.ConnectRequested += (host, port) =>
    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] CONNECT {host}:{port}");

Console.WriteLine($"SOCKS5 testbed listening on 127.0.0.1:{server.Port}");

if (requireAuth)
{
    Console.WriteLine("Authentication required — username 'splitlane', password 'testbed'");
}

Console.WriteLine("Press Ctrl+C to stop.");

var stopping = new TaskCompletionSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    stopping.TrySetResult();
};

await stopping.Task;

Console.WriteLine($"Accepted {server.AcceptedConnections} connections.");
