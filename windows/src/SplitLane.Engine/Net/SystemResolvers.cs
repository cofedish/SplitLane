using System.Net;
using System.Net.NetworkInformation;

namespace SplitLane.Engine.Net;

/// <summary>
/// The DNS servers Windows is configured to use, read from the network interfaces.
/// </summary>
/// <remarks>
/// Read only, and only to decide whether a DNS answer from a loopback address can be believed
/// (SL-SEC-003): on loopback any local process can both send a query and answer it, so an answer is
/// evidence only when it comes from a resolver the machine itself is configured to ask. The list is
/// cached briefly and refreshed when an address changes, because asking every interface for its DNS
/// settings per packet would be far too slow for the packet loop.
/// </remarks>
public static class SystemResolvers
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(30);
    private static volatile Snapshot _current = new(Read(), DateTimeOffset.UtcNow);

    static SystemResolvers()
    {
        NetworkChange.NetworkAddressChanged += (_, _) => _current = _current with { ReadAt = DateTimeOffset.MinValue };
    }

    private sealed record Snapshot(HashSet<IPAddress> Addresses, DateTimeOffset ReadAt);

    /// <summary>Whether an address is one of the configured DNS servers.</summary>
    public static bool Contains(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        var snapshot = _current;
        if (DateTimeOffset.UtcNow - snapshot.ReadAt > Lifetime)
        {
            snapshot = _current = new Snapshot(Read(), DateTimeOffset.UtcNow);
        }

        return snapshot.Addresses.Contains(address);
    }

    private static HashSet<IPAddress> Read()
    {
        var addresses = new HashSet<IPAddress>();

        try
        {
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (adapter.OperationalStatus != OperationalStatus.Up)
                {
                    continue;
                }

                foreach (var server in adapter.GetIPProperties().DnsAddresses)
                {
                    addresses.Add(server.ScopeId == 0 ? server : new IPAddress(server.GetAddressBytes()));
                }
            }
        }
        catch (NetworkInformationException)
        {
            // No answer means no loopback resolver is believed - the conservative direction.
        }

        return addresses;
    }
}
