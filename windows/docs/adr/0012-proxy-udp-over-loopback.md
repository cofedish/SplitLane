# ADR W-0012 — Selected applications' UDP goes through the proxy, over loopback

**Status:** Accepted
**Date:** 2026-08-22
**Supersedes on Windows:** the fail-closed half of macOS [ADR 0004](../../../docs/adr/0004-tcp-first-mvp.md)
(TCP-first, with UDP failed closed), which the Windows port had followed. W-0001 made no rule about UDP.

## Context

A selected application's datagrams were dropped. The reasoning was sound as far as it went: letting
them out unproxied would be a silent bypass, QUIC fails closed, and an application that cannot use
QUIC falls back to TCP, which is proxied correctly.

It is no help at all to anything with no TCP path. Discord's voice sits on "Connecting to RTC"
forever, because there is no second way for it to try. The user reported it as datagrams being
"dropped outright, when they should get through", which is exactly what was happening and exactly
what the code said it did.

SOCKS5 can carry datagrams: `UDP ASSOCIATE` opens a relay alongside the control connection. Before
building anything, the configured proxy was asked directly — it granted the association and returned
a real DNS answer through it, so the capability was established rather than assumed.

## Decision

**A selected application's UDP is relayed through the proxy, and refused when it cannot be.** It is
never forwarded unproxied. `ProxiesUdp` turns the relaying off, and off means refused — the setting
chooses between working and safe, never between safe and leaky.

**The application's datagrams are redirected over loopback, not captured and re-injected.**

Each `(application socket, remote endpoint)` pair gets a *lane*: a loopback UDP socket. The packet
layer rewrites an outgoing datagram to loopback, addressed to that lane; the lane relays it through
a SOCKS5 UDP association and sends the answer back; the packet layer rewrites that answer to carry
the address the application wrote to. One association per application socket, because that is what
costs a connection at the proxy; one lane per remote, because the port a reply arrives on is the
only thing the packet layer can use to know which remote to attribute it to.

## Why not capture and inject

That was built first, and it worked everywhere except where it mattered.

The engine took the datagram, relayed it, received the answer, built a correct IPv4/UDP packet from
the remote host to the application, and injected it inbound. The counters read `sent 4, back 4,
injected 4, failures 0`. The packet was dumped and verified by hand: right addresses, right ports,
right length, checksums computed, real interface index, inbound direction. WinDivert accepted every
one. **The application received nothing.**

Windows Firewall is enabled and this machine's active profile is Public. The outbound datagram never
left — the engine took it — so there is no state entry for the conversation, and an unsolicited
inbound datagram to an ephemeral port is precisely what a firewall exists to drop. Nothing reports
this. There is no error at either end, and no log anywhere says a packet was discarded.

The loopback shape has none of that problem, and it is not a new idea here: it is what the TCP path
has always done, and the reason that path works.

## Consequences

- Voice, and anything else with no TCP fallback, works for a selected application.
- The divert filter also captures the lanes' replies on loopback, and **names only the lanes'
  ports**. The lanes come from a contiguous block of loopback ports (`UdpLanePool`) reserved
  *before* the filter is built, so the filter can say `udp.SrcPort >= first and udp.SrcPort <= last`
  and never needs reopening when an application talks to a new host.

  The first version of this record, and of the code, captured all outbound loopback UDP instead and
  recognised lanes by port in the packet loop, on the reasoning that a dictionary lookup per datagram
  is cheap. It is; ten thousand datagrams a second of other software's traffic is not. On a machine
  whose DNS ran through a local tunnel it broke name resolution outright — TCP by address still
  worked, so what the user saw was an internet that had gone, with no error anywhere. Naming the block
  took the packets captured in a minute from 618,646 to 8,315. If no block can be reserved, UDP is
  refused rather than relayed, and the filter does not name loopback UDP at all.
- A lane is opened synchronously on the first datagram, so unlike a design that waited for the
  association, the first datagram of a conversation is not lost.
- Lanes and associations are evicted after two minutes idle; an association holds a TCP connection
  at the proxy for as long as it lives.
- Bounded at 64 lanes by default, the size of the reserved block. Beyond that, datagrams are refused
  rather than relayed - still not forwarded.
- IPv6 datagrams are not relayed. They are refused, as before.
- A proxy that will not grant `UDP ASSOCIATE` produces one warning per socket and dropped datagrams.
  That is the old behaviour, arrived at honestly rather than by default.

## What this does not change

DNS is still not proxied. A selected application's name lookups are made by Windows before SplitLane
sees a connection, and that is a separate problem — see `docs/THREAT_MODEL.md`.
