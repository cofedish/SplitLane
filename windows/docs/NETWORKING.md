# Networking

How a connection actually gets from a selected application into the proxy lane, and what that
costs.

## 1. The problem Windows poses

The macOS build is built on `NETransparentProxyProvider`, which hands the provider each new flow
*before a socket exists* and lets it return `false` to disclaim the flow entirely. That single
property is what makes "unselected applications are untouched" a literal statement rather than an
approximation.

Windows offers nothing equivalent in user mode:

- **WFP** (`fwpuclnt.dll`) can permit and block by application from user mode, but redirection —
  `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4` — is available only to a kernel callout driver.
- **LSPs** were the historical answer and are effectively dead on modern Windows.
- **DLL injection** into the target process is what Proxifier does. It requires writing into other
  people's processes, breaks on protected processes, and is indistinguishable from malware to most
  endpoint protection.

What remains is packet interception. SplitLane uses [WinDivert](https://github.com/basil00/WinDivert),
a signed kernel driver with a user-mode API. See [ADR W-0001](adr/0001-windivert-and-loopback-nat.md).

## 2. Identity arrives separately from packets

This is the central structural difference, and everything else follows from it.

| Layer | Gives us | Missing |
|---|---|---|
| `WINDIVERT_LAYER_SOCKET` | process id, local port, remote address and port | the packet |
| `WINDIVERT_LAYER_NETWORK` | the packet | any notion of which process it belongs to |

So the routing decision is made **in advance**, on the socket layer, and the packet layer is a table
lookup:

```
connect()  ──▶  SOCKET/CONNECT event
                    │  pid ──▶ image path + package family (cached, keyed on pid + start time)
                    │  RuleEngine.Decide(...)
                    │
                    ├─ PROXY  ──▶ NatTable.Record(localPort, original destination)
                    ├─ BLOCK  ──▶ NatTable verdict Block: the connection's packets are dropped
                    ├─ HOLD   ──▶ NatTable verdict Pending: packets dropped while the image is
                    │             verified, then the connection is decided again
                    └─ DIRECT ──▶ recorded with its destination, so its SYN does not wait
                    ▼
        SYN leaves ──▶ NETWORK layer
                    │  no decision yet? wait for one, up to 8 ms
                    │  NatTable lookup by source port, checked against the destination
                    ├─ proxied        ──▶ rewrite to the loopback listener, reinject
                    ├─ Block, Pending ──▶ drop
                    └─ anything else  ──▶ reinject byte-for-byte, unmodified
```

**The order in which the two arrive is not guaranteed.** Windows generates the socket-layer event
before it sends the SYN, but the two travel through separate WinDivert queues to separate threads, and
either can be read first. The design assumed otherwise until a packet capture on a live machine showed
the SYN leaving un-redirected, the connection establishing with its real server, and the later packets
being rewritten and dropped.

So a SYN with no decision waits for one, for up to eight milliseconds (`DivertPipeline`), and a
connection is redirected only if its SYN was. A SYN whose wait times out is let through rather than
dropped, because dropping it would break an application SplitLane was never asked to touch. If a
PROXY decision then arrives for it, that connection has already established with its real
destination; it is left alone and a warning is logged — a selected application's connection gone
DIRECT, reported rather than silent. Across a full load run the wait timed out 0 times
(`tools/stress-divert.ps1`). DIRECT decisions are recorded too, so an unselected
application's SYN finds its answer instead of waiting out the window — without that, every
connection it opened paid the full wait (see [DEVELOPMENT.md](DEVELOPMENT.md), "What it costs an
application nobody selected").

A held connection is different: its first SYN is dropped on purpose while its image is verified, and
TCP's retransmission about a second later meets the answer. See [ARCHITECTURE.md](ARCHITECTURE.md),
"Application identity".

**Pid reuse** is the obvious hazard — Windows recycles process ids within seconds. `ProcessResolver`
keys its cache on `(pid, process start time)`, so a recycled id is a cache miss rather than one
application's connection inheriting another's rule.

## 3. The loopback NAT

A selected application's connection is destination-NATed to a loopback listener, relayed over SOCKS5,
and the replies are source-NATed back so the application's socket never learns anything happened.

```
app ──▶  192.168.1.5:51000 → 93.184.216.34:443      (what the app sent)
         rewritten to
         127.0.0.1:51000   → 127.0.0.1:24444        (what the stack sees)

listener ──▶ SOCKS5 CONNECT to 93.184.216.34:443 via the configured proxy

reply ──▶  127.0.0.1:24444 → 127.0.0.1:51000        (what the listener sent)
           rewritten to
           93.184.216.34:443 → 192.168.1.5:51000    (what the app receives)
```

Three things about this are load-bearing:

- **Both endpoints move to loopback.** Rewriting only the destination leaves a packet addressed
  `192.168.1.5 → 127.0.0.1`, which the Windows stack drops as a martian: an address in `127/8` is
  only valid paired with another one.
- **The source port never changes.** It is the only field that survives the rewrite, and it is the
  key that both the listener and the return path use to find the connection's NAT entry.
- **The reply must carry the exact original four-tuple.** The application's socket is `ESTABLISHED`
  against it; a reply that did not match would be answered with a reset by the application's own
  stack.

The rewrite and its checksums live in `RedirectRewriter` and `PacketView` — pure functions over a
buffer, with no WinDivert types in the signature, covered by `PacketRewriteTests`. That separation is
deliberate: a NAT bug does not produce an error anywhere, it produces a connection that silently
hangs, which is close to undiagnosable from the outside.

A selected application's UDP takes the same shape (ADR W-0012). Each application socket and remote
pair gets a *lane*, a loopback UDP socket from a reserved block; the datagram is rewritten to the
lane, the lane relays it through a SOCKS5 `UDP ASSOCIATE` and sends the answer back over loopback, and
that answer is rewritten to carry the address the application wrote to. Relaying in the engine and
injecting the answer as an inbound packet was tried first: WinDivert accepted every injection and
Windows Firewall discarded every one, because the outbound datagram never left and there was no state
for the conversation. A datagram that cannot be relayed — relaying off, a proxy that refuses
`UDP ASSOCIATE`, all lanes in use, IPv6 — is dropped, never forwarded.

## 4. The divert filters

Three handles — socket layer, network layer, DNS observer — plus a sniffing trace handle under
`--trace`.

**When they are open.** The handles are opened when routing starts, which the engine does as soon as
it starts whenever the divert layer is enabled. They stay open while routing is paused and while no
rule selects anything: pausing makes every decision DIRECT, it does not stop packets being captured
and reinjected. Only stopping routing — the Overview page's *Stop routing*, `StopRouting` on the
control channel — or stopping the engine closes them.

**Socket layer** — sniffing, cannot block:

```
event = CONNECT or event = BIND or event = CLOSE
```

`BIND` is there for UDP attribution. An unconnected `sendto()` never produces a `CONNECT`, so without
tracking binds a selected application's QUIC traffic would be unattributable at the packet layer,
could be neither relayed nor stopped, and would escape DIRECT — the exact leak macOS ADR 0004 exists
to prevent.

**Network layer** — the only handle that modifies anything:

```
(outbound and tcp and not loopback) or
(outbound and tcp and loopback and tcp.SrcPort = <listener>) or
(outbound and udp and not loopback) or
(outbound and udp and loopback and udp.SrcPort >= <first lane> and udp.SrcPort <= <last lane>)
```

Each clause earns its place:

1. Application traffic that may need redirecting.
2. Replies from the redirect listener, which need restoring. Matching on the *listener's* source port
   is what stops the redirected traffic — whose source port is the application's — being captured a
   second time and looping.
3. Outbound UDP, so that a selected application's datagrams can be redirected to its lane and relayed
   through the proxy, or dropped when they cannot be (ADR W-0012). This is the expensive clause: every
   outbound datagram on the machine passes through the packet loop. It is here because a selected
   application's UDP must never leave unproxied.
4. Replies from the UDP lanes, on their way back to the application. Present only when UDP is relayed.
   The lanes are a contiguous block of loopback ports (`UdpLanePool`, 64 by default) reserved *before*
   the filter is built, so the filter can name that block and nothing else. An earlier version
   captured all outbound loopback UDP; on a machine whose DNS ran through a local tunnel that was ten
   thousand packets a second of other software's traffic, and name resolution broke. Naming the block
   took the packets captured in a minute from 618,646 to 8,315. If no block can be reserved, UDP is
   refused rather than relayed, and the clause is left out.

**DNS observer** — a separate sniffing handle, `inbound and udp and udp.SrcPort = 53`. Separate on
purpose: hostname recovery is an optimisation, and a parser bug in it must not be able to affect
packet delivery.

## 5. What this costs

On a busy machine, **every outbound TCP and UDP packet transits user mode and is reinjected**, for
as long as the engine is routing — including while routing is paused and while no rule selects
anything. For unselected applications the packet is returned unmodified, but it is copied.

This is not a limitation that can be engineered away without a kernel callout driver of our own, and
writing one would mean asking every user to trust an unsigned driver or paying for attestation
signing. That is a larger decision than this port should make quietly.

What keeps the cost down:

- **Loopback is excluded from the outbound clauses**, except the listener's replies and the reserved
  lane block. Local traffic — which on a developer machine is often the majority — is never captured.
- **DIRECT decisions are recorded**, so an unselected application's SYN does not wait for a decision
  that was already made. Measured by `tools/measure-direct-cost.ps1`: 8.16 ms per connection before
  that, 0.14 ms after.
- **Only a SYN ever waits**, and only when its decision has not arrived. Every other packet of an
  unselected application is a table lookup.

What does not: pausing. A paused engine still captures and reinjects; only stopping routing closes
the handles.

## 6. Loop prevention

Three independent layers, in the order they fire:

1. **Engine self-traffic goes DIRECT.** The first check in `RuleEngine.Decide`. Without it the
   engine's own connection to the proxy would be re-diverted into the engine, which is the one
   failure mode that takes the machine's networking with it.
2. **Loopback destinations are never proxied, for any application.** So even a mistaken rule degrades
   to "not proxied" rather than to recursion.
3. **The divert filter excludes loopback** except for the listener's own replies and the UDP lane
   block, so the redirected traffic is not recaptured on its way to the listener or a lane.

`RuleEngineTests` covers all three, including the ordering: engine self-traffic is checked before the
master switch, so no state can route the engine's upstream connection back into itself.

## 7. DNS

**DNS is not proxied, and cannot be by this design.** Windows resolves names in the DNS Client
service (`svchost.exe`), which is a different process from the application; the query has already
left the machine by the time SplitLane sees a connection to the resulting address.

What the engine does instead is sniff DNS *answers* and remember which name an address came from, so
that the SOCKS5 request can use `ATYP=DOMAIN` and let the upstream resolve the name from its own
vantage point. Without that, a CDN hands you an edge node chosen for where *you* are rather than
where the proxy is.

This improves routing quality. It does nothing for privacy, and the UI says so on the Overview page
rather than leaving it to be discovered.

### What an unproxied lookup costs

Only lookups made **through the Windows DNS Client service** escape. An application that resolves
names itself - its own UDP/53, or DNS over HTTPS/TLS - sends that traffic from its own process, and a
selected application's traffic goes through the proxy like everything else it sends (UDP relayed per
ADR W-0012, DoH/DoT as ordinary TCP). What escapes, then, is the ordinary `getaddrinfo` path most
applications use.

That path has these consequences for a selected application:

1. **The names are visible outside the proxy.** Every hostname the application looks up goes, in
   clear on port 53, to whatever resolver the machine uses - the corporate DNS, the ISP, a public
   resolver - and to anyone watching the local network. The connections themselves go through the
   proxy, but *which services the application talks to, and when* does not. With system-wide DoH
   (Windows 11) the network no longer sees it; the resolver still does.
2. **Blocking or poisoning happens before SplitLane is involved.** A resolver that answers NXDOMAIN
   or refuses leaves the application with nothing to connect to, and no routing decision can fix that.
   A resolver that answers with a wrong address is mostly survived: the engine sees the answer, sends
   the *name* to the proxy with `ATYP=DOMAIN`, and the proxy resolves it itself. Not when the name
   was cached before the engine started or was resolved over encrypted DNS the engine cannot read -
   then the proxy is given the wrong address as a literal.
3. **Names that only exist on the far side do not resolve.** An intranet reachable only through the
   proxy - `git.corp.internal` behind a remote office's SOCKS server - has no answer in local DNS, so
   the application fails before it connects. The reverse also bites: a split-horizon corporate DNS
   hands out an internal address the proxy side cannot reach.
4. **Geography and CDNs.** With the name known, the proxy resolves it from where it is and gets its
   own nearest edge. Without it (cached answers, encrypted DNS), the proxy is asked to connect to the
   edge chosen for *this* machine - slower, or refused by a service that checks region.
5. **"All of this application's traffic goes through the proxy" is not literally true.** For
   compliance regimes that require every egress of an application to be inspected or logged at the
   proxy, DNS is egress too. It is also the classic exfiltration channel: data encoded into lookups
   never passes the proxy's inspection.

### When it matters

It is **acceptable** - the default reading of this product - when the proxy is used to reach services
(an API that must be reached from a given region or network, a corporate egress for particular
applications), local DNS is trustworthy and complete, and the hostnames themselves are not sensitive.
`ATYP=DOMAIN` already takes care of CDN placement in that case.

It is **needed** when any of these holds:

- the names an application contacts must not be visible to the local network or its resolver;
- the local network blocks or poisons DNS for the services the application needs;
- the application needs names that only resolve on the proxy's side;
- policy requires that all of an application's egress, lookups included, pass through the proxy, or
  DNS exfiltration from that application is in the threat model.

### What can be done today, and what it would take

- **Make the application resolve its own names.** Chromium and Electron applications have a "secure
  DNS" (DoH) setting; with it on, their lookups are HTTPS from their own process and go through the
  proxy. The DoH server's own name is bootstrapped through system DNS unless configured by address.
- **System-wide encrypted DNS** hides lookups from the local network, not from the resolver, and
  applies to every application, not only the selected ones.
- **In SplitLane**, per-application DNS proxying needs to know which process asked, and the query
  leaves from `svchost.exe`. The DNS Client's ETW provider does report the requesting process id, so an
  engine could learn "a selected application asked for this name" and answer it through the proxy
  instead - a separate, sizeable piece of work, not started. Capturing all of port 53 would be simpler
  and would change DNS for applications that were never selected, which this product does not do.
