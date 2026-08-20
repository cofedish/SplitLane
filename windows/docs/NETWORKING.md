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
                    │  pid ──▶ image path (cached, keyed on pid + start time)
                    │  RuleEngine.Decide(...)
                    │
                    ├─ PROXY  ──▶ NatTable.Record(localPort, original destination)
                    ├─ BLOCK  ──▶ counter only; the packet layer drops the datagrams
                    └─ DIRECT ──▶ counter only; nothing else happens, ever
                    ▼
        SYN leaves ──▶ NETWORK layer
                    │  NatTable lookup by source port
                    ├─ hit  ──▶ rewrite to the loopback listener, reinject
                    └─ miss ──▶ reinject byte-for-byte, unmodified
```

Windows guarantees the ordering: the socket-layer event is delivered before the SYN is sent. Without
that guarantee the design would not work.

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

## 4. The divert filters

Three handles, opened only while routing is active.

**Socket layer** — sniffing, cannot block:

```
event = CONNECT or event = BIND or event = CLOSE
```

`BIND` is there for UDP attribution. An unconnected `sendto()` never produces a `CONNECT`, so without
tracking binds a selected application's QUIC traffic would be unattributable at the packet layer and
would escape DIRECT — the exact leak ADR 0004 exists to prevent.

**Network layer** — the only handle that modifies anything:

```
(outbound and tcp and not loopback) or
(outbound and tcp and loopback and tcp.SrcPort = <listener>) or
(outbound and udp and not loopback)
```

Each clause earns its place:

1. Application traffic that may need redirecting.
2. Replies from the redirect listener, which need restoring. Matching on the *listener's* source port
   is what stops the redirected traffic — whose source port is the application's — being captured a
   second time and looping.
3. Outbound UDP, needed only so that a selected application's datagrams can be dropped. This is the
   expensive clause and it is here because failing closed matters more than throughput.

**DNS observer** — a separate sniffing handle, `inbound and udp and udp.SrcPort = 53`. Separate on
purpose: hostname recovery is an optimisation, and a parser bug in it must not be able to affect
packet delivery.

## 5. What this costs

On a busy machine, **every outbound TCP and UDP packet transits user mode and is reinjected**. For
unselected applications the packet is returned unmodified, but it is copied.

This is not a limitation that can be engineered away without a kernel callout driver of our own, and
writing one would mean asking every user to trust an unsigned driver or paying for attestation
signing. That is a larger decision than this port should make quietly.

Two mitigations are in place, and they matter:

- **The handles are closed unless something needs routing.** No enabled PROXY rule, or routing
  paused, means no handle, means zero interception. A paused SplitLane on Windows really is inert.
- **Loopback is excluded from the outbound clause.** Local traffic — which on a developer machine is
  often the majority — is never captured.

## 6. Loop prevention

Three independent layers, in the order they fire:

1. **Engine self-traffic goes DIRECT.** The first check in `RuleEngine.Decide`. Without it the
   engine's own connection to the proxy would be re-diverted into the engine, which is the one
   failure mode that takes the machine's networking with it.
2. **Loopback destinations are never proxied, for any application.** So even a mistaken rule degrades
   to "not proxied" rather than to recursion.
3. **The divert filter excludes loopback** except for the listener's own replies, so the redirected
   connection is not recaptured on its way to the listener.

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
