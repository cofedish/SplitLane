# SplitLane Networking

Everything in this document that describes Apple behaviour was read out of the macOS SDK headers
installed on the development machine, not from memory. Where a claim is still an assumption it is
marked **UNVERIFIED** and carries the experiment that will settle it.

SDK of record: `MacOSX15.5.sdk` (Command Line Tools), host macOS 15.6, arm64.
Header path: `/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks/NetworkExtension.framework/Headers`.

---

## 1. Verified API facts

### 1.1 Return semantics — the foundation of the whole design

`NETransparentProxyProvider.h`:

> The NETransparentProxyProvider class has the following behavior differences from its super class
> NEAppProxyProvider:
> - Returning NO from `handleNewFlow:` and `handleNewUDPFlow:initialRemoteEndpoint:` causes the
>   flow to proceed to communicate directly with the flow's ultimate destination, instead of
>   closing the flow with a "Connection Refused" error.
> - NEDNSSettings and NEProxySettings specified within NETransparentProxyNetworkSettings are
>   ignored. […]
> - Flows that are created using a "connect by name" API (such as Network.framework or
>   NSURLSession) that match the includedNetworkRules **will not bypass DNS resolution**.

Three consequences:

1. `return false` ⇒ DIRECT, natively, with no socket recreation. This is what makes "unselected
   apps are untouched" true rather than aspirational.
2. `return true` ⇒ we own the flow. If we then close it without relaying, the app sees a failed
   connection. **That is our BLOCK / fail-closed primitive.**
3. DNS is *not* bypassed for intercepted connect-by-name flows — the name is still resolved
   locally before we ever see the flow. See §4.

### 1.2 Flow metadata

`NEFlowMetaData.h`:

| Property | Availability | Notes from the header |
|---|---|---|
| `sourceAppSigningIdentifier` | macOS 10.11+ | "signing identifier (almost always equivalent to the bundle identifier) […] **may be empty** in cases where the flow originates from a system process" |
| `sourceAppAuditToken` | macOS 10.15+ | nullable `NSData` — the audit token of the source process |
| `sourceAppUniqueIdentifier` | macOS 10.11+ | "uniquely identifies the binary for each build" — cdhash-like, may be empty |
| `filterFlowIdentifier` | macOS 10.15.4+ | correlates with a content filter flow |

Note "**almost always** equivalent to the bundle identifier" — Apple explicitly declines to
guarantee equality. SplitLane therefore stores both the bundle identifier and the signing
identifier for a picked app and routes on the signing identifier. See ADR 0002.

### 1.3 Flow objects

`NEAppProxyFlow` (macOS 10.11+):
- `openWithLocalFlowEndpoint:completionHandler:` — macOS 15.0+; replaces the deprecated
  `openWithLocalEndpoint:`. **Must complete before any read/write.**
- `closeReadWithError:` / `closeWriteWithError:` — independent half-close.
- `remoteHostname` — macOS 11.0+, **nullable**.
- `metaData` — the `NEFlowMetaData` above.

`NEAppProxyTCPFlow`:
- `readDataWithCompletionHandler:` — a `nil`/empty `data` with `nil` error means EOF.
- `writeData:withCompletionHandler:`
- `remoteFlowEndpoint` (`nw_endpoint_t`) — macOS 15.0+, replaces deprecated `remoteEndpoint`.

`NEAppProxyUDPFlow`:
- `readDatagramsAndFlowEndpointsWithCompletionHandler:` — macOS 15.0+.
- `writeDatagrams:sentByFlowEndpoints:completionHandler:` — macOS 15.0+.
- `localFlowEndpoint` — macOS 15.0+.

`NEAppProxyProvider`:
- `handleNewFlow:` → `BOOL`
- `handleNewUDPFlow:initialRemoteFlowEndpoint:` → `BOOL` — macOS 15.0+ (`nw_endpoint_t` variant);
  the `NWEndpoint` variant is deprecated as of macOS 15.

Because the whole modern surface lands on macOS 15.0, SplitLane sets a **deployment target of
macOS 15.0** and uses the non-deprecated APIs exclusively. That avoids a codebase littered with
availability branches and deprecation warnings.

### 1.4 Network rules and their restrictions

`NETransparentProxyNetworkSettings.h` — restrictions on every rule in `includedNetworkRules` /
`excludedNetworkRules`:

> - If the port string of the endpoint is "0" or is the empty string, then the address of the
>   endpoint must be a non-wildcard address.
> - If the address is a wildcard address, then the port string must be non-empty and must not be "0".
> - **A port string of "53" is not allowed.** Destination Domain-based rules must be used to match
>   DNS traffic.
> - The `matchLocalNetwork` property must be nil.
> - The `matchDirection` property must be `NETrafficDirectionOutbound`.

`NENetworkRule.h`, on wildcard addresses:

> If the address is a wildcard address (i.e. "0.0.0.0" or "::") then the rule will match all
> destinations **except for loopback** (127.0.0.1 or ::1). To match loopback traffic set the
> address to the loopback address.

and on the remote/local constructor:

> If both remoteNetwork and localNetwork are nil then the rule will match all traffic of the given
> protocol and direction, **except for loopback traffic**.

### 1.5 IPC

`NETunnelProviderSession.sendProviderMessage:returnError:responseHandler:` exists (macOS 10.11+).
`NETransparentProxyManager` inherits `connection` from `NEVPNManager`; for provider-based
configurations that connection object is an `NETunnelProviderSession`.
**UNVERIFIED**: that the cast `manager.connection as? NETunnelProviderSession` succeeds for a
`NETransparentProxyManager` specifically. *Experiment:* at M3, log the dynamic type of
`manager.connection` immediately after `loadFromPreferences`. Fallback if the cast fails: bump
`ConfigurationVersion` in `providerConfiguration` and restart the proxy session, which is correct
but drops in-flight flows.

`NETunnelProviderProtocol.providerConfiguration` is an arbitrary plist dictionary stored in system
NE preferences. `NEVPNProtocol.passwordReference` takes a Keychain persistent reference for a
`kSecClassGenericPassword` item — this is where the SOCKS5 password goes.

---

## 2. The network rules SplitLane installs

```swift
// Outbound TCP to anywhere except loopback.
NENetworkRule(remoteNetworkEndpoint: nil, remotePrefix: 0,
              localNetworkEndpoint: nil, localPrefix: 0,
              protocol: .TCP, direction: .outbound)

// Outbound UDP to anywhere except loopback — needed so selected-app UDP can be
// failed closed rather than silently escaping. Unselected-app UDP returns false → DIRECT.
NENetworkRule(remoteNetworkEndpoint: nil, remotePrefix: 0,
              localNetworkEndpoint: nil, localPrefix: 0,
              protocol: .UDP, direction: .outbound)
```

No `excludedNetworkRules` are required for loopback: §1.4 shows loopback is already outside a
nil/wildcard rule. An explicit exclusion is *not* added, because adding one would be dead
configuration that implies a protection we are not actually relying on.

### Why UDP is included at all

If UDP were excluded from `includedNetworkRules`, selected-app QUIC traffic would never reach the
provider and would go straight out DIRECT — a silent bypass of the proxy, which violates the
project's core guarantee. Including UDP is what makes fail-closed possible. Unselected apps are
unaffected: they get `return false` and the identical DIRECT path they would have had.

---

## 3. Proxy loop prevention

The extension connects to `127.0.0.1:10808`. That connection must never be captured by SplitLane.

**Primary guarantee (platform, documented):** wildcard/nil remote address rules do not match
loopback. `127.0.0.1` and `::1` are outside the intercept set by construction. This is stated
twice in `NENetworkRule.h` (§1.4) and is not a side effect we are exploiting — it is the
documented behaviour of the API.

**Secondary guarantee (design):** SplitLane never constructs a rule whose remote address is a
loopback address. Rule construction lives in exactly one function,
`TransparentProxyProvider.makeNetworkSettings()`, so this is auditable in one place.

**Tertiary guarantee (defence in depth):** `FlowRouter` returns `.direct` for any flow whose
resolved remote address is loopback or link-local, regardless of the source app. A selected app
talking to `localhost` is not proxied. This costs one address comparison per flow and means a
future rule mistake degrades to "not proxied" rather than "infinite recursion".

**Verification procedure (run at M8):**

1. Start the provider with a selected app configured.
2. `sudo lsof -nP -iTCP:10808` — the only client of the SOCKS5 port must be the extension process.
3. In the provider log, confirm no flow is ever seen with remote endpoint `127.0.0.1:10808`:
   `log stream --predicate 'subsystem == "dev.cofe.splitlane"' --info | grep 10808`
4. Confirm the relay does not stall — a loop would manifest as a hang plus growing flow count.

---

## 4. DNS — the honest picture

**SplitLane does not proxy DNS, and cannot, within this architecture.**

Three independent reasons, all from §1:

1. `includedNetworkRules` may not contain a rule with port `"53"`. Address-based interception of
   DNS is prohibited by the API.
2. Domain-based rules exist but require enumerating the domains in advance, which defeats the
   purpose of a general app router.
3. Even for flows we *do* intercept, the header states connect-by-name flows "will not bypass DNS
   resolution" — resolution has already happened locally by the time the flow reaches us.

Additionally, most macOS DNS goes through `mDNSResponder`, a separate process. Its flows carry
`sourceAppSigningIdentifier == "com.apple.mDNSResponder"`, not the requesting app's identifier, so
they would not match a selected-app rule even if they were interceptable.

### What this means

- The DNS query for `chatgpt.com` is visible to the local network / ISP even when the connection
  to it is proxied. **This is a real privacy leak and it is documented, not hidden.**
- Because the app already resolved the name, SplitLane must not blindly send the resolved IP to
  the SOCKS5 server: CDN geolocation would then be computed from the *local* resolver's answer.
  SplitLane sends `ATYP = DOMAIN` with `flow.remoteHostname` whenever it is non-nil, so the
  upstream re-resolves from its own vantage point. Only when `remoteHostname` is nil (BSD-socket
  apps that connect straight to an IP) does SplitLane send `ATYP = IPv4/IPv6`.
- Mitigation is out of MVP scope. The roadmap entry is "DNS lane": either a companion
  `NEDNSProxyProvider` or forcing selected apps at DoH. Both are post-M10.

**UNVERIFIED**: the actual population rate of `remoteHostname` for the target app. *Experiment:*
M4 flow diagnostics logs `remoteHostname != nil` per flow per app; the M4 report records the
observed ratio for Codex, Safari, and a BSD-socket client such as `curl`.

---

## 5. UDP policy

| | TCP | UDP |
|---|---|---|
| **Unselected app** | `return false` → DIRECT | `return false` → DIRECT |
| **Selected app** | `return true` → SOCKS5 relay | `return true`, then close → **fail closed** |

Fail-closed UDP is implemented by returning `true` from
`handleNewUDPFlow:initialRemoteFlowEndpoint:` and immediately calling
`closeReadWithError:`/`closeWriteWithError:` with `NEAppProxyFlowErrorRefused` — *without* opening
the flow. The app observes datagram failure and, if it implements HTTP/3 → HTTP/2 fallback (as
Chromium, Electron and `URLSession` all do), retries over TCP, which SplitLane proxies correctly.

**UNVERIFIED**: that closing an unopened UDP flow is legal and surfaces as a clean error to the
app rather than a hang. *Experiment:* M9 — select a QUIC-capable app, confirm via provider logs
that UDP flows are refused, and confirm via Activity that the app's subsequent TCP flows appear.
If closing an unopened flow misbehaves, the fallback is to open it and then immediately close it,
at the cost of one wasted flow setup.

Risk accepted: an app with no TCP fallback (a game, a VoIP client, a DNS-over-QUIC-only resolver)
will lose connectivity when selected. This is the correct trade for a tool whose entire promise is
"selected traffic does not leak", and it is surfaced in the UI as a warning on the app row rather
than silently.

`ProxyConfiguration.allowDirectFallback` exists in the model, defaults to `false`, and has no UI.
It is the future opt-in for users who prefer leaks to breakage. Turning it on is a deliberate,
documented downgrade of the security property.

---

## 6. Destination selection for SOCKS5 CONNECT

```
remoteHostname != nil  ──▶  ATYP = 0x03 (DOMAIN), send the name, upstream resolves
remoteHostname == nil  ──▶  ATYP = 0x01 / 0x04, send the IP from remoteFlowEndpoint
```

SplitLane never performs its own `getaddrinfo`. There is no local resolve step and no DNS engine
in the MVP.

---

## 7. Failure behaviour (fail-closed matrix)

Every one of these closes the flow with an error. None of them fall back to DIRECT.

| Condition | Result |
|---|---|
| SOCKS5 upstream connection refused | flow closed, `ConnectionEvent.error = .upstreamUnreachable` |
| SOCKS5 negotiation: no acceptable method | flow closed, `.authenticationUnsupported` |
| SOCKS5 auth failure (RFC 1929 status ≠ 0) | flow closed, `.authenticationFailed` |
| SOCKS5 reply status ≠ 0x00 | flow closed, `.socksReply(code)` |
| Handshake exceeds timeout | flow closed, `.timedOut` |
| Selected-app UDP flow | flow closed, `.udpNotSupported` |
| Provider stopping | all flows closed, relays cancelled |

The UI surfaces the last error per application so a misconfigured proxy is visible rather than
mysterious.

---

## 8. Known leak windows (documented, not fixed)

1. **DNS**, §4. Structural.
2. **Provider not running.** If the extension is not installed/approved/enabled, or crashes and is
   being restarted, flows go DIRECT — the kernel has no rule to consult. Nothing inside the
   provider can prevent this; the host app surfaces provider state prominently in Overview so the
   user can see the lane is not armed.
3. **Traffic that never becomes a flow.** Raw sockets, ICMP, and anything not TCP/UDP are outside
   `NENetworkRule`'s vocabulary entirely.
4. **Loopback by design.** A selected app talking to another local service is not proxied (§3).
5. **Pre-existing connections.** Toggling a rule ON does not migrate already-established
   connections into the proxy lane; they keep their original path until they close.

These are listed in `docs/THREAT_MODEL.md` with severity and mitigation status.
