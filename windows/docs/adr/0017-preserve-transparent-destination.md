# ADR 0017: Preserve the destination of transparent TCP flows

Status: accepted for the TLS-name regression fix.

## Problem

Windows socket events carry an IP, not the application's requested hostname. DnsObserver is shared
across flows. Its ambiguity check prevents choosing between two *observed* aliases, but a single
observed alias is not proof either: the application's answer may have been cached before the engine
started or obtained over encrypted DNS. Substituting this alias changes HTTP CONNECT while the
application's TLS SNI stays unchanged. KES traces show CONNECT bridge.claudeusercontent.com with SNI
claude.ai, a valid server chain, CERT_E_CN_NO_MATCH, then a client certificate_unknown alert.

## Decision

RedirectListener opens the upstream tunnel to NatEntry.OriginalDestination and its original port.
This applies to both HTTP and SOCKS5; no server-first protocol is delayed to sniff TLS. Explicitly
named upstream health checks still work. TLS verification and the original TLS bytes are unchanged.
DNS evidence remains available to domain policies. The obsolete hostname preference is hidden from
the UI; its JSON field remains readable for compatibility and cannot re-enable alias substitution.

## Trade-offs and acceptance

Remote DNS/CDN reselection is no longer performed for transparent TCP. A proxy that forbids IP
CONNECT can refuse the tunnel; that refusal remains visible and never becomes DIRECT fallback.
Validate the corporate proxy and KES on a Windows pilot before rollout. Do not bypass certificate,
revocation, manifest or publisher validation. Domain routing policy inference is unchanged by this fix.

Integration regressions cover a single observed alias, the legacy flag on/off, no alias, actual HTTP
CONNECT authority on the wire, and SOCKS5's address type/original destination. The single-alias case
must fail against the previous implementation; a populated multi-alias cache alone misses this bug.
