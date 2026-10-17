# DHCP bootstrap regression and Windows acceptance

Status: source fix and synthetic packet regression tests; live DHCP acquisition after boot on Windows 11 25H2 build 26200.9711 still requires acceptance. The report did not establish whether the DHCP service failed to start or was running but unable to obtain a lease. A packet-path regression cannot prove a service startup failure is fixed.

## Cause and scope

The latest public Windows release v0.13.1 and Corporate capture outbound non-loopback UDP through WinDivert. Routing starts with the Windows service. Even DIRECT traffic is captured and reinjected. WinDivert issue https://github.com/basil00/WinDivert/issues/320 reports DHCP broadcast failure with a pure passthrough capture during ipconfig /renew. Separately, SplitLane's strict classifier drops unattributed UDP while application protection is active; DHCP could therefore be dropped while its owner is unavailable or when rules select its process.

DHCP must remain on the Windows network stack. NetworkFilter now wraps all TCP/UDP/DNS/relay capture clauses with a DHCP exclusion. A matching classifier guard forwards DHCP unchanged before owner lookup, rules, NAT or rewriting if it reaches user mode anyway. Exact control-plane exceptions:

- IPv4 UDP client 68 → server 67 and server 67 → client 68.
- IPv6 UDP client 546 → server 547 and server 547 → client 546.

These are explicit reserved port-pair exceptions regardless of application rules, including unicast renew/rebind and unknown ownership at boot. The filter classifies by family/protocol/ports, not payload or process identity. It is not a general allowance for a DHCP port, broadcast, multicast, svchost.exe or arbitrary LAN traffic. TCP on these ports, wrong-family pairs, other destinations from the same port and traffic to only one matching port retain normal policy. DHCP relay/server-only pairs 67↔67 and 547↔547 are not exempted by this client fix.

No installer changes to the DHCP service, adapter configuration, firewall or driver startup type are made. The network driver/version and public/corporate update providers remain unchanged.

## Automated checks

DhcpBootstrapTests drives the real packet classifier with initial 0.0.0.0/broadcast, rebind, unicast renew, server replies and DHCPv6 exchanges, with unknown owners and Block/Proxy/ProxyOnly decisions. The original Corporate classifier failed all 54 DHCP cases; all 63 cases passed after the fix in each edition, including nine negative controls. Tests require neither WinDivert nor a network.

DhcpNativeFilterTests compiles and evaluates the actual complete generated filter via the pinned Windows WinDivert DLL. It checks DHCP exclusion in both directions with/without UDP relay lanes, retention of unrelated UDP and loopback relay replies. These helper APIs do not open a driver or require elevation. The Windows workflow fetches the hash-pinned DLL before build so it reaches the tests. This native test is explicitly Windows-only; Linux portable tests do not claim it passed. Filter evaluation does not test the WFP driver or acquire a DHCP lease.

## Windows acceptance (isolated VM with console access)

Use Windows 11 Enterprise 25H2, ideally the reported build 26200.9711, with a DHCP network and snapshot/console access. Record exact SplitLane version, adapter, IPv4/IPv6, DHCP server and configured app rules. Do not run release/renew over the only remote-access interface.

1. Before installation record Get-Service Dhcp,SplitLane (SplitLane may not exist), ipconfig /all, and available DHCP event channels (Get-WinEvent -ListLog '*Dhcp*'). Verify lease acquisition/renewal without SplitLane.
2. Install the candidate manually, retain the same DHCP adapter, reboot, and verify address/default gateway/DNS and service states before opening the UI. Test both with no selected applications and with normal application proxy/block rules active.
3. From the VM console run ipconfig /release then ipconfig /renew; verify a lease returns. Repeat renewal with an existing address to cover unicast renewal. If DHCPv6 is provided, repeat its acquisition/renewal separately.
4. Test routing active and paused; compare stopping SplitLane from the console if needed. Preserve engine update/divert errors and the Microsoft-Windows-Dhcp-Client events around the failure. A stopped/failed Dhcp service requires its exact SCM error and dependencies; do not change them to force a pass.
5. Repeat a reboot and confirm app proxy/block policy still works for ordinary TCP/UDP. Run native filter and packet tests as well. Uninstall/reboot and verify the network baseline returns.

Windows acceptance is pending until these results are recorded. No release tags, channel promotion or main/windows merges are authorized by merely adding this patch.

## Shared version numbering

Both editions declare the next coordinated Windows version as 0.14.0 in windows/release-version.txt. Directory.Build.props and the default installer builder read this file; release jobs reject tags that disagree. Public uses v0.14.0; Corporate uses corp-v0.14.0. The product number is identical; repositories, signing authorities, channels and manifests remain independent. Existing v0.13.1 and corporate testing tags 0.13.2–0.13.7 are not rewritten. Test-only builds may use explicit non-release versions. No 0.14.0 tag/release is created by this change; publication waits for Windows DHCP and the separate Corporate KES/updater acceptance.
