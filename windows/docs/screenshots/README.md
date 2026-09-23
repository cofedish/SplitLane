# Screenshots

Captured by `tools/uiprobe/uiprobe.ps1` driving the real application through UI Automation. Nothing
here is a mockup.

| File | What it shows | Engine behind it |
|---|---|---|
| `1-overview.png` | State, master switch, counters, and what SplitLane will not do. | development build, WinDivert 2.2 loaded, routing |
| `2-picker.png` | Adding an application from the running-process list. | `--no-divert` — the sidebar reads "Divert layer off" |
| `3-applications.png` | A rule in the proxy lane, with *Include folder* ticked. | development build, WinDivert 2.2 loaded, routing |
| `4-proxy.png` | Upstream settings and the authentication section. | development build, WinDivert 2.2 loaded, routing |
| `5-activity.png` | Recent connections, each relayed through the proxy. DIRECT decisions are counted, not listed. | development build, WinDivert 2.2 loaded, routing |
| `6-settings.png` | Appearance, the divert layer's state, the honest statement about how this differs from macOS, and diagnostics. | development build, WinDivert 2.2 loaded, routing |
| `7-routing.png` | The installed build, connected to the installed engine with the driver loaded. | installed product |
| `8-light-theme.png` | The light theme, chosen in Settings and applied without a restart. | development build, WinDivert 2.2 loaded, routing |

Only `2` was taken with the engine in `--no-divert` mode. `1` and `3`-`6` and `8` are a development
build with the divert layer live: the sidebar reads "Routing, WinDivert 2.2", and the counters and
Activity rows are traffic that actually went through the proxy. `7` is the installed product: the MSI
installed to Program Files, the engine started from there with WinDivert loaded, and the app reporting
it as live - counters, driver version and redirect port all read from a running engine over the
control channel.

All of them are older than the current interface. Since they were taken, the Applications page has
changed to show how each application is recognised (ADR W-0013) rather than a publisher badge, and the
Overview's text has changed with it - `7` still says a selected application's UDP is refused, where
the current build says it is relayed through the proxy (ADR W-0012). `2` is older than the rest.

The window is captured from the screen rather than rendered offscreen, so the composition backdrop is
included. The probe verifies it has foreground before reading pixels — an earlier version did not,
and captured whatever application happened to be on top instead.
