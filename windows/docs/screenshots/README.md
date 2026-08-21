# Screenshots

Captured by `tools/uiprobe/uiprobe.ps1` driving the real application through UI Automation. Nothing
here is a mockup.

`1`-`6` were taken against a development build with the engine in `--no-divert` mode. `7` is the
installed product: the MSI installed to Program Files, the engine started from there with WinDivert
loaded, and the app reporting it as live - counters, driver version and redirect port all read from
a running engine over the control channel.

| | |
|---|---|
| `1-overview.png` | Engine live. State, master switch, counters, and what SplitLane will not do. |

`1` and `3`-`6` are re-captured whenever the interface changes, so what the README shows is what
the current build looks like rather than what an earlier one did. `2` is older than the rest.

| `2-picker.png` | Adding an application from the running-process list. |
| `3-applications.png` | A saved rule. The banner is the round-trip through the control channel. |
| `4-proxy.png` | Upstream settings after a successful reachability test against a real SOCKS5 proxy. |
| `5-activity.png` | Recent connections. DIRECT decisions are counted, not listed. |
| `6-settings.png` | Diagnostics, storage, and the honest statement about how this differs from macOS. |
| `7-routing.png` | The installed build, connected to the installed engine with the driver loaded. |
| `8-light-theme.png` | The light theme, chosen in Settings and applied without a restart. |

The window is captured from the screen rather than rendered offscreen, so the composition backdrop is
included. The probe verifies it has foreground before reading pixels — an earlier version did not,
and captured whatever application happened to be on top instead.
