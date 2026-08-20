# Screenshots

Captured by `tools/uiprobe/uiprobe.ps1` driving the real application through UI Automation, with the
engine running in `--no-divert` mode. Nothing here is a mockup.

| | |
|---|---|
| `1-overview.png` | Engine live. State, master switch, counters, and what SplitLane will not do. |
| `2-picker.png` | Adding an application from the running-process list. |
| `3-applications.png` | A saved rule. The banner is the round-trip through the control channel. |
| `4-proxy.png` | Upstream settings after a successful reachability test against a real SOCKS5 proxy. |
| `5-activity.png` | Recent connections. DIRECT decisions are counted, not listed. |
| `6-settings.png` | Diagnostics, storage, and the honest statement about how this differs from macOS. |

The window is captured from the screen rather than rendered offscreen, so the composition backdrop is
included. The probe verifies it has foreground before reading pixels — an earlier version did not,
and captured whatever application happened to be on top instead.
