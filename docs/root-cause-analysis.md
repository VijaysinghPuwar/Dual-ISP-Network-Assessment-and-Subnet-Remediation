# Root cause analysis

Each statement is tagged **Observed** (seen directly in data), **Inferred** (follows from observations), or **Not tested**.

## Symptom

Device lists from different computers disagreed. The Windows scan on ROUTER-A found 5 hosts and the Mac on the same router found 6. The Mac on ROUTER-B found a different set of 7, including a second Synology-like device at `.242`. One Windows PC answered ARP but not ping.

## Multi-vantage evidence

| Vantage point | Router | Gateway MAC for `192.168.0.1` | NAS address seen |
|---|---|---|---|
| WIN-CLIENT-01 `.135` | A | `3C:6A:D2` (TP-Link) | `.2` |
| MAC-CLIENT-01 `.201` | A | `3C:6A:D2` (TP-Link) | `.2` |
| MAC-CLIENT-02 `.8` | B | `24:2F:D0` | `.242` |
| WIN-CLIENT-02 `.56` | B | ARP entries only for `.1` and `.242` | `.242` (SMB session) |

- **Observed:** one gateway IP, two different MACs, depending on where you ask from.
- **Observed:** no host saw hosts from both groups.
- **Inferred:** two separate broadcast domains using the same prefix. Layer 3 identity was duplicated; Layer 2 was not shared, so no live IP conflict occurred.

![Vantage visibility](../08_Live_Assessment_2026-09-28/charts/vantage_visibility.png)

## Why it happened

1. **Observed:** both TP-Link routers ship with `192.168.0.1/24` as the LAN default. Neither was changed when the second ISP line was added.
2. **Observed:** NAS-01 was cabled to both routers and held an address in the same /24 on each port, `192.168.0.2` and `192.168.0.242`.
3. **Inferred:** with two interfaces in one /24, the NAS has two equal connected routes. Replies to a client on either LAN can leave through the wrong port, which can cause intermittent SMB and DSM failures.
4. **Inferred:** a host moved between routers keeps the same gateway IP, so nothing looks wrong at Layer 3. The fault is only visible in the ARP table.

## Why it went unnoticed

- Each LAN worked on its own. Internet access, DHCP and DNS were fine everywhere.
- Ping-based discovery hid part of Domain B (WIN-CLIENT-02 drops ICMP).
- MAC-CLIENT-01 had TCP 5000 open (macOS AirPlay Receiver, inferred), so WIN-CLIENT-01's port-based guess labeled it "Synology NAS (likely)".

## Fix

Give each domain its own prefix and keep the NAS from routing between them.

| Change | Why |
|---|---|
| ROUTER-B LAN to `192.168.20.1/24` | Removes the duplicate prefix and gateway |
| NAS-01 LAN 2 to static `192.168.20.2`, no gateway | One default route (via Domain A), no asymmetric replies |
| No bridging or forwarding on NAS-01 | The two ISP domains stay isolated by design |

Validation of each change: [validation](validation.md).
