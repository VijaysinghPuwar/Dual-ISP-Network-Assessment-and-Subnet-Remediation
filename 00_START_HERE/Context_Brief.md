# Context brief

One page that explains the whole project. Everything here is sanitized. Asset names such as `WIN-CLIENT-01` replace real hostnames.

## Summary

A home network runs **two independent routers on two separate ISP services**, and a **NAS with one network port on each router**. Both routers shipped with the same default LAN (`192.168.0.0/24`, gateway `192.168.0.1`) and were never changed. The result was two physically separate networks that looked identical at Layer 3. Hosts on one could not see hosts on the other, and inventories taken from different machines disagreed.

The fix moved ROUTER-B to `192.168.20.0/24` and gave NAS-01's second port a static `192.168.20.2` with no gateway. A September 2026 re-assessment from Domain A, using Nmap, tshark and PowerShell, found one gateway MAC for `192.168.0.1`, one DHCP server, no duplicate addresses, NAS-01 LAN 2 advertising itself at `192.168.20.2`, and no path from Domain A to `192.168.20.0/24`. That confirms the design from the Domain A side.

## Assets

| Asset | What it is | Network | Address |
|---|---|---|---|
| ROUTER-A | TP-Link Archer AX53, ISP-A | Domain A | `192.168.0.1` |
| ROUTER-B | TP-Link Archer AX10 (AX1500), ISP-B, PPPoE WAN | Domain B | `192.168.0.1` before, `192.168.20.1` after |
| NAS-01 | Synology DS423+, two 1 GbE ports | both | LAN 1 `192.168.0.2`; LAN 2 `192.168.0.242` before, `192.168.20.2` after |
| WIN-CLIENT-01 | Windows 11 workstation, main scanning host | Domain A | `192.168.0.135` |
| MAC-CLIENT-01 | Mac mini (M4 Pro) | Domain A | `192.168.0.201` |
| MAC-CLIENT-02 | Mac mini (M2 Pro) | Domain B | `192.168.0.8` (July) |
| WIN-CLIENT-02 | Windows 11 workstation, diagnostic only | Domain B | `192.168.0.56` (July) |

## Timeline

| Date | Round | What happened |
|---|---|---|
| 2026-07-26 | Discovery | Custom inventory scripts run from WIN-CLIENT-01, MAC-CLIENT-01 and MAC-CLIENT-02, plus a full diagnostic on WIN-CLIENT-02. The two Macs got different gateway MACs for the same gateway IP. |
| 2026-07 | Remediation | ROUTER-B readdressed to `192.168.20.0/24`, NAS-01 LAN 2 set to `192.168.20.2` static, no gateway (as documented in the report) |
| 2026-09-28 | Re-assessment | Nmap, tshark and PowerShell baseline from WIN-CLIENT-01 on Domain A (broadcast discovery re-run 2026-09-29) |

## Where to look

| Question | File |
|---|---|
| What was found, how bad is it? | [`docs/findings.md`](../docs/findings.md) |
| Why did it happen? | [`docs/root-cause-analysis.md`](../docs/root-cause-analysis.md) |
| Why did each machine see something different? | [`docs/root-cause-analysis.md#multi-vantage-evidence`](../docs/root-cause-analysis.md#multi-vantage-evidence) |
| How was the fix checked? | [`docs/validation.md`](../docs/validation.md) |
| How was it done? | [`docs/methodology.md`](../docs/methodology.md) |
| September evidence | [`08_Live_Assessment_2026-09-28/`](../08_Live_Assessment_2026-09-28/) |

## Known quirks in the July data

- WIN-CLIENT-01's July scan labelled `.201` "Synology NAS (likely)" because TCP 5000 was open. It is MAC-CLIENT-01. MAC-CLIENT-02 shows the same port, which is consistent with the macOS AirPlay Receiver listening on 5000 (inferred, not verified).
- The macOS scanner counted multicast and broadcast addresses (`224.0.0.251`, `239.255.102.18`, `.255`) as devices, so its totals are inflated.
- `.56` answered ARP but not ping. It is WIN-CLIENT-02, whose Ethernet was on a Windows *Public* network profile.
