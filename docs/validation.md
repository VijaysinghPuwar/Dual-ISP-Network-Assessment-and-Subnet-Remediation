# Validation

Tests run on 28-29 September 2026 from WIN-CLIENT-01 on Domain A. Evidence: [`08_Live_Assessment_2026-09-28/`](../08_Live_Assessment_2026-09-28/).

| # | Expectation after the fix | Method | Result |
|---|---|---|---|
| V1 | Exactly one device owns `192.168.0.1` on Domain A | ARP bindings in two tshark captures | **Pass.** 90 ARP frames, one MAC (`3C:6A:D2`) |
| V2 | Exactly one DHCP server on Domain A | Nmap `broadcast-dhcp-discover` | **Pass.** One offer, from `192.168.0.1` |
| V3 | No duplicate IPv4 addresses | Wireshark `arp.duplicate-address-detected`, neighbor cache | **Pass.** 0 alerts, no duplicates |
| V4 | NAS-01 LAN 2 is `192.168.20.2` | NAS SSDP advertisement for its eth1 interface | **Pass.** `http://192.168.20.2:5000` |
| V5 | Domain B is not reachable from Domain A | Nmap ICMP echo and TCP SYN 22/80/443/5001 to `192.168.20.1` and `.2` | **Pass.** 0 of 2 hosts up |
| V6 | Scanning host has a single egress path | Default routes in `Get-NetRoute` | **Pass.** One `0.0.0.0/0` via `192.168.0.1` |
| V7 | ROUTER-B answers on `192.168.20.1` | Needs a host on Domain B | **Not tested** |
| V8 | NAS-01 default route is via LAN 1 only | Needs DSM or SSH access to the NAS | **Not tested** |

## Reading V4 and V5 together

V5 on its own cannot tell "isolated" from "not there". V4 shows `192.168.20.2` exists on the NAS, so the failed probes in V5 mean the address is configured but not reachable from Domain A. Together they confirm the design for NAS-01.

## Remaining steps

1. From a Domain B host: `ipconfig` / `ipconfig getifaddr en0` shows `192.168.20.x`, and `arp -a` shows ROUTER-B's MAC for `192.168.20.1` (V7).
2. On NAS-01: `ip route` shows one default route via `192.168.0.1` (V8).
3. From Domain B, repeat the ARP discovery and the negative test toward `192.168.0.0/24`.
