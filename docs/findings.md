# Findings

Severity reflects impact on this home network, not a CVSS score. Evidence for September items is in [`08_Live_Assessment_2026-09-28/`](../08_Live_Assessment_2026-09-28/).

| ID | Severity | Finding | Status |
|---|---|---|---|
| F-01 | High | Both routers used `192.168.0.0/24` with gateway `192.168.0.1` | Remediated, validated |
| F-02 | Medium | UPnP Internet Gateway Device enabled on ROUTER-A | Open |
| F-03 | Low | NAS-01 services exposed to every Domain A host | Open |
| F-04 | Low | NAS-01 advertises its Domain B address into Domain A | Open |
| F-05 | Low | Unidentified device on Domain A | Open |
| F-06 | Info | ICMP-only discovery missed Windows hosts on the Public profile | Understood |

## F-01 Overlapping LAN address space

- **Observed (July):** ROUTER-A and ROUTER-B were both `192.168.0.1/24`. MAC-CLIENT-01 and MAC-CLIENT-02 resolved the same gateway IP to different vendor MACs (`3C:6A:D2` TP-Link and `24:2F:D0`). NAS-01 held `192.168.0.2` on LAN 1 and `192.168.0.242` on LAN 2, two interfaces in one prefix on two different Layer 2 segments.
- **Impact:** hosts that look like neighbors at Layer 3 cannot reach each other. The dual-homed NAS has two connected routes for the same /24 and can answer on the wrong port. Inventories from different machines contradict each other.
- **Fix:** ROUTER-B moved to `192.168.20.0/24`. NAS-01 LAN 2 set to static `192.168.20.2` with no gateway.
- **Validation:** see [validation](validation.md).

## F-02 UPnP IGD on ROUTER-A

- **Observed:** SSDP advertises `InternetGatewayDevice:1` with `WANIPConnection:1` (MiniUPnPd 2.2.2), TCP and UDP 1900 open.
- **Impact:** any program on any LAN device can open inbound port forwards without the owner knowing.
- **Recommendation:** disable UPnP in the router UI unless a specific application needs it, then review the port-forwarding table.

## F-03 NAS-01 service exposure

- **Observed:** SSH 22, SMB 139/445, DSM over HTTP 5000 and HTTPS 5001, iSCSI 3261-3265 and Snapshot Replication 5566 are reachable from every Domain A host.
- **Recommendation:** turn SSH off when not in use, redirect DSM HTTP to HTTPS, restrict iSCSI targets to known initiators with CHAP, and limit services in the DSM firewall to the hosts that use them.

## F-04 Cross-domain advertisement

- **Observed:** NAS-01 answered an SSDP search on Domain A with two locations, `192.168.0.2:5000` (eth0) and `192.168.20.2:5000` (eth1).
- **Impact:** low. It discloses Domain B addressing but gives no path to it. It was also the evidence that confirmed the new LAN 2 address.
- **Recommendation:** disable SSDP/UPnP discovery on LAN 2 if Domain B clients do not need to discover the NAS.

## F-05 Unidentified device

- **Observed:** `192.168.0.118`, Elitegroup OUI, Linux TCP/IP stack, TCP 5005 and 65527, present in both rounds. `192.168.0.156` appears in both rounds but only answered while the scans were not running.
- **Recommendation:** identify both from ROUTER-A's DHCP client list and record them in the inventory.

## F-06 ICMP-only discovery gaps

- **Observed:** WIN-CLIENT-02 answered ARP but not ping. Its Ethernet was on a Windows Public profile, which drops inbound echo by default. MAC-CLIENT-01 now drops all TCP probes (stealth mode), where in July it had TCP 5000 open.
- **Takeaway:** use ARP discovery on local segments and treat ICMP silence as "unknown", not "absent".

## What was healthy

One gateway MAC and one DHCP server on Domain A, zero duplicate-address alerts, one default route, zero adapter errors, and DNS answered in 13.6 ms on average.
