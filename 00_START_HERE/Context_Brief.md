# Home Network — Context Brief

> Paste this whole file into a new Claude session to give full context. It summarizes a set of network-inventory scans, one Windows diagnostic, and a series of topology diagrams for a home network. All data was generated 2026-07-26.

---

## 1. The one-paragraph summary

This is a **home network with two independent routers and two internet plans**, plus a **Synology NAS that bridges both**. The routers were originally *both* configured on the same LAN subnet (`192.168.0.0/24`) with the same gateway IP (`192.168.0.1`), which is a misconfiguration — two separate physical LANs pretending to be one network, told apart only by different router MAC addresses. The fix (already designed, see the final diagram) is to **move Router B to its own subnet `192.168.20.0/24`** and move the Synology's second LAN port to `192.168.20.2`. The scans in this folder were taken from three different computers, which is why each one "sees" a different slice of the network.

---

## 2. The hardware

**Routers**
- **Router A** — TP-Link Archer AX53 (AX3000). LAN `192.168.0.1/24`. MAC `██:██:██:██:██:██`. Own internet plan (Plan A). DHCP on.
- **Router B** — TP-Link AX1500 Wi-Fi 6. Originally `192.168.0.1/24` (conflict); **target = `192.168.20.1/24`**. MAC `██:██:██:██:██:██`. Own internet plan (Plan B). DHCP on.

**Synology NAS — DS423+ (dual-homed, one physical box, two LAN cables)**
- LAN 1 → Router A. IP `192.168.0.2`. MAC `██:██:██:██:██:██`.
- LAN 2 → Router B. IP `192.168.0.242` originally; **target = `192.168.20.2`**. MAC `██:██:██:██:██:██`.
- Services: SSH 22, HTTP 80, NetBIOS 139, HTTPS 443, SMB 445, DSM 5000/5001, Synology Drive 6690.

**Computers that ran scans / diagnostics**
| Name | Type | Key specs | On which LAN | Its IP |
|---|---|---|---|---|
| DESKTOP-282LTKE | Windows 11 Pro PC (ASUS) | Ryzen 7 7700X, 16 GB; has VirtualBox `192.168.56.1` + Docker | Router A | `192.168.0.135` |
| Vijaysinhh's Mac mini | Mac mini **M4 Pro** (Mac16,11) | 24 GB, macOS 26.3.1 | Router A | `192.168.0.201` |
| Vijaysinhh's Mac mini (2) | Mac mini **M2 Pro** (Mac14,12) | 16 GB, macOS 26.5.1 | **Router B** | `192.168.0.8` |
| AUDIOBOOK | Windows 11 Pro PC (Gigabyte H410M) | user `vpuwa`; full system diagnostic only | (own LAN) | — |

---

## 3. The core problem (as diagnosed)

Both routers were on **the same subnet AND the same gateway IP** (`192.168.0.0/24`, gw `192.168.0.1`) but are **physically separate LANs**. Consequences:
- Devices on Router A and Router B can have overlapping/duplicate IPs.
- The gateway IP is ambiguous — you can only tell the two routers apart by MAC.
- A scan from a machine on Router A cannot see Router B's devices and vice versa.

**Evidence it's two LANs, not one:** the M4 Pro Mac (`.201`) and the M2 Pro Mac (`.8`) both report gateway `192.168.0.1`, but the gateway's **MAC differs** — `██:██:██:██:██:██` (Router A) vs `██:██:██:██:██:██` (Router B). They also see completely different device lists.

## 4. The fix (target state — already drawn in the final diagram)

- Router B LAN → `192.168.20.1/24` (separate subnet).
- Synology LAN 2 → `192.168.20.2`.
- Result: two clean subnets, each with its own router + ISP; Synology reachable from both.
- Management after fix: Router A `http://192.168.0.1`, Router B `http://192.168.20.1`, Synology DSM `https://192.168.20.2:5001`, SMB `smb://192.168.20.2/home`.

---

## 5. Devices seen, by scan

**Router A side** (seen by Windows PC `.135` and M4 Pro Mac `.201`):
- `.1` Router A · `.2` Synology LAN1 · `.118` unknown (stable) · `.135` Windows PC · `.156` unknown wireless · `.201` M4 Pro Mac · (`.45` referenced in diagrams)

**Router B side** (seen by M2 Pro Mac `.8`):
- `.1` Router B · `.8` M2 Pro Mac · `.52` unknown · `.56` unknown (ARP only, blocks ping) · `.107` unknown · `.228` web-managed device (port 80) · `.242` Synology LAN2

Note: Mac scans also list multicast/broadcast addresses (`224.0.0.251`, `239.255.102.18`, `.255`) — these are **not real devices**.

---

## 6. Folder structure (how this project is arranged)

```
Dual-ISP Network Assessment and Subnet Remediation/
├── README.md                         Project front page + folder map
├── 00_START_HERE/
│   └── Context_Brief.md              THIS file — full context in one page
├── 01_Scanner_Scripts/
│   ├── Home_Network_Inventory_v1.5.ps1   Windows scanner (ping+ARP+TCP → HTML/PDF/CSV/JSON/log)
│   └── Mac_Network_Inventory_v1.1.sh     macOS port of the same tool
├── 02_Scan_Results/                  One subfolder per computer that scanned
│   ├── 01_Windows-PC_DESKTOP-282LTKE_192.168.0.135/   (Router A side)
│   ├── 02_Mac-mini-M4-Pro_192.168.0.201/              (Router A side)
│   └── 03_Mac-mini-M2-Pro_192.168.0.8/                (Router B side)
├── 03_System_Diagnostics/
│   └── AUDIOBOOK_Windows_System_Diagnostic.txt   43-section single-PC health/forensics dump
├── 04_Topology_Diagrams/             Numbered in the order the understanding evolved
│   ├── 01_Windows-scan_5-devices.png                 Earliest, Windows-only, one router assumed
│   ├── 02_Windows+Mac_combined.png                   Two Router-A scans merged
│   ├── 03_Discovered_dual-LAN_subnet-conflict.png    THE DIAGNOSIS (two LANs, one subnet)
│   ├── 04_Target-state_subnet-remediation.png        THE FIX (Router B → 192.168.20.x)
│   └── 05_Summary_infographic_conflict-and-remediation.png   One-page overview
├── 05_Report/                        Technical write-up
│   ├── Dual-ISP_Network_Assessment_and_Subnet_Remediation.pdf         IEEE-style report
│   └── Dual-ISP_Network_Assessment_and_Subnet_Remediation_slides.pptx slide-form twin
├── 06_Presentation/
│   └── Dual-ISP_Subnet_Remediation_visual-deck.pptx   11-slide visual infographic deck
└── 07_Media/
    └── Why_two_routers_crashed_this_PC.m4a            Audio explainer
```

**Inside each `02_Scan_Results` machine folder**, filenames are normalized: `Network_Inventory_Report.html`, `Network_Inventory_Report.pdf`, `Network_Inventory.json`, `Network_Devices.csv`, `Network_Inventory.log`, and (Mac only) `Network_Inventory.txt`. The Windows PowerShell scanner does not emit a `.txt`.

> **Important — why files were re-sorted by content, not name:** the original downloads had misleading `(1)`/`(2)` suffixes from browser filename collisions. The suffixes did **not** line up across file types (e.g. the no-suffix `.txt` was actually the M4 Pro Mac, while the no-suffix `.json`/`.csv`/`.log` were the Windows PC). Every file here was placed by reading its actual contents. Two byte-identical copies of the target diagram existed; one was removed.

---

## 7. Known data quirks (don't be misled)

- The **Windows scan mislabeled `.201`** as "Synology (likely)" — it's actually the M4 Pro Mac. Later diagrams corrected this.
- "8 devices" in the Mac reports includes multicast/broadcast noise; real host count is lower.
- Some hosts (e.g. `.56`) answer ARP but block ping, so they appear "online but unpingable."
- Scans can't see: sleeping, firewalled, guest-network-isolated, Wi-Fi-client-isolated, or IPv6-only devices.

---

## 8. Open / unresolved items

- Several devices are still **unidentified** (`.45`, `.52`, `.56`, `.107`, `.118`, `.156`, `.228`) — no hostnames resolved.
- Whether the `192.168.20.x` fix has actually been **applied yet** vs. just designed is not confirmed by any scan in this folder (the latest scans still show `.242`/`.0.x`).
- `AUDIOBOOK` (Full_Report.txt) has not been mapped onto either LAN.
