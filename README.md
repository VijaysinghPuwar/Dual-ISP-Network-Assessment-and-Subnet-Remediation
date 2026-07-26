# Dual-ISP Network Assessment and Subnet Remediation

Assessment of a home network running **two independent routers on two separate internet plans**, with a **Synology NAS bridging both**. The project documents a misconfiguration — both routers using the *same* LAN subnet (`192.168.0.0/24`) and *same* gateway IP (`192.168.0.1`) — and the remediation that moves Router B onto its own subnet (`192.168.20.0/24`).

**Assessment date:** 2026-07-26 · **Scope:** authorized private network only (inventory/connectivity; no exploits or config changes by the tooling).

---

## Start here

Read **[`00_START_HERE/Context_Brief.md`](00_START_HERE/Context_Brief.md)** — it explains the entire setup, the problem, and the fix on one page. (Paste that file into a new assistant session for instant full context.)

## Folder map

| Folder | Contents |
|---|---|
| `00_START_HERE/` | One-page context brief |
| `01_Scanner_Scripts/` | The Windows (`.ps1`) and macOS (`.sh`) inventory scanners |
| `02_Scan_Results/` | Scan output, **one subfolder per computer** that ran a scan |
| `03_System_Diagnostics/` | Full single-PC Windows diagnostic (`AUDIOBOOK`) |
| `04_Topology_Diagrams/` | Five diagrams: the four evolution stages plus a summary infographic |
| `05_Report/` | The technical write-up — IEEE-style **PDF** and its slide-form `.pptx` twin |
| `06_Presentation/` | Visual infographic slide deck (`.pptx`) |
| `07_Media/` | Audio explainer (`.m4a`) |

## The scanners (`01_Scanner_Scripts/`)

Two custom, cross-platform inventory scripts were written for this assessment — one for Windows, one for macOS — so the same network could be mapped from every machine on it. Both are **read-only**: they inventory and test reachability only, and do **not** attempt passwords, exploit vulnerabilities, bypass firewalls, or change any configuration. Each auto-detects the local private (RFC 1918) subnet, runs an ICMP/ARP host-discovery sweep, resolves names where possible, checks a small set of common TCP service ports (e.g. SSH, SMB, HTTP/S, Synology DSM), and collects the host's own adapters, routes, gateway, and neighbor cache.

| Script | Platform | Description |
|---|---|---|
| **`Home_Network_Inventory_v1.5.ps1`** | Windows (PowerShell 5.1+ / PowerShell 7) | Discovers active private subnets on the PC, scans them, resolves DNS/NetBIOS names, tests common TCP ports, and exports a full report set — **HTML, PDF** (rendered via Edge/Chrome, with Word as fallback), **CSV, JSON**, and a run **log**. Options: `-Subnets`, `-SkipPortScan`, `-OpenReport`. *v1.5 also lists devices that have no open TCP ports.* |
| **`Mac_Network_Inventory_v1.1.sh`** | macOS (Bash 3.2, the version shipped with macOS) | The macOS port of the same tool. Scans RFC 1918 IPv4 only and produces the matching outputs — **PDF, HTML, CSV, JSON, TXT**, and a **log**. Options: `--subnet`, `--open-report`. *v1.1 adds parallel discovery, correct CIDR filtering, MAC collection, multicast exclusion, and filtered ARP output.* |

Running both across the different computers is what produced the three vantage points below — and revealed that each machine could only see its own router's LAN.

## The three scan vantage points

| Folder | Computer | Its IP | Sees |
|---|---|---|---|
| `02_Scan_Results/01_…_192.168.0.135` | Windows PC (DESKTOP-282LTKE) | `.135` | **Router A** LAN |
| `02_Scan_Results/02_…_192.168.0.201` | Mac mini M4 Pro | `.201` | **Router A** LAN |
| `02_Scan_Results/03_…_192.168.0.8`   | Mac mini M2 Pro | `.8`   | **Router B** LAN |

Each computer sees only its own router's LAN — that split is itself the evidence of the two-LAN problem.

## Diagram sequence (`04_Topology_Diagrams/`)

1. **Windows-scan, 5 devices** — earliest view, one router assumed.
2. **Windows + Mac combined** — two Router-A scans merged.
3. **Discovered dual-LAN subnet conflict** — the diagnosis.
4. **Target-state subnet remediation** — the fix (Router B → `192.168.20.x`, Synology LAN2 → `192.168.20.2`).
5. **Summary infographic** — one-page conflict-and-remediation overview.

---

## Privacy / redaction status

This repository has been redacted for public sharing. **All hardware MAC addresses are removed** (blacked out in images/PDFs, replaced with `██` in text) because router/AP MACs can be looked up in public Wi-Fi-geolocation databases to approximate a physical location. Internal IPs and device/computer names are retained intentionally — they do not reveal location. The technical report masks MACs to the vendor prefix (OUI) only.
