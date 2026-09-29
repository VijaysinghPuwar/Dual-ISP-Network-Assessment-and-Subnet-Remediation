#!/usr/bin/env python3
"""Turn Nmap XML output into a sanitized asset inventory (CSV + Markdown).

Only the standard library is used. Input XML stays local; the output is meant
to be committed, so MAC addresses are reduced to their vendor OUI, hostnames
are dropped, and every host is given a neutral asset ID.

Usage:
    python nmap_inventory.py --vantage WIN-CLIENT-01 --assets assets.json \
        --csv inventory.csv --md inventory.md scan1.xml [scan2.xml ...]

assets.json (optional, kept private) maps IPs to public labels:
    {"192.168.0.1": {"id": "ROUTER-A", "role": "Gateway (Domain A)"}}
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


def is_locally_administered(mac: str) -> bool:
    """True when the U/L bit is set, i.e. a randomized/private MAC."""
    first = int(re.sub(r"[^0-9A-Fa-f]", "", mac)[:2], 16)
    return bool(first & 0x02)


def mask_mac(mac: str | None) -> str:
    """Keep the OUI, hide the device half. Randomized MACs are fully hidden."""
    if not mac:
        return ""
    if not MAC_RE.match(mac):
        raise ValueError(f"not a MAC address: {mac!r}")
    if is_locally_administered(mac):
        return "XX:XX:XX:XX:XX:XX (randomized)"
    octets = re.split(r"[:-]", mac.upper())
    return ":".join([*octets[:3], "XX", "XX", "XX"])


def subnet_of(ip: str, prefix: int = 24) -> str:
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def require_private(ip: str) -> None:
    """Refuse to publish anything about a non-private address."""
    if not ipaddress.ip_address(ip).is_private:
        raise ValueError(f"refusing to publish non-private address {ip}")


@dataclass
class Asset:
    ip: str
    mac: str = ""
    vendor: str = ""
    reason: str = ""
    os_family: str = ""
    os_accuracy: int = 0
    services: dict[str, str] = field(default_factory=dict)
    methods: set[str] = field(default_factory=set)


def _method_for(scan_args: str) -> str:
    if "-sn" in scan_args:
        return "ARP/ICMP host discovery"
    if "-sU" in scan_args:
        return "UDP service scan"
    return "TCP service scan"


def parse_files(paths: list[Path]) -> dict[str, Asset]:
    assets: dict[str, Asset] = {}
    for path in paths:
        root = ET.parse(path).getroot()
        method = _method_for(root.get("args", ""))
        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue
            ip = mac = vendor = ""
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr", "")
                elif addr.get("addrtype") == "mac":
                    mac = addr.get("addr", "")
                    vendor = addr.get("vendor", "")
            if not ip:
                continue
            a = assets.setdefault(ip, Asset(ip=ip))
            a.mac = a.mac or mac
            a.vendor = a.vendor or vendor
            a.reason = a.reason or status.get("reason", "")
            a.methods.add(method)
            for match in host.findall("os/osmatch"):
                acc = int(match.get("accuracy", "0"))
                cls = match.find("osclass")
                family = cls.get("osfamily", "") if cls is not None else ""
                if acc > a.os_accuracy and family:
                    a.os_family, a.os_accuracy = family, acc
            for port in host.findall("ports/port"):
                state = port.find("state")
                if state is None or state.get("state") not in ("open", "open|filtered"):
                    continue
                if state.get("state") == "open|filtered":
                    continue  # ambiguous UDP result, not evidence of a service
                svc = port.find("service")
                name = svc.get("name", "unknown") if svc is not None else "unknown"
                a.services[f"{port.get('portid')}/{port.get('protocol')}"] = name
    return assets


def _port_key(item: tuple[str, str]) -> tuple[str, int]:
    num, proto = item[0].split("/")
    return proto, int(num)


def build_rows(assets: dict[str, Asset], labels: dict, vantage: str) -> list[dict[str, str]]:
    rows = []
    unknown = 0
    for ip in sorted(assets, key=lambda x: ipaddress.ip_address(x)):
        require_private(ip)
        a = assets[ip]
        label = labels.get(ip)
        if label:
            asset_id, role = label.get("id", ""), label.get("role", "")
        else:
            unknown += 1
            asset_id, role = f"UNKNOWN-{unknown:02d}", "Unidentified"
        services = ", ".join(f"{p} {n}" for p, n in sorted(a.services.items(), key=_port_key))
        rows.append(
            {
                "asset_id": asset_id,
                "role": role,
                "ip": ip,
                "subnet": subnet_of(ip),
                "mac_oui": mask_mac(a.mac) if a.mac else "(scanning host)",
                "vendor": a.vendor or ("randomized MAC" if a.mac and is_locally_administered(a.mac) else ""),
                "os_family": f"{a.os_family} ({a.os_accuracy}%)" if a.os_family else "",
                "reachability": a.reason,
                "open_services": services,
                "discovery": "; ".join(sorted(a.methods)),
                "vantage_point": vantage,
            }
        )
    return rows


def write_csv(rows: list[dict[str, str]], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["asset_id"])
        writer.writeheader()
        writer.writerows(rows)


def to_markdown(rows: list[dict[str, str]]) -> str:
    cols = ["asset_id", "role", "ip", "mac_oui", "vendor", "os_family", "reachability", "open_services"]
    head = ["Asset", "Role", "IP", "MAC (OUI only)", "Vendor", "OS guess", "Seen via", "Open services"]
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for r in rows:
        lines.append("| " + " | ".join(r[c].replace("|", "/") or "-" for c in cols) + " |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("xml", nargs="+", type=Path)
    ap.add_argument("--assets", type=Path, help="private JSON mapping IP -> {id, role}")
    ap.add_argument("--vantage", default="VANTAGE-01")
    ap.add_argument("--csv", type=Path)
    ap.add_argument("--md", type=Path)
    args = ap.parse_args(argv)

    labels = json.loads(args.assets.read_text(encoding="utf-8")) if args.assets else {}
    rows = build_rows(parse_files(args.xml), labels, args.vantage)
    if args.csv:
        write_csv(rows, args.csv)
    md = to_markdown(rows)
    if args.md:
        args.md.write_text(md, encoding="utf-8")
    else:
        sys.stdout.write(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
