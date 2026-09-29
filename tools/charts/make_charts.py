#!/usr/bin/env python3
"""Render the README charts from the sanitized CSVs in 08_Live_Assessment_2026-09-28/data.

Only committed, sanitized data is read, so anyone can regenerate the figures:
    pip install matplotlib
    python tools/charts/make_charts.py
"""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap
from matplotlib.patches import Patch

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "08_Live_Assessment_2026-09-28" / "data"
OUT = ROOT / "08_Live_Assessment_2026-09-28" / "charts"

INK = "#1f2933"
MUTED = "#6b7785"
GRID = "#d9dee3"
BLUE = "#2f6fb0"
GREEN = "#3a8f5c"
GREY = "#c4ccd4"
AMBER = "#d08b1f"

plt.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "font.size": 10,
        "axes.edgecolor": GRID,
        "axes.labelcolor": INK,
        "xtick.color": INK,
        "ytick.color": INK,
        "axes.titleweight": "bold",
        "axes.titlesize": 12,
        "figure.dpi": 150,
    }
)


def read_csv(name: str) -> list[dict[str, str]]:
    with (DATA / name).open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def visibility_matrix() -> None:
    """Vantage point x network segment: what each scanning host could see."""
    rows = read_csv("vantage_matrix.csv")
    cols = [c for c in rows[0] if c != "vantage_point"]
    code = {"yes": 2, "no": 0, "not tested": 1}
    grid = [[code[r[c].strip().lower()] for c in cols] for r in rows]

    fig, ax = plt.subplots(figsize=(8.6, 0.62 * len(rows) + 1.6))
    ax.imshow(grid, cmap=ListedColormap([GREY, "#eef1f4", GREEN]), vmin=0, vmax=2, aspect="auto")
    for i, r in enumerate(rows):
        for j, c in enumerate(cols):
            v = r[c].strip().lower()
            ax.text(
                j,
                i,
                {"yes": "Yes", "no": "No", "not tested": "n/t"}[v],
                ha="center",
                va="center",
                color="white" if v == "yes" else INK,
                fontweight="bold" if v != "not tested" else "normal",
            )
    ax.set_xticks(range(len(cols)), [c.replace("_", " ") for c in cols], rotation=0)
    ax.set_yticks(range(len(rows)), [r["vantage_point"] for r in rows])
    ax.tick_params(length=0)
    ax.set_xticks([x - 0.5 for x in range(1, len(cols))], minor=True)
    ax.set_yticks([y - 0.5 for y in range(1, len(rows))], minor=True)
    ax.grid(which="minor", color="white", linewidth=3)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.xaxis.tick_top()
    ax.set_title("What each vantage point could see", loc="left", pad=34)
    if any(1 in row for row in grid):
        fig.text(0.01, 0.01, "n/t = not tested from that host", color=MUTED, fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT / "vantage_visibility.png", bbox_inches="tight", facecolor="white")
    plt.close(fig)


def packet_mix() -> None:
    """Frame counts for the protocols the analysis relied on (log scale)."""
    wanted = {
        "tcp": "TCP",
        "udp": "UDP",
        "tcp.analysis.retransmission": "TCP retransmissions",
        "ssdp": "SSDP (UPnP)",
        "dns && !mdns": "DNS (unicast)",
        "arp": "ARP",
        "eth.dst==ff:ff:ff:ff:ff:ff": "Ethernet broadcast",
        "tcp.flags.reset==1": "TCP resets",
        "mdns": "mDNS",
        "igmp": "IGMP",
        "nbns": "NBNS",
        "lldp || cdp": "LLDP",
        "dhcp": "DHCP",
        "llmnr": "LLMNR",
        "arp.duplicate-address-detected": "Duplicate-IP alerts",
    }
    counts = {r["Filter"]: int(r["Frames"]) for r in read_csv("packet_filter_counts.csv")}
    items = [(label, counts.get(f, 0)) for f, label in wanted.items() if f in counts]
    items.sort(key=lambda x: x[1])
    labels = [i[0] for i in items]
    values = [max(i[1], 0) for i in items]
    colors = [AMBER if lbl in ("TCP retransmissions", "TCP resets") else BLUE for lbl in labels]

    fig, ax = plt.subplots(figsize=(8.6, 5.2))
    bars = ax.barh(labels, [v if v > 0 else 0.8 for v in values], color=colors, height=0.62)
    ax.set_xscale("log")
    ax.set_xlim(0.7, max(values) * 3)
    for b, v in zip(bars, values, strict=True):
        ax.text(
            b.get_width() * 1.12 if v else 1.0,
            b.get_y() + b.get_height() / 2,
            f"{v:,}",
            va="center",
            color=INK,
        )
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.set_xlabel("Frames in a 300 s passive capture (log scale)")
    ax.set_title("Domain A traffic by protocol, passive baseline", loc="left")
    ax.legend(
        handles=[Patch(color=BLUE, label="protocol volume"), Patch(color=AMBER, label="error indicator")],
        loc="lower right",
        frameon=False,
    )
    fig.tight_layout()
    fig.savefig(OUT / "packet_protocol_mix.png", bbox_inches="tight", facecolor="white")
    plt.close(fig)


def host_timeline() -> None:
    """Domain A hosts seen in July 2026 versus September 2026."""
    rows = read_csv("domain_a_hosts_july_vs_sept.csv")
    rounds = ["july_2026", "sept_2026"]
    fig, ax = plt.subplots(figsize=(8.6, 0.46 * len(rows) + 1.4))
    for i, r in enumerate(rows):
        for j, rd in enumerate(rounds):
            seen = r[rd].strip().lower() == "yes"
            ax.scatter(
                j,
                i,
                s=260,
                marker="o",
                color=GREEN if seen else "white",
                edgecolor=GREEN if seen else GREY,
                linewidth=1.6,
                zorder=3,
            )
        ax.plot([0, 1], [i, i], color=GRID, zorder=1)
    ax.set_yticks(range(len(rows)), [f"{r['ip']}  {r['asset']}" for r in rows])
    ax.set_xticks([0, 1], ["July 2026", "Sept 2026"])
    ax.set_xlim(-0.5, 1.5)
    ax.invert_yaxis()
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
    ax.set_title("Domain A hosts by assessment round", loc="left")
    fig.text(0.01, 0.01, "Filled = present in that round's discovery", color=MUTED, fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT / "domain_a_host_timeline.png", bbox_inches="tight", facecolor="white")
    plt.close(fig)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    visibility_matrix()
    packet_mix()
    host_timeline()
    for p in sorted(OUT.glob("*.png")):
        print("wrote", p.relative_to(ROOT))


if __name__ == "__main__":
    main()
