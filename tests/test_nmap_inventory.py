import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools" / "parsers"))

import nmap_inventory as ni

DISCOVERY_XML = """<?xml version="1.0"?>
<nmaprun args="nmap -sn -PR -n 192.168.0.0/24">
  <host><status state="up" reason="arp-response"/>
    <address addr="192.168.0.1" addrtype="ipv4"/>
    <address addr="3C:6A:D2:00:00:01" addrtype="mac" vendor="TP-Link Systems"/></host>
  <host><status state="up" reason="arp-response"/>
    <address addr="192.168.0.20" addrtype="ipv4"/>
    <address addr="6A:00:00:00:00:01" addrtype="mac"/></host>
  <host><status state="down" reason="no-response"/>
    <address addr="192.168.0.99" addrtype="ipv4"/></host>
  <host><status state="up" reason="localhost-response"/>
    <address addr="192.168.0.135" addrtype="ipv4"/></host>
</nmaprun>"""

TCP_XML = """<?xml version="1.0"?>
<nmaprun args="nmap -sS -p- -sV -O 192.168.0.1">
  <host><status state="up" reason="arp-response"/>
    <address addr="192.168.0.1" addrtype="ipv4"/>
    <address addr="3C:6A:D2:00:00:01" addrtype="mac" vendor="TP-Link Systems"/>
    <ports>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
      <port protocol="udp" portid="1900"><state state="open|filtered"/><service name="upnp"/></port>
      <port protocol="udp" portid="53"><state state="open"/><service name="domain"/></port>
    </ports>
    <os>
      <osmatch name="Linux 4.X" accuracy="91"><osclass osfamily="Linux"/></osmatch>
      <osmatch name="Embedded" accuracy="85"><osclass osfamily="embedded"/></osmatch>
    </os>
  </host>
</nmaprun>"""


@pytest.fixture
def xml_files(tmp_path):
    d = tmp_path / "discovery.xml"
    t = tmp_path / "tcp.xml"
    d.write_text(DISCOVERY_XML, encoding="utf-8")
    t.write_text(TCP_XML, encoding="utf-8")
    return [d, t]


@pytest.mark.parametrize(
    "mac,expected",
    [
        ("3C:6A:D2:00:00:01", "3C:6A:D2:XX:XX:XX"),
        ("3c-6a-d2-00-00-01", "3C:6A:D2:XX:XX:XX"),
        ("6A:00:00:00:00:01", "XX:XX:XX:XX:XX:XX (randomized)"),
        ("", ""),
        (None, ""),
    ],
)
def test_mask_mac(mac, expected):
    assert ni.mask_mac(mac) == expected


def test_mask_mac_rejects_garbage():
    with pytest.raises(ValueError):
        ni.mask_mac("not-a-mac")


def test_locally_administered_bit():
    assert ni.is_locally_administered("02:00:00:00:00:00")
    assert not ni.is_locally_administered("00:25:11:00:00:00")


def test_subnet_of():
    assert ni.subnet_of("192.168.0.135") == "192.168.0.0/24"
    assert ni.subnet_of("192.168.20.2") == "192.168.20.0/24"


def test_require_private_blocks_public_addresses():
    ni.require_private("192.168.0.1")
    with pytest.raises(ValueError):
        ni.require_private("93.184.216.34")


def test_parse_merges_discovery_and_service_scans(xml_files):
    assets = ni.parse_files(xml_files)
    assert set(assets) == {"192.168.0.1", "192.168.0.20", "192.168.0.135"}  # down host dropped
    gw = assets["192.168.0.1"]
    assert gw.services == {"443/tcp": "https", "80/tcp": "http", "53/udp": "domain"}
    assert gw.os_family == "Linux" and gw.os_accuracy == 91
    assert gw.methods == {"ARP/ICMP host discovery", "TCP service scan"}


def test_rows_are_sanitized_and_labelled(xml_files):
    labels = {"192.168.0.1": {"id": "ROUTER-A", "role": "Gateway (Domain A)"}}
    rows = ni.build_rows(ni.parse_files(xml_files), labels, "WIN-CLIENT-01")
    by_ip = {r["ip"]: r for r in rows}
    assert [r["ip"] for r in rows] == ["192.168.0.1", "192.168.0.20", "192.168.0.135"]
    assert by_ip["192.168.0.1"]["asset_id"] == "ROUTER-A"
    assert by_ip["192.168.0.1"]["mac_oui"] == "3C:6A:D2:XX:XX:XX"
    assert by_ip["192.168.0.1"]["open_services"] == "80/tcp http, 443/tcp https, 53/udp domain"
    assert by_ip["192.168.0.20"]["asset_id"] == "UNKNOWN-01"
    assert by_ip["192.168.0.20"]["vendor"] == "randomized MAC"
    assert by_ip["192.168.0.135"]["mac_oui"] == "(scanning host)"
    assert all(r["vantage_point"] == "WIN-CLIENT-01" for r in rows)
    flat = repr(rows)
    assert "17:00:01" not in flat and "B0:43" not in flat


def test_cli_writes_csv_and_markdown(xml_files, tmp_path):
    csv_out, md_out = tmp_path / "inv.csv", tmp_path / "inv.md"
    assert ni.main([*map(str, xml_files), "--csv", str(csv_out), "--md", str(md_out)]) == 0
    assert csv_out.read_text(encoding="utf-8").startswith("asset_id,role,ip")
    md = md_out.read_text(encoding="utf-8")
    assert md.splitlines()[0].startswith("| Asset | Role | IP")
    assert "UNKNOWN-01" in md
