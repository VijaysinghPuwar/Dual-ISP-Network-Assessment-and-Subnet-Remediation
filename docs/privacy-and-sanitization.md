# Privacy and sanitization

Everything collected from the live network is treated as private until it has been deliberately reduced to something safe to publish.

## What stays local (never committed)

| Artifact | Why |
|---|---|
| `.pcap` / `.pcapng` captures | Contain full MACs, public peer addresses, DNS names looked up, and potentially payload |
| Raw Nmap `.xml` / `.nmap` / `.gnmap` | Full MACs, hostnames, exact service banners |
| Raw `ipconfig /all`, `netstat -ano`, `arp -a` | Hostname, full MACs, DHCPv6 DUID, remote public addresses |
| `artifacts/private/` | Raw output of the tools in this repo |
| `.privacy-denylist.txt` | The list of real hostnames/usernames the privacy check looks for |

All of these are covered by [`.gitignore`](../.gitignore).

## Transformation rules

| Data | Published as | Reason |
|---|---|---|
| Hostname (for example a Windows default `DESKTOP-XXXXXXX`) | `WIN-CLIENT-01`, `MAC-CLIENT-02`, `NAS-01`, `ROUTER-A` | Hostnames often contain a person's name |
| Usernames, home paths | `<user>`, `<HOME>` | Personal data |
| MAC address | OUI only, `3C:6A:D2:XX:XX:XX` | The OUI is needed to show "same IP, different vendor". The device half is unique to the hardware, and router MACs (BSSIDs) can be geolocated through public Wi-Fi databases |
| Randomized (locally administered) MAC | `XX:XX:XX:XX:XX:XX (randomized)` | No vendor meaning, only a tracking value |
| Public / WAN IP | Removed entirely | Reveals ISP and approximate location |
| Private IP (`192.168.x.x`) | Kept | These are vendor-default ranges shared by millions of networks. The whole finding depends on showing them |
| Listening ports on endpoints | Count only, unless the port is part of a finding | Unnecessary attack-surface detail |
| Windows SID, DHCPv6 DUID, serial numbers | Removed | Unique hardware or account identifiers |
| Wi-Fi SSID / BSSID | Never collected into public files | Location and identity |

## Tooling

- [`tools/windows/Get-NetworkBaseline.ps1`](../tools/windows/Get-NetworkBaseline.ps1) writes `private/` and `public/` copies. The public copy passes through `Protect-Text` and `ConvertTo-PublicBaseline`.
- [`tools/parsers/nmap_inventory.py`](../tools/parsers/nmap_inventory.py) refuses to publish any non-private address, reduces MACs to the OUI, and replaces hostnames with asset IDs.
- [`tools/privacy/Test-PublicArtifacts.ps1`](../tools/privacy/Test-PublicArtifacts.ps1) is the pre-publication gate. It looks for full MACs, public IPv4 addresses, email addresses, Windows SIDs, home paths, credential patterns, packet captures and local denylist terms, including text inside `.pptx`/`.docx`. It only reads files and never sends anything anywhere. CI runs it on every push.

```powershell
# before every commit
./tools/privacy/Test-PublicArtifacts.ps1 -TrackedOnly
```

## Known limits

- The scanner cannot read text inside images, PDFs or audio. The PDFs were checked separately with a text extractor, and the diagrams and slides were reviewed by eye. The audio explainer has not been transcribed.
