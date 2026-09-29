<#
.SYNOPSIS
    Summarize a local packet capture into publishable, metadata-only evidence.

.DESCRIPTION
    Runs tshark display filters against a .pcap/.pcapng and reports protocol
    counts, ARP IP-to-MAC bindings (the key test for duplicate gateways),
    DNS resolver usage, broadcast/multicast talkers and TCP retransmission
    concentration. No payloads are exported. MACs are reduced to their OUI and
    public IPs are never written.

    The capture itself stays local; only the summary is meant to be committed.

.EXAMPLE
    .\Invoke-PacketSummary.ps1 -CaptureFile ..\..\artifacts\private\baseline.pcapng -OutputDirectory ..\..\artifacts\public
#>
[CmdletBinding()]
param(
    [string]$CaptureFile,
    [string]$OutputDirectory = (Join-Path (Get-Location) 'artifacts\public'),
    [string]$TsharkPath = 'C:\Program Files\Wireshark\tshark.exe',
    [string]$LocalPrefix = '192.168.'
)

Set-StrictMode -Version 2.0

# Filters and what each one answers. Order is the order of the report.
$script:Filters = [ordered]@{
    'arp'                                          = 'ARP frames (all)'
    'arp.opcode==1'                                = 'ARP requests'
    'arp.opcode==2'                                = 'ARP replies'
    'arp.src.proto_ipv4==0.0.0.0'                  = 'ARP probes (RFC 5227 address conflict detection)'
    'arp.isgratuitous==1'                          = 'Gratuitous ARP'
    'arp.duplicate-address-detected'               = 'Wireshark duplicate-address alerts'
    'dhcp'                                         = 'DHCP'
    'dns && !mdns'                                 = 'Unicast DNS'
    'mdns'                                         = 'mDNS'
    'llmnr'                                        = 'LLMNR'
    'nbns'                                         = 'NetBIOS name service'
    'ssdp'                                         = 'SSDP (UPnP discovery)'
    'igmp'                                         = 'IGMP'
    'lldp || cdp'                                  = 'LLDP/CDP'
    'icmp'                                         = 'ICMPv4'
    'icmpv6'                                       = 'ICMPv6 (incl. neighbor discovery)'
    'tcp'                                          = 'TCP'
    'udp'                                          = 'UDP'
    'tcp.analysis.retransmission'                  = 'TCP retransmissions'
    'tcp.analysis.duplicate_ack'                   = 'TCP duplicate ACKs'
    'tcp.flags.reset==1'                           = 'TCP resets'
    'tcp.analysis.zero_window'                     = 'TCP zero window'
    'eth.dst==ff:ff:ff:ff:ff:ff'                   = 'Ethernet broadcast frames'
    'eth.dst[0]&1 && !(eth.dst==ff:ff:ff:ff:ff:ff)' = 'Ethernet multicast frames'
}

function ConvertTo-OuiMac {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Mac)
    $hex = ($Mac -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($hex.Length -ne 12) { return $Mac }
    if (([Convert]::ToInt32($hex.Substring(0, 2), 16) -band 0x02) -ne 0) { return 'randomized' }
    return '{0}:{1}:{2}:XX:XX:XX' -f $hex.Substring(0, 2), $hex.Substring(2, 2), $hex.Substring(4, 2)
}

function Get-ArpBindingReport {
    <#
        Input: lines of "sender-ip<TAB>sender-mac" from ARP frames.
        Output: one row per IP with the number of distinct MACs that claimed it.
        More than one MAC for the same IP inside one broadcast domain is the
        signature of a duplicate address (or, in this project, a second gateway).
    #>
    param([string[]]$Lines = @())
    $pairs = foreach ($l in $Lines) {
        $f = $l -split "`t"
        if ($f.Count -ge 2 -and $f[0] -and $f[1] -and $f[0] -ne '0.0.0.0') {
            [pscustomobject]@{ IP = $f[0].Trim(); Mac = $f[1].Trim().ToLowerInvariant() }
        }
    }
    $pairs | Group-Object IP | ForEach-Object {
        $macs = @($_.Group.Mac | Select-Object -Unique)
        [pscustomobject]@{
            IP           = $_.Name
            Frames       = $_.Count
            DistinctMacs = $macs.Count
            MacOui       = ($macs | ForEach-Object { ConvertTo-OuiMac $_ }) -join ', '
            Conflict     = $macs.Count -gt 1
        }
    } | Sort-Object { [version]($_.IP) }
}

function Get-StreamConcentration {
    <# Share of retransmissions that fall in the single worst TCP stream. #>
    param([string[]]$StreamIds = @())
    $ids = @($StreamIds | Where-Object { $_ -ne '' })
    if ($ids.Count -eq 0) { return [pscustomobject]@{ Total = 0; Streams = 0; TopStreamShare = 0.0 } }
    $groups = @($ids | Group-Object | Sort-Object Count -Descending)
    [pscustomobject]@{
        Total          = $ids.Count
        Streams        = $groups.Count
        TopStreamShare = [math]::Round($groups[0].Count / $ids.Count, 3)
    }
}

function Invoke-Tshark {
    param([string[]]$Arguments)
    $out = & $script:Tshark @Arguments 2>$null
    return @($out)
}

if ($MyInvocation.InvocationName -ne '.') {
    if (-not $CaptureFile -or -not (Test-Path $CaptureFile)) { throw "Capture file not found: $CaptureFile" }
    if (-not (Test-Path $TsharkPath)) { throw "tshark not found at $TsharkPath. Install Wireshark or pass -TsharkPath." }
    $script:Tshark = $TsharkPath
    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

    $meta = Invoke-Tshark @('-r', $CaptureFile, '-q', '-z', 'io,stat,0')
    $frames = ($meta | Select-String '\|\s*[\d.]+\s*<>\s*[\d.]+\s*\|\s*(\d+)\s*\|' | Select-Object -First 1).Matches.Groups[1].Value
    $duration = ($meta | Select-String 'Duration:\s*([\d.]+)' | Select-Object -First 1).Matches.Groups[1].Value

    $counts = foreach ($f in $script:Filters.Keys) {
        [pscustomobject]@{ Filter = $f; Meaning = $script:Filters[$f]; Frames = @(Invoke-Tshark @('-r', $CaptureFile, '-Y', $f, '-T', 'fields', '-e', 'frame.number')).Count }
    }
    $counts | Export-Csv (Join-Path $OutputDirectory 'packet_filter_counts.csv') -NoTypeInformation -Encoding UTF8

    $arp = Get-ArpBindingReport -Lines (Invoke-Tshark @('-r', $CaptureFile, '-Y', 'arp', '-T', 'fields', '-e', 'arp.src.proto_ipv4', '-e', 'arp.src.hw_mac'))
    $resolvers = Invoke-Tshark @('-r', $CaptureFile, '-Y', 'dns.flags.response==0 && !mdns', '-T', 'fields', '-e', 'ip.dst') |
        Group-Object | ForEach-Object {
            $name = if ($_.Name.StartsWith($LocalPrefix)) { $_.Name } else { 'external resolver (address withheld)' }
            [pscustomobject]@{ Resolver = $name; Queries = $_.Count } }
    $rcodes = Invoke-Tshark @('-r', $CaptureFile, '-Y', 'dns.flags.response==1 && !mdns', '-T', 'fields', '-e', 'dns.flags.rcode') | Group-Object
    $latency = @(Invoke-Tshark @('-r', $CaptureFile, '-Y', 'dns.time', '-T', 'fields', '-e', 'dns.time') | ForEach-Object { [double]$_ })
    $retrans = Get-StreamConcentration -StreamIds (Invoke-Tshark @('-r', $CaptureFile, '-Y', 'tcp.analysis.retransmission', '-T', 'fields', '-e', 'tcp.stream'))
    $talkers = Invoke-Tshark @('-r', $CaptureFile, '-Y', 'eth.dst[0]&1', '-T', 'fields', '-e', 'ip.src') |
        Where-Object { $_ -and $_.StartsWith($LocalPrefix) } | Group-Object | Sort-Object Count -Descending

    $md = [System.Text.StringBuilder]::new()
    [void]$md.AppendLine('# Packet capture summary (metadata only)')
    [void]$md.AppendLine('')
    [void]$md.AppendLine("Frames: $frames, duration: $duration s. Payloads were not exported.")
    [void]$md.AppendLine('')
    [void]$md.AppendLine('## Protocol and anomaly counts')
    [void]$md.AppendLine('')
    [void]$md.AppendLine('| Display filter | Meaning | Frames |')
    [void]$md.AppendLine('|---|---|---|')
    foreach ($c in $counts) { [void]$md.AppendLine(('| `{0}` | {1} | {2} |' -f $c.Filter.Replace('|', '\|'), $c.Meaning, $c.Frames)) }
    [void]$md.AppendLine('')
    [void]$md.AppendLine('## ARP bindings (sender IP to MAC)')
    [void]$md.AppendLine('')
    [void]$md.AppendLine('| IP | ARP frames | Distinct MACs | MAC (OUI) | Conflict |')
    [void]$md.AppendLine('|---|---|---|---|---|')
    foreach ($a in $arp) { [void]$md.AppendLine(('| {0} | {1} | {2} | {3} | {4} |' -f $a.IP, $a.Frames, $a.DistinctMacs, $a.MacOui, $(if ($a.Conflict) { 'YES' } else { 'no' }))) }
    [void]$md.AppendLine('')
    [void]$md.AppendLine('## DNS')
    [void]$md.AppendLine('')
    foreach ($r in $resolvers) { [void]$md.AppendLine("- Resolver $($r.Resolver): $($r.Queries) queries") }
    foreach ($r in $rcodes) { [void]$md.AppendLine("- Response code $($r.Name): $($r.Count)") }
    if ($latency.Count) {
        [void]$md.AppendLine(('- Response time: mean {0:N1} ms, max {1:N1} ms over {2} answered queries' -f (($latency | Measure-Object -Average).Average * 1000), (($latency | Measure-Object -Maximum).Maximum * 1000), $latency.Count))
    }
    [void]$md.AppendLine('')
    [void]$md.AppendLine('## TCP retransmissions')
    [void]$md.AppendLine('')
    [void]$md.AppendLine(('{0} retransmissions across {1} streams; the worst single stream accounts for {2:P0}.' -f $retrans.Total, $retrans.Streams, $retrans.TopStreamShare))
    [void]$md.AppendLine('')
    [void]$md.AppendLine('## Local broadcast/multicast talkers')
    [void]$md.AppendLine('')
    foreach ($t in $talkers) { [void]$md.AppendLine("- $($t.Name): $($t.Count) frames") }
    $md.ToString() | Set-Content -Path (Join-Path $OutputDirectory 'packet_summary.md') -Encoding UTF8
    $arp | Export-Csv (Join-Path $OutputDirectory 'arp_bindings.csv') -NoTypeInformation -Encoding UTF8
    Write-Output "Summary written to $OutputDirectory"
}
