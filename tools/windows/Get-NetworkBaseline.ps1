<#
.SYNOPSIS
    Read-only Windows network baseline with a sanitized public copy.

.DESCRIPTION
    Collects interface, IPv4, gateway, DNS, route, neighbor, TCP state and
    adapter-counter data using built-in NetTCPIP/NetAdapter cmdlets. Nothing on
    the host or the network is changed.

    Two outputs are written:
      <OutputDirectory>\private\baseline.json   raw values, never commit
      <OutputDirectory>\public\baseline.json    sanitized (MAC suffixes masked,
      <OutputDirectory>\public\baseline.md      public IPs, host and user names removed)

.PARAMETER OutputDirectory
    Root folder for the private/ and public/ subfolders. Defaults to .\artifacts

.PARAMETER SkipConnectivity
    Skip the gateway ping, DNS lookup and internet reachability checks.

.EXAMPLE
    .\Get-NetworkBaseline.ps1 -OutputDirectory ..\..\artifacts
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path (Get-Location) 'artifacts'),
    [switch]$SkipConnectivity
)

Set-StrictMode -Version 2.0

# ---------------------------------------------------------------- helpers --

function Test-IsPrivateIPv4 {
    <# True for RFC 1918, loopback, link-local and CGNAT (RFC 6598) IPv4. #>
    param([Parameter(Mandatory)][string]$Address)
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$ip)) { return $false }
    if ($ip.AddressFamily -ne 'InterNetwork') { return $false }
    $b = $ip.GetAddressBytes()
    return ($b[0] -eq 10) -or
           ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
           ($b[0] -eq 192 -and $b[1] -eq 168) -or
           ($b[0] -eq 127) -or
           ($b[0] -eq 169 -and $b[1] -eq 254) -or
           ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127)
}

function Test-IsSpecialIPv4 {
    <# Multicast, broadcast and the unspecified address: safe to publish. #>
    param([Parameter(Mandatory)][string]$Address)
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$ip)) { return $false }
    if ($ip.AddressFamily -ne 'InterNetwork') { return $false }
    $b = $ip.GetAddressBytes()
    return ($b[0] -ge 224) -or ($Address -eq '0.0.0.0')
}

function Get-IPv4NetworkAddress {
    <# Returns the network address in CIDR form, e.g. 192.168.0.135/24 -> 192.168.0.0/24 #>
    param(
        [Parameter(Mandatory)][string]$Address,
        [Parameter(Mandatory)][ValidateRange(0, 32)][int]$PrefixLength
    )
    $ip = [System.Net.IPAddress]::Parse($Address)
    if ($ip.AddressFamily -ne 'InterNetwork') { throw "Not an IPv4 address: $Address" }
    $bytes = $ip.GetAddressBytes()
    [Array]::Reverse($bytes)
    $value = [BitConverter]::ToUInt32($bytes, 0)
    $mask = if ($PrefixLength -eq 0) { [uint32]0 } else { [uint32](([uint64]4294967295 -shl (32 - $PrefixLength)) -band [uint64]4294967295) }
    $net = [BitConverter]::GetBytes([uint32]($value -band $mask))
    [Array]::Reverse($net)
    return ('{0}/{1}' -f ([System.Net.IPAddress]::new($net)).ToString(), $PrefixLength)
}

function Test-IsLocallyAdministeredMac {
    <# The U/L bit (0x02 of the first octet) marks randomized/private MACs. #>
    param([Parameter(Mandatory)][string]$Mac)
    $first = ($Mac -replace '[^0-9A-Fa-f]', '').Substring(0, 2)
    return ([Convert]::ToInt32($first, 16) -band 0x02) -ne 0
}

function ConvertTo-MaskedMac {
    <#
        Keeps the vendor OUI (first three octets) and masks the device-specific
        half. Locally administered MACs carry no vendor meaning, so they are
        masked completely.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Mac)
    $hex = ($Mac -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($hex.Length -ne 12) { return $Mac }
    if ($hex -eq 'FFFFFFFFFFFF' -or $hex -eq '000000000000') {
        return (($hex -split '(..)' | Where-Object { $_ }) -join ':')
    }
    if (Test-IsLocallyAdministeredMac -Mac $hex) { return 'XX:XX:XX:XX:XX:XX (randomized)' }
    return ('{0}:{1}:{2}:XX:XX:XX' -f $hex.Substring(0, 2), $hex.Substring(2, 2), $hex.Substring(4, 2))
}

function Protect-Text {
    <#
        Scrubs free text before it is published: full MACs, public IPv4
        addresses, Windows/macOS home paths, the local user and computer name.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [string[]]$SensitiveNames = @()
    )
    $out = [regex]::Replace($Text, '\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b', {
            param($m) ConvertTo-MaskedMac -Mac $m.Value })
    $out = [regex]::Replace($out, '\b(?:\d{1,3}\.){3}\d{1,3}\b', {
            param($m)
            $ip = $null
            if (-not [System.Net.IPAddress]::TryParse($m.Value, [ref]$ip)) { return $m.Value }
            if ((Test-IsPrivateIPv4 $m.Value) -or (Test-IsSpecialIPv4 $m.Value)) { return $m.Value }
            return '<public-ip>'
        })
    $out = $out -replace '(?i)[A-Z]:\\Users\\[^\\\s"'']+', '<HOME>'
    $out = $out -replace '/Users/[^/\s"'']+', '<HOME>'
    foreach ($name in $SensitiveNames | Where-Object { $_ }) {
        $out = $out -replace [regex]::Escape($name), '<redacted>'
    }
    return $out
}

# -------------------------------------------------------------- collection --

function Get-NetworkBaseline {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingComputerNameHardcoded', '',
        Justification = 'Fixed Microsoft NCSI endpoint used only as an internet reachability probe.')]
    [CmdletBinding()]
    param([switch]$SkipConnectivity)

    $interfaces = @(Get-NetIPConfiguration -ErrorAction SilentlyContinue |
        Where-Object { $_.IPv4Address -and $_.NetAdapter.Status -eq 'Up' })

    $ifaceData = foreach ($cfg in $interfaces) {
        $addr = @($cfg.IPv4Address)[0]
        $gw = if ($cfg.IPv4DefaultGateway) { @($cfg.IPv4DefaultGateway)[0].NextHop } else { $null }
        $gwMac = $null
        if ($gw) {
            $n = Get-NetNeighbor -IPAddress $gw -InterfaceIndex $cfg.InterfaceIndex -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if ($n) { $gwMac = $n.LinkLayerAddress }
        }
        $stats = Get-NetAdapterStatistics -Name $cfg.InterfaceAlias -ErrorAction SilentlyContinue
        $ipif = Get-NetIPInterface -InterfaceIndex $cfg.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        [pscustomobject]@{
            Interface         = $cfg.InterfaceAlias
            Description       = $cfg.InterfaceDescription
            LinkSpeed         = $cfg.NetAdapter.LinkSpeed
            MacAddress        = $cfg.NetAdapter.MacAddress
            IPv4Address       = $addr.IPAddress
            PrefixLength      = [int]$addr.PrefixLength
            Network           = Get-IPv4NetworkAddress -Address $addr.IPAddress -PrefixLength $addr.PrefixLength
            AddressIsPrivate  = Test-IsPrivateIPv4 $addr.IPAddress
            Dhcp              = if ($ipif) { [string]$ipif.Dhcp } else { $null }
            Mtu               = if ($ipif) { $ipif.NlMtu } else { $null }
            InterfaceMetric   = if ($ipif) { $ipif.InterfaceMetric } else { $null }
            DefaultGateway    = $gw
            GatewayMac        = $gwMac
            DnsServers        = @($cfg.DNSServer | Where-Object { $_.AddressFamily -eq 2 } |
                    ForEach-Object { $_.ServerAddresses }) | Select-Object -Unique
            NetworkCategory   = if ($cfg.NetProfile) { [string]$cfg.NetProfile.NetworkCategory } else { $null }
            RxErrors          = if ($stats) { $stats.ReceivedPacketErrors } else { $null }
            RxDiscards        = if ($stats) { $stats.ReceivedDiscardedPackets } else { $null }
            TxErrors          = if ($stats) { $stats.OutboundPacketErrors } else { $null }
            TxDiscards        = if ($stats) { $stats.OutboundDiscardedPackets } else { $null }
        }
    }

    $routes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.DestinationPrefix -notmatch '/32$' -and $_.DestinationPrefix -notlike '224.*' -and
                       $_.DestinationPrefix -notlike '127.*' -and $_.DestinationPrefix -ne '255.255.255.255/32' } |
        Sort-Object DestinationPrefix |
        Select-Object @{n = 'Destination'; e = { $_.DestinationPrefix } }, NextHop,
            @{n = 'Interface'; e = { $_.InterfaceAlias } }, RouteMetric, InterfaceMetric)

    $defaultRoutes = @($routes | Where-Object { $_.Destination -eq '0.0.0.0/0' })

    $neighbors = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.State -notin 'Unreachable', 'Permanent' -and $_.LinkLayerAddress -and
                       $_.LinkLayerAddress -ne '00-00-00-00-00-00' })
    $neighborSummary = $neighbors | Group-Object InterfaceAlias | ForEach-Object {
        [pscustomobject]@{
            Interface  = $_.Name
            Count      = $_.Count
            Randomized = @($_.Group | Where-Object { Test-IsLocallyAdministeredMac $_.LinkLayerAddress }).Count
            States     = ($_.Group | Group-Object State | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }) -join ', '
        }
    }

    # Duplicate-IP check inside the neighbor cache: one IP, more than one MAC.
    $duplicateIps = @($neighbors | Group-Object IPAddress |
        Where-Object { @($_.Group.LinkLayerAddress | Select-Object -Unique).Count -gt 1 } |
        ForEach-Object { $_.Name })

    $tcpStates = Get-NetTCPConnection -ErrorAction SilentlyContinue | Group-Object State |
        Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ State = $_.Name; Count = $_.Count } }
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty LocalPort -Unique | Sort-Object)

    $connectivity = @()
    if (-not $SkipConnectivity) {
        foreach ($i in $ifaceData | Where-Object DefaultGateway) {
            $ok = Test-Connection -ComputerName $i.DefaultGateway -Count 2 -Quiet -ErrorAction SilentlyContinue
            $connectivity += [pscustomobject]@{ Check = "Gateway echo via $($i.Interface)"; Target = $i.DefaultGateway; Result = [bool]$ok }
        }
        $dns = $null
        try { $dns = Resolve-DnsName -Name 'www.msftconnecttest.com' -Type A -ErrorAction Stop | Select-Object -First 1 }
        catch { Write-Verbose "DNS check failed: $($_.Exception.Message)" }
        $connectivity += [pscustomobject]@{ Check = 'DNS resolution (A record)'; Target = 'www.msftconnecttest.com'; Result = [bool]$dns }
        $web = $false
        try {
            $web = (Test-NetConnection -ComputerName 'www.msftconnecttest.com' -Port 80 -WarningAction SilentlyContinue).TcpTestSucceeded
        } catch { Write-Verbose "TCP/80 check failed: $($_.Exception.Message)" }
        $connectivity += [pscustomobject]@{ Check = 'Internet TCP/80 (Windows NCSI endpoint)'; Target = 'www.msftconnecttest.com'; Result = [bool]$web }
    }

    [pscustomobject]@{
        CollectedAt        = (Get-Date).ToString('o')
        ComputerName       = $env:COMPUTERNAME
        UserName           = $env:USERNAME
        OS                 = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
        Interfaces         = @($ifaceData)
        DefaultRouteCount  = $defaultRoutes.Count
        Routes             = $routes
        NeighborSummary    = @($neighborSummary)
        DuplicateNeighborIPs = $duplicateIps
        TcpStates          = @($tcpStates)
        ListeningTcpPorts  = $listeners
        Connectivity       = $connectivity
    }
}

function ConvertTo-PublicBaseline {
    <# Produces the sanitized copy that is safe to commit. #>
    param([Parameter(Mandatory)]$Baseline, [string]$AssetName = 'WIN-CLIENT-01')
    $names = @($Baseline.ComputerName, $Baseline.UserName)
    $json = $Baseline | ConvertTo-Json -Depth 6
    $json = Protect-Text -Text $json -SensitiveNames $names
    $public = $json | ConvertFrom-Json
    $public.ComputerName = $AssetName
    $public.UserName = '<redacted>'
    foreach ($i in $public.Interfaces) { $i.MacAddress = ConvertTo-MaskedMac -Mac ([string]$i.MacAddress) }
    # The exact listener list is host attack surface; publish only the count.
    $public.ListeningTcpPorts = @("$(@($Baseline.ListeningTcpPorts).Count) listening ports (list kept private)")
    return $public
}

function ConvertTo-BaselineMarkdown {
    param([Parameter(Mandatory)]$Baseline)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("# Network baseline: $($Baseline.ComputerName)")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("Collected: $($Baseline.CollectedAt)  ")
    [void]$sb.AppendLine("OS: $($Baseline.OS)")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Interfaces')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Interface | IPv4 | Network | Gateway | Gateway MAC | DNS | DHCP | Rx err/disc | Tx err/disc |')
    [void]$sb.AppendLine('|---|---|---|---|---|---|---|---|---|')
    foreach ($i in $Baseline.Interfaces) {
        [void]$sb.AppendLine(('| {0} | {1}/{2} | {3} | {4} | {5} | {6} | {7} | {8}/{9} | {10}/{11} |' -f
                $i.Interface, $i.IPv4Address, $i.PrefixLength, $i.Network, $i.DefaultGateway, $i.GatewayMac,
                (@($i.DnsServers) -join ', '), $i.Dhcp, $i.RxErrors, $i.RxDiscards, $i.TxErrors, $i.TxDiscards))
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("Default routes: $($Baseline.DefaultRouteCount)  ")
    [void]$sb.AppendLine("Duplicate IPs in neighbor cache: $(if (@($Baseline.DuplicateNeighborIPs).Count) { @($Baseline.DuplicateNeighborIPs) -join ', ' } else { 'none' })")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## IPv4 routes')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Destination | Next hop | Interface | Metric |')
    [void]$sb.AppendLine('|---|---|---|---|')
    foreach ($r in $Baseline.Routes) {
        [void]$sb.AppendLine(('| {0} | {1} | {2} | {3} |' -f $r.Destination, $r.NextHop, $r.Interface, ($r.RouteMetric + $r.InterfaceMetric)))
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Neighbor cache (ARP)')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Interface | Entries | Randomized MACs | States |')
    [void]$sb.AppendLine('|---|---|---|---|')
    foreach ($n in $Baseline.NeighborSummary) {
        [void]$sb.AppendLine(('| {0} | {1} | {2} | {3} |' -f $n.Interface, $n.Count, $n.Randomized, $n.States))
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## TCP')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(('States: {0}  ' -f (($Baseline.TcpStates | ForEach-Object { '{0}={1}' -f $_.State, $_.Count }) -join ', ')))
    [void]$sb.AppendLine(('Listening ports: {0}' -f (@($Baseline.ListeningTcpPorts) -join ', ')))
    if (@($Baseline.Connectivity).Count) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('## Connectivity checks')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('| Check | Target | Result |')
        [void]$sb.AppendLine('|---|---|---|')
        foreach ($c in $Baseline.Connectivity) {
            [void]$sb.AppendLine(('| {0} | {1} | {2} |' -f $c.Check, $c.Target, $(if ($c.Result) { 'pass' } else { 'FAIL' })))
        }
    }
    return $sb.ToString()
}

# ------------------------------------------------------------------- main --

if ($MyInvocation.InvocationName -ne '.') {
    $privateDir = Join-Path $OutputDirectory 'private'
    $publicDir = Join-Path $OutputDirectory 'public'
    New-Item -ItemType Directory -Force -Path $privateDir, $publicDir | Out-Null

    $baseline = Get-NetworkBaseline -SkipConnectivity:$SkipConnectivity
    $baseline | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $privateDir 'baseline.json') -Encoding UTF8

    $public = ConvertTo-PublicBaseline -Baseline $baseline
    $public | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $publicDir 'baseline.json') -Encoding UTF8
    ConvertTo-BaselineMarkdown -Baseline $public | Set-Content -Path (Join-Path $publicDir 'baseline.md') -Encoding UTF8

    Write-Output "Private (do not commit): $privateDir"
    Write-Output "Public  (sanitized):     $publicDir"
}
