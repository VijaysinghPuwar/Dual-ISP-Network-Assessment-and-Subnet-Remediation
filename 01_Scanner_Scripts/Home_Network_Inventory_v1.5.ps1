#requires -Version 5.1
<#
.SYNOPSIS
    Creates a detailed inventory of an authorized private IPv4 network and
    generates HTML, PDF, CSV, and JSON reports.

.DESCRIPTION
    - Detects active private IPv4 subnets connected to this Windows computer.
    - Performs an ICMP/ARP-based host discovery scan.
    - Resolves DNS and NetBIOS names when available.
    - Tests a limited set of common TCP service ports.
    - Collects local Windows network adapters, routes, gateways, and neighbors.
    - Generates a single PDF report using Microsoft Edge/Google Chrome, with
      Microsoft Word as a fallback when available.

    This is an inventory and connectivity script. It does not attempt passwords,
    exploit vulnerabilities, bypass firewalls, or make configuration changes.

.NOTES
    Version 1.5 - allows devices with no detected open TCP ports.
    Run only on networks that you own or are authorized to assess.
    Windows PowerShell 5.1 or PowerShell 7 on Windows is supported.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\Home_Network_Inventory.ps1" -OpenReport

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\Home_Network_Inventory.ps1" `
      -Subnets "192.168.0.0/24","192.168.1.0/24" -OpenReport

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\Home_Network_Inventory.ps1" `
      -SkipPortScan -OpenReport
#>

[CmdletBinding()]
param(
    [Parameter()]
    [Alias("Subnet")]
    [string[]]$Subnets,

    [Parameter()]
    [string]$OutputDirectory = (Join-Path ([Environment]::GetFolderPath("Desktop")) ("Network_Inventory_{0}" -f (Get-Date -Format "yyyyMMdd_HHmmss"))),

    [Parameter()]
    [ValidateRange(100, 5000)]
    [int]$PingTimeoutMs = 450,

    [Parameter()]
    [ValidateRange(100, 5000)]
    [int]$TcpTimeoutMs = 450,

    [Parameter()]
    [ValidateRange(1, 65534)]
    [int]$MaxHostsPerSubnet = 1024,

    [Parameter()]
    [int[]]$Ports = @(
        22, 23, 53, 80, 135, 139, 443, 445, 548, 515, 631,
        3389, 5000, 5001, 5900, 5985, 5986, 6690, 8080, 8443,
        9100, 32400
    ),

    [Parameter()]
    [switch]$IncludeVirtualAdapters,

    [Parameter()]
    [switch]$SkipPortScan,

    [Parameter()]
    [switch]$OpenReport
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$script:StartedAt = Get-Date
$script:Warnings = New-Object System.Collections.Generic.List[string]
$script:LogPath = $null

$PortNames = [ordered]@{
    22    = "SSH"
    23    = "Telnet"
    53    = "DNS"
    80    = "HTTP"
    135   = "MS RPC"
    139   = "NetBIOS"
    443   = "HTTPS"
    445   = "SMB"
    515   = "LPD Printing"
    548   = "AFP"
    631   = "IPP Printing"
    3389  = "RDP"
    5000  = "Synology DSM HTTP"
    5001  = "Synology DSM HTTPS"
    5900  = "VNC/Screen Sharing"
    5985  = "WinRM HTTP"
    5986  = "WinRM HTTPS"
    6690  = "Synology Drive"
    8080  = "Alternate HTTP"
    8443  = "Alternate HTTPS"
    9100  = "JetDirect Printing"
    32400 = "Plex"
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("INFO", "WARN", "ERROR", "OK")]
        [string]$Level = "INFO"
    )

    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Write-Host $line

    if ($script:LogPath) {
        Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8
    }
}

function Add-ReportWarning {
    param([Parameter(Mandatory)][string]$Message)

    if (-not $script:Warnings.Contains($Message)) {
        [void]$script:Warnings.Add($Message)
    }
    Write-Log -Message $Message -Level "WARN"
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Test-PrivateIPv4 {
    param([Parameter(Mandatory)][string]$Address)

    try {
        $ip = [System.Net.IPAddress]::Parse($Address)
        $bytes = $ip.GetAddressBytes()

        if ($bytes.Count -ne 4) {
            return $false
        }

        if ($bytes[0] -eq 10) {
            return $true
        }

        if (($bytes[0] -eq 172) -and ($bytes[1] -ge 16) -and ($bytes[1] -le 31)) {
            return $true
        }

        if (($bytes[0] -eq 192) -and ($bytes[1] -eq 168)) {
            return $true
        }

        return $false
    }
    catch {
        return $false
    }
}

function Convert-IPv4ToUInt32 {
    param([Parameter(Mandatory)][string]$Address)

    $bytes = [System.Net.IPAddress]::Parse($Address).GetAddressBytes()
    if ($bytes.Count -ne 4) {
        throw "'$Address' is not an IPv4 address."
    }

    [Array]::Reverse($bytes)
    return [BitConverter]::ToUInt32($bytes, 0)
}

function Convert-UInt32ToIPv4 {
    param([Parameter(Mandatory)][uint32]$Value)

    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($bytes)
    return (New-Object System.Net.IPAddress -ArgumentList (, $bytes)).ToString()
}

function Get-CidrInformation {
    param([Parameter(Mandatory)][string]$Cidr)

    $parts = $Cidr.Trim().Split("/")
    if ($parts.Count -ne 2) {
        throw "Invalid CIDR '$Cidr'. Use a value such as 192.168.1.0/24."
    }

    $ipText = $parts[0].Trim()
    [int]$prefix = 0

    if (-not [int]::TryParse($parts[1], [ref]$prefix)) {
        throw "Invalid prefix in CIDR '$Cidr'."
    }

    if (($prefix -lt 0) -or ($prefix -gt 32)) {
        throw "Prefix length in '$Cidr' must be from 0 to 32."
    }

    if (-not (Test-PrivateIPv4 -Address $ipText)) {
        throw "CIDR '$Cidr' is not in an RFC1918 private IPv4 range."
    }

    # Windows PowerShell 5.1 may interpret the common all-bits-set
    # hexadecimal mask as signed -1 before a UInt64 conversion. Use
    # decimal unsigned-safe arithmetic instead for every /0 to /32 prefix.
    [uint64]$allIPv4Bits = 4294967295
    [uint64]$totalAddresses = [uint64][Math]::Pow(2, (32 - $prefix))
    [uint64]$hostMask = $totalAddresses - 1
    [uint64]$mask64 = $allIPv4Bits - $hostMask

    [uint64]$ipInt = Convert-IPv4ToUInt32 -Address $ipText
    [uint64]$networkInt = $ipInt -band $mask64
    [uint64]$broadcastInt = $networkInt + $totalAddresses - 1

    if ($prefix -eq 32) {
        [uint64]$firstHost = $networkInt
        [uint64]$lastHost = $networkInt
        [uint64]$hostCount = 1
    }
    elseif ($prefix -eq 31) {
        [uint64]$firstHost = $networkInt
        [uint64]$lastHost = $broadcastInt
        [uint64]$hostCount = 2
    }
    else {
        [uint64]$firstHost = $networkInt + 1
        [uint64]$lastHost = $broadcastInt - 1
        [uint64]$hostCount = $totalAddresses - 2
    }

    [pscustomobject]@{
        OriginalCidr  = $Cidr
        NormalizedCidr = ("{0}/{1}" -f (Convert-UInt32ToIPv4 -Value ([uint32]$networkInt)), $prefix)
        PrefixLength  = $prefix
        NetworkInt    = $networkInt
        BroadcastInt  = $broadcastInt
        FirstHostInt  = $firstHost
        LastHostInt   = $lastHost
        HostCount     = $hostCount
    }
}

function Test-IpInCidr {
    param(
        [Parameter(Mandatory)][string]$Address,
        [Parameter(Mandatory)]$CidrInformation
    )

    try {
        [uint64]$value = Convert-IPv4ToUInt32 -Address $Address
        return (($value -ge $CidrInformation.NetworkInt) -and ($value -le $CidrInformation.BroadcastInt))
    }
    catch {
        return $false
    }
}

function Get-AutoDetectedSubnets {
    param([switch]$IncludeVirtual)

    $detected = New-Object System.Collections.Generic.List[string]
    $ips = Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred -ErrorAction Stop |
        Where-Object {
            $_.IPAddress -ne "127.0.0.1" -and
            $_.IPAddress -notlike "169.254.*" -and
            (Test-PrivateIPv4 -Address $_.IPAddress)
        }

    foreach ($ip in $ips) {
        $adapter = Get-NetAdapter -InterfaceIndex $ip.InterfaceIndex -ErrorAction SilentlyContinue
        if (-not $adapter) {
            continue
        }

        if ($adapter.Status -ne "Up") {
            continue
        }

        $adapterText = "{0} {1}" -f $adapter.Name, $adapter.InterfaceDescription
        $looksVirtual = $adapterText -match "(?i)virtual|hyper-v|vmware|virtualbox|docker|wsl|loopback|tunnel|teredo|bluetooth|vpn"

        if ($looksVirtual -and -not $IncludeVirtual) {
            continue
        }

        $cidr = "{0}/{1}" -f $ip.IPAddress, $ip.PrefixLength
        $info = Get-CidrInformation -Cidr $cidr

        if (-not $detected.Contains($info.NormalizedCidr)) {
            [void]$detected.Add($info.NormalizedCidr)
        }
    }

    return @($detected)
}

function Get-IpAddressRange {
    param([Parameter(Mandatory)]$CidrInformation)

    $addresses = New-Object System.Collections.Generic.List[string]
    for ([uint64]$current = $CidrInformation.FirstHostInt; $current -le $CidrInformation.LastHostInt; $current++) {
        [void]$addresses.Add((Convert-UInt32ToIPv4 -Value ([uint32]$current)))
    }

    return @($addresses)
}

function Invoke-PingSweep {
    param(
        [Parameter(Mandatory)][string[]]$Addresses,
        [Parameter(Mandatory)][int]$TimeoutMs
    )

    # Windows PowerShell 5.1 can throw "Argument types do not match" when
    # async Task objects and Generic.List[object] are returned through an
    # array subexpression. A synchronous Ping.Send call is more compatible
    # and still provides all information required for this home inventory.
    $results = New-Object System.Collections.ArrayList
    $index = 0

    foreach ($address in $Addresses) {
        $index++
        Write-Progress -Activity "Discovering network devices" `
            -Status ("Ping {0} of {1}: {2}" -f $index, $Addresses.Count, $address) `
            -PercentComplete (($index / [Math]::Max($Addresses.Count, 1)) * 100)

        $pinger = New-Object System.Net.NetworkInformation.Ping

        try {
            $reply = $pinger.Send($address, $TimeoutMs)
            $alive = $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success
            $latency = if ($alive) { [int64]$reply.RoundtripTime } else { $null }

            [void]$results.Add([pscustomobject]@{
                IPAddress  = $address
                IsAlive    = $alive
                PingStatus = $reply.Status.ToString()
                PingMs     = $latency
            })
        }
        catch {
            [void]$results.Add([pscustomobject]@{
                IPAddress  = $address
                IsAlive    = $false
                PingStatus = "Error"
                PingMs     = $null
            })
        }
        finally {
            $pinger.Dispose()
        }
    }

    Write-Progress -Activity "Discovering network devices" -Completed
    return $results.ToArray()
}

function Resolve-HostNameWithTimeout {
    param(
        [Parameter(Mandatory)][string]$IPAddress,
        [int]$TimeoutMs = 900
    )

    try {
        $task = [System.Net.Dns]::GetHostEntryAsync($IPAddress)
        if ($task.Wait($TimeoutMs)) {
            $entry = $task.Result
            if ($entry -and $entry.HostName -and ($entry.HostName -ne $IPAddress)) {
                return $entry.HostName
            }
        }
    }
    catch {
    }

    return $null
}

function Get-NetBIOSName {
    param(
        [Parameter(Mandatory)][string]$IPAddress,
        [int]$TimeoutMs = 1800
    )

    $nbtstat = Get-Command "nbtstat.exe" -ErrorAction SilentlyContinue
    if (-not $nbtstat) {
        return $null
    }

    $process = $null
    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $nbtstat.Source
        $startInfo.Arguments = "-A $IPAddress"
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.CreateNoWindow = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        [void]$process.Start()

        if (-not $process.WaitForExit($TimeoutMs)) {
            try { $process.Kill() } catch {}
            return $null
        }

        $output = $process.StandardOutput.ReadToEnd()
        $match = [regex]::Match($output, "(?im)^\s*(\S+)\s+<00>\s+UNIQUE")
        if ($match.Success) {
            return $match.Groups[1].Value.Trim()
        }
    }
    catch {
    }
    finally {
        if ($process) {
            $process.Dispose()
        }
    }

    return $null
}

function Get-OpenTcpPorts {
    param(
        [Parameter(Mandatory)][string]$IPAddress,
        [Parameter(Mandatory)][int[]]$PortList,
        [Parameter(Mandatory)][int]$TimeoutMs
    )

    $probes = New-Object System.Collections.Generic.List[object]
    $openPorts = New-Object System.Collections.Generic.List[int]

    foreach ($port in ($PortList | Sort-Object -Unique)) {
        $client = New-Object System.Net.Sockets.TcpClient

        try {
            $task = $client.ConnectAsync($IPAddress, $port)
            [void]$probes.Add([pscustomobject]@{
                Port   = [int]$port
                Client = $client
                Task   = $task
            })
        }
        catch {
            $client.Dispose()
        }
    }

    foreach ($probe in $probes) {
        try {
            if ($probe.Task.Wait($TimeoutMs) -and $probe.Client.Connected) {
                [void]$openPorts.Add([int]$probe.Port)
            }
        }
        catch {
        }
        finally {
            $probe.Client.Dispose()
        }
    }

    return @($openPorts | Sort-Object)
}

function Get-LikelyDeviceType {
    param(
        [Parameter(Mandatory)][string]$IPAddress,
        [Parameter(Mandatory)][AllowEmptyCollection()][int[]]$OpenPorts,
        [bool]$IsGateway,
        [bool]$IsLocalComputer,
        [string]$HostName
    )

    if ($IsLocalComputer) {
        return "This Windows PC"
    }

    if ($IsGateway) {
        return "Router / default gateway"
    }

    if (($OpenPorts -contains 5000) -or ($OpenPorts -contains 5001) -or ($OpenPorts -contains 6690)) {
        return "Synology NAS (likely)"
    }

    if (($OpenPorts -contains 445) -or ($OpenPorts -contains 3389) -or
        ($OpenPorts -contains 5985) -or ($OpenPorts -contains 5986) -or
        ($OpenPorts -contains 135)) {
        return "Windows PC/server (likely)"
    }

    if (($OpenPorts -contains 548) -or (($OpenPorts -contains 5900) -and ($OpenPorts -contains 22))) {
        return "Mac/Apple device (likely)"
    }

    if ($OpenPorts -contains 32400) {
        return "Media server or NAS (likely)"
    }

    if (($OpenPorts -contains 9100) -or ($OpenPorts -contains 515) -or ($OpenPorts -contains 631)) {
        return "Network printer (likely)"
    }

    if (($OpenPorts -contains 53) -and (($OpenPorts -contains 80) -or ($OpenPorts -contains 443))) {
        return "Router/network appliance (likely)"
    }

    if ($HostName -match "(?i)synology|diskstation|rackstation") {
        return "Synology NAS (hostname indication)"
    }

    if ($HostName -match "(?i)macbook|imac|mac-mini|apple") {
        return "Mac/Apple device (hostname indication)"
    }

    if ($OpenPorts.Count -gt 0) {
        return "Network host with TCP services"
    }

    return "Unknown network device"
}

function Convert-ObjectsToHtmlTable {
    param(
        [Parameter(Mandatory)]$InputObjects,
        [Parameter(Mandatory)][string]$EmptyMessage
    )

    $array = @($InputObjects)
    if ($array.Count -eq 0) {
        return "<p class='muted'>$([System.Net.WebUtility]::HtmlEncode($EmptyMessage))</p>"
    }

    return (($array | ConvertTo-Html -Fragment) -join [Environment]::NewLine)
}

function Convert-HtmlReportToPdf {
    param(
        [Parameter(Mandatory)][string]$HtmlPath,
        [Parameter(Mandatory)][string]$PdfPath
    )

    $browserCandidates = New-Object System.Collections.Generic.List[string]
    $browserRoots = @(
        ${env:ProgramFiles(x86)},
        $env:ProgramFiles,
        $env:LOCALAPPDATA
    ) | Where-Object { $_ } | Select-Object -Unique

    foreach ($root in $browserRoots) {
        foreach ($relativePath in @(
            "Microsoft\Edge\Application\msedge.exe",
            "Google\Chrome\Application\chrome.exe"
        )) {
            $candidate = Join-Path $root $relativePath
            if ((Test-Path -LiteralPath $candidate) -and -not $browserCandidates.Contains($candidate)) {
                [void]$browserCandidates.Add($candidate)
            }
        }
    }

    $resolvedHtml = (Resolve-Path -LiteralPath $HtmlPath).Path
    $htmlUri = (New-Object System.Uri($resolvedHtml)).AbsoluteUri

    foreach ($browser in $browserCandidates) {
        try {
            Write-Log -Message ("Creating PDF with {0}" -f (Split-Path $browser -Leaf)) -Level "INFO"

            $arguments = @(
                "--headless",
                "--disable-gpu",
                "--no-pdf-header-footer",
                ("--print-to-pdf=`"{0}`"" -f $PdfPath),
                ("`"{0}`"" -f $htmlUri)
            )

            $process = Start-Process -FilePath $browser -ArgumentList $arguments -PassThru -Wait -WindowStyle Hidden
            Start-Sleep -Milliseconds 400

            if ((Test-Path -LiteralPath $PdfPath) -and ((Get-Item -LiteralPath $PdfPath).Length -gt 1024)) {
                return [pscustomobject]@{
                    Success = $true
                    Method  = (Split-Path $browser -Leaf)
                }
            }
        }
        catch {
            Add-ReportWarning -Message ("PDF creation with browser failed: {0}" -f $_.Exception.Message)
        }
    }

    # Optional fallback when Microsoft Word is installed.
    $word = $null
    $document = $null
    try {
        Write-Log -Message "Trying Microsoft Word PDF conversion fallback." -Level "INFO"
        $word = New-Object -ComObject Word.Application
        $word.Visible = $false
        $word.DisplayAlerts = 0
        $document = $word.Documents.Open($resolvedHtml, $false, $true)
        $wdFormatPDF = 17
        $document.SaveAs([ref]$PdfPath, [ref]$wdFormatPDF)
        $document.Close($false)
        $document = $null
        $word.Quit()
        $word = $null

        if ((Test-Path -LiteralPath $PdfPath) -and ((Get-Item -LiteralPath $PdfPath).Length -gt 1024)) {
            return [pscustomobject]@{
                Success = $true
                Method  = "Microsoft Word"
            }
        }
    }
    catch {
        Add-ReportWarning -Message ("Microsoft Word PDF fallback was unavailable or failed: {0}" -f $_.Exception.Message)
    }
    finally {
        if ($document) {
            try { $document.Close($false) } catch {}
        }
        if ($word) {
            try { $word.Quit() } catch {}
        }
        if ($document) {
            try { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($document) } catch {}
        }
        if ($word) {
            try { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($word) } catch {}
        }
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }

    return [pscustomobject]@{
        Success = $false
        Method  = "HTML only"
    }
}

try {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
    $script:LogPath = Join-Path $OutputDirectory "Network_Inventory.log"

    $htmlPath = Join-Path $OutputDirectory "Network_Inventory_Report.html"
    $pdfPath = Join-Path $OutputDirectory "Network_Inventory_Report.pdf"
    $csvPath = Join-Path $OutputDirectory "Network_Devices.csv"
    $jsonPath = Join-Path $OutputDirectory "Network_Inventory.json"

    Write-Log -Message "Authorized private-network inventory started."
    Write-Log -Message ("Output directory: {0}" -f $OutputDirectory)

    $isAdmin = Test-IsAdministrator
    if (-not $isAdmin) {
        Add-ReportWarning -Message "The script is not running as Administrator. The scan will still work, but some local network details may be incomplete."
    }

    # Collect local system information.
    $computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $operatingSystem = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $processor = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1

    $localSystem = [pscustomobject]@{
        ComputerName       = $env:COMPUTERNAME
        CurrentUser        = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        Manufacturer       = $computerSystem.Manufacturer
        Model              = $computerSystem.Model
        OperatingSystem    = $operatingSystem.Caption
        OSVersion          = $operatingSystem.Version
        OSBuild            = $operatingSystem.BuildNumber
        InstalledRAMGB     = if ($computerSystem.TotalPhysicalMemory) { [Math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2) } else { $null }
        Processor          = $processor.Name
        PowerShellVersion  = $PSVersionTable.PSVersion.ToString()
        RunningAsAdmin     = $isAdmin
        ScanStarted        = $script:StartedAt
    }

    # Collect adapter details.
    $adapterCim = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue
    $adapterRows = New-Object System.Collections.Generic.List[object]
    $localPrivateIps = New-Object System.Collections.Generic.List[string]

    foreach ($adapter in (Get-NetAdapter -ErrorAction SilentlyContinue | Sort-Object ifIndex)) {
        $config = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue
        if (-not $config) {
            continue
        }

        $ipv4Values = @($config.IPv4Address | ForEach-Object {
            if (Test-PrivateIPv4 -Address $_.IPAddress) {
                if (-not $localPrivateIps.Contains($_.IPAddress)) {
                    [void]$localPrivateIps.Add($_.IPAddress)
                }
            }
            "{0}/{1}" -f $_.IPAddress, $_.PrefixLength
        })

        $dhcpRecord = $adapterCim | Where-Object { $_.InterfaceIndex -eq $adapter.ifIndex } | Select-Object -First 1

        # Some adapters (virtual, disconnected, VPN, secondary, or local-only)
        # do not have a default gateway or DNS object. Under StrictMode, directly
        # reading .NextHop from a null value causes PropertyNotFoundStrict.
        $gatewayValues = @(
            foreach ($gatewayObject in @($config.IPv4DefaultGateway)) {
                if ($null -ne $gatewayObject -and
                    $null -ne $gatewayObject.PSObject.Properties["NextHop"] -and
                    $gatewayObject.NextHop) {
                    $gatewayObject.NextHop
                }
            }
        )

        $dnsServerValues = @(
            foreach ($dnsObject in @($config.DNSServer)) {
                if ($null -ne $dnsObject -and
                    $null -ne $dnsObject.PSObject.Properties["ServerAddresses"]) {
                    foreach ($serverAddress in @($dnsObject.ServerAddresses)) {
                        if ($serverAddress) {
                            $serverAddress
                        }
                    }
                }
            }
        )

        [void]$adapterRows.Add([pscustomobject]@{
            InterfaceIndex = $adapter.ifIndex
            Alias          = $adapter.Name
            Description    = $adapter.InterfaceDescription
            Status         = $adapter.Status
            LinkSpeed      = $adapter.LinkSpeed
            MacAddress     = $adapter.MacAddress
            IPv4           = ($ipv4Values -join ", ")
            DefaultGateway = ($gatewayValues -join ", ")
            DnsServers     = ($dnsServerValues -join ", ")
            DhcpEnabled    = if ($dhcpRecord) { $dhcpRecord.DHCPEnabled } else { $null }
        })
    }

    # Determine scan subnets.
    if (-not $Subnets -or $Subnets.Count -eq 0) {
        $Subnets = Get-AutoDetectedSubnets -IncludeVirtual:$IncludeVirtualAdapters
        if (-not $Subnets -or $Subnets.Count -eq 0) {
            throw "No active RFC1918 private IPv4 subnet was detected. Supply -Subnets manually, for example -Subnets '192.168.1.0/24'."
        }
        Write-Log -Message ("Auto-detected subnets: {0}" -f ($Subnets -join ", "))
    }
    else {
        Write-Log -Message ("User-specified subnets: {0}" -f ($Subnets -join ", "))
    }

    $cidrRecords = New-Object System.Collections.Generic.List[object]
    $normalizedSubnets = New-Object System.Collections.Generic.List[string]

    foreach ($cidr in $Subnets) {
        $info = Get-CidrInformation -Cidr $cidr

        if (-not $normalizedSubnets.Contains($info.NormalizedCidr)) {
            [void]$normalizedSubnets.Add($info.NormalizedCidr)
            [void]$cidrRecords.Add($info)
        }
    }

    # Get gateways and route table.
    $gatewayIps = @(
        Get-NetIPConfiguration -ErrorAction SilentlyContinue |
            ForEach-Object {
                foreach ($gatewayObject in @($_.IPv4DefaultGateway)) {
                    if ($null -ne $gatewayObject -and
                        $null -ne $gatewayObject.PSObject.Properties["NextHop"] -and
                        $gatewayObject.NextHop) {
                        $gatewayObject.NextHop
                    }
                }
            } |
            Where-Object { $_ -and (Test-PrivateIPv4 -Address $_) } |
            Sort-Object -Unique
    )

    $routeRows = @(
        Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Sort-Object DestinationPrefix, RouteMetric |
            Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric, Protocol, State
    )

    $scanSummaries = New-Object System.Collections.Generic.List[object]
    $allPingResults = New-Object System.Collections.Generic.List[object]
    $allTargetAddresses = New-Object System.Collections.Generic.List[string]

    foreach ($cidrInfo in $cidrRecords) {
        if ($cidrInfo.HostCount -gt $MaxHostsPerSubnet) {
            $message = "Skipped $($cidrInfo.NormalizedCidr): it contains $($cidrInfo.HostCount) host addresses, exceeding MaxHostsPerSubnet=$MaxHostsPerSubnet. Supply a narrower subnet or intentionally raise -MaxHostsPerSubnet."
            Add-ReportWarning -Message $message
            [void]$scanSummaries.Add([pscustomobject]@{
                Subnet        = $cidrInfo.NormalizedCidr
                HostCapacity  = $cidrInfo.HostCount
                AddressesTested = 0
                PingResponsive  = 0
                Status        = "Skipped - too large"
            })
            continue
        }

        Write-Log -Message ("Scanning subnet {0} ({1} possible hosts)." -f $cidrInfo.NormalizedCidr, $cidrInfo.HostCount)
        $addresses = Get-IpAddressRange -CidrInformation $cidrInfo

        foreach ($address in $addresses) {
            if (-not $allTargetAddresses.Contains($address)) {
                [void]$allTargetAddresses.Add($address)
            }
        }

        $pingResults = @(Invoke-PingSweep -Addresses $addresses -TimeoutMs $PingTimeoutMs)
        foreach ($result in $pingResults) {
            [void]$allPingResults.Add($result)
        }

        [void]$scanSummaries.Add([pscustomobject]@{
            Subnet          = $cidrInfo.NormalizedCidr
            HostCapacity    = $cidrInfo.HostCount
            AddressesTested = $addresses.Count
            PingResponsive  = @($pingResults | Where-Object IsAlive).Count
            Status          = "Scanned"
        })
    }

    if ($allTargetAddresses.Count -eq 0) {
        throw "No host addresses were selected for scanning. Review the subnet warnings or increase -MaxHostsPerSubnet intentionally."
    }

    # ICMP attempts normally populate ARP/neighbor cache even when a host blocks ping.
    Start-Sleep -Milliseconds 350
    $neighborRowsRaw = @(
        Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object {
                $_.IPAddress -and
                $_.LinkLayerAddress -and
                $_.LinkLayerAddress -notmatch "^(00-00-00-00-00-00|FF-FF-FF-FF-FF-FF)$" -and
                $_.State -notin @("Unreachable", "Incomplete")
            }
    )

    $neighborByIp = @{}
    foreach ($neighbor in $neighborRowsRaw) {
        if (-not $neighborByIp.ContainsKey($neighbor.IPAddress)) {
            $neighborByIp[$neighbor.IPAddress] = $neighbor
        }
    }

    $pingByIp = @{}
    foreach ($ping in $allPingResults) {
        $pingByIp[$ping.IPAddress] = $ping
    }

    $discoveredIps = New-Object System.Collections.Generic.List[string]

    foreach ($ping in $allPingResults) {
        if ($ping.IsAlive -and -not $discoveredIps.Contains($ping.IPAddress)) {
            [void]$discoveredIps.Add($ping.IPAddress)
        }
    }

    foreach ($neighbor in $neighborRowsRaw) {
        $inScanRange = $false
        foreach ($cidrInfo in $cidrRecords) {
            if ((Test-IpInCidr -Address $neighbor.IPAddress -CidrInformation $cidrInfo) -and
                ($cidrInfo.HostCount -le $MaxHostsPerSubnet)) {
                $inScanRange = $true
                break
            }
        }

        if ($inScanRange -and -not $discoveredIps.Contains($neighbor.IPAddress)) {
            [void]$discoveredIps.Add($neighbor.IPAddress)
        }
    }

    foreach ($ip in $localPrivateIps) {
        if ($allTargetAddresses.Contains($ip) -and -not $discoveredIps.Contains($ip)) {
            [void]$discoveredIps.Add($ip)
        }
    }

    foreach ($gateway in $gatewayIps) {
        if ($allTargetAddresses.Contains($gateway) -and -not $discoveredIps.Contains($gateway)) {
            [void]$discoveredIps.Add($gateway)
        }
    }

    $deviceRows = New-Object System.Collections.Generic.List[object]
    $hostIndex = 0

    foreach ($ip in ($discoveredIps | Sort-Object { Convert-IPv4ToUInt32 -Address $_ })) {
        $hostIndex++
        Write-Progress -Activity "Identifying discovered devices" `
            -Status ("Device {0} of {1}: {2}" -f $hostIndex, $discoveredIps.Count, $ip) `
            -PercentComplete (($hostIndex / [Math]::Max($discoveredIps.Count, 1)) * 100)

        $ping = if ($pingByIp.ContainsKey($ip)) { $pingByIp[$ip] } else { $null }
        $neighbor = if ($neighborByIp.ContainsKey($ip)) { $neighborByIp[$ip] } else { $null }
        $hostname = Resolve-HostNameWithTimeout -IPAddress $ip
        $isGateway = $gatewayIps -contains $ip
        $isLocal = $localPrivateIps.Contains($ip)
        $openPorts = @()

        if (-not $SkipPortScan) {
            $openPorts = @(Get-OpenTcpPorts -IPAddress $ip -PortList $Ports -TimeoutMs $TcpTimeoutMs)
        }

        $netbiosName = $null
        if (($openPorts -contains 139) -or ($openPorts -contains 445)) {
            $netbiosName = Get-NetBIOSName -IPAddress $ip
        }

        if (-not $hostname -and $netbiosName) {
            $hostname = $netbiosName
        }

        $serviceText = @(
            foreach ($port in $openPorts) {
                $name = if ($PortNames.Contains($port)) { $PortNames[$port] } else { "TCP" }
                "{0}/{1}" -f $port, $name
            }
        ) -join "; "

        $reachability = if ($ping -and $ping.IsAlive) {
            "ICMP reply"
        }
        elseif ($neighbor) {
            "ARP/neighbor detected"
        }
        elseif ($isLocal) {
            "Local computer"
        }
        elseif ($isGateway) {
            "Configured gateway"
        }
        else {
            "Detected"
        }

        $notes = New-Object System.Collections.Generic.List[string]
        if ($ping -and -not $ping.IsAlive -and $neighbor) {
            [void]$notes.Add("Host appears online but may block ICMP ping.")
        }
        if ($isGateway) {
            [void]$notes.Add("Configured as a default gateway on this PC.")
        }
        if ($isLocal) {
            [void]$notes.Add("Address belongs to the computer running this report.")
        }

        $deviceType = Get-LikelyDeviceType `
            -IPAddress $ip `
            -OpenPorts $openPorts `
            -IsGateway $isGateway `
            -IsLocalComputer $isLocal `
            -HostName $hostname

        [void]$deviceRows.Add([pscustomobject]@{
            IPAddress       = $ip
            HostName        = $hostname
            NetBIOSName     = $netbiosName
            MacAddress      = if ($neighbor) { $neighbor.LinkLayerAddress } else { $null }
            Interface       = if ($neighbor) { $neighbor.InterfaceAlias } else { $null }
            Reachability    = $reachability
            PingMs          = if ($ping) { $ping.PingMs } else { $null }
            IsDefaultGateway = $isGateway
            LikelyDevice    = $deviceType
            OpenTcpServices = $serviceText
            Notes           = ($notes -join " ")
        })
    }

    Write-Progress -Activity "Identifying discovered devices" -Completed

    $neighborRows = @(
        $neighborRowsRaw |
            Sort-Object InterfaceAlias, IPAddress |
            Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias
    )

    # Add limitations that are especially relevant to multi-router home networks.
    Add-ReportWarning -Message "Device type is an evidence-based estimate from addresses, names, gateways, and common TCP ports; it is not authenticated operating-system identification."
    Add-ReportWarning -Message "A second router operating in access-point/bridge mode should appear on the same subnet. A double-NAT router can hide its downstream devices unless this PC has a route and the router permits traffic between subnets."
    Add-ReportWarning -Message "Offline, sleeping, firewall-filtered, guest-network-isolated, Wi-Fi client-isolated, or IPv6-only devices may not appear."

    $completedAt = Get-Date
    $duration = New-TimeSpan -Start $script:StartedAt -End $completedAt
    $openServiceCount = @(
        $deviceRows | Where-Object { $_.OpenTcpServices } |
            ForEach-Object { ($_.OpenTcpServices -split ";").Count } |
            Measure-Object -Sum
    ).Sum

    if ($null -eq $openServiceCount) {
        $openServiceCount = 0
    }

    $summary = [pscustomobject]@{
        ReportGenerated     = $completedAt
        Duration            = $duration.ToString()
        SubnetsRequested    = ($normalizedSubnets -join ", ")
        SubnetsScanned      = (@($scanSummaries.ToArray() | Where-Object Status -eq "Scanned").Count)
        AddressesTested     = (@($scanSummaries.ToArray() | Measure-Object AddressesTested -Sum).Sum)
        DevicesDiscovered   = $deviceRows.Count
        DefaultGateways     = ($gatewayIps -join ", ")
        OpenTcpServicesFound = $openServiceCount
        PortScanEnabled     = (-not $SkipPortScan)
        RunningAsAdmin      = $isAdmin
    }

    # Save machine-readable exports before generating the final report.
    $deviceRows |
        Sort-Object { Convert-IPv4ToUInt32 -Address $_.IPAddress } |
        Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

    $reportObject = [pscustomobject]@{
        Summary         = $summary
        LocalSystem     = $localSystem
        NetworkAdapters = $adapterRows.ToArray()
        SubnetResults   = $scanSummaries.ToArray()
        Devices         = $deviceRows.ToArray()
        IPv4Routes      = @($routeRows)
        NeighborCache   = @($neighborRows)
        Warnings        = $script:Warnings.ToArray()
    }

    $reportObject |
        ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $jsonPath -Encoding UTF8

    $warningHtml = if ($script:Warnings.Count -gt 0) {
        "<ul>" + (($script:Warnings | ForEach-Object {
            "<li>$([System.Net.WebUtility]::HtmlEncode($_))</li>"
        }) -join [Environment]::NewLine) + "</ul>"
    }
    else {
        "<p class='muted'>No warnings were recorded.</p>"
    }

    $summaryCards = @"
<div class="cards">
  <div class="card"><span>Devices</span><strong>$($summary.DevicesDiscovered)</strong></div>
  <div class="card"><span>Addresses tested</span><strong>$($summary.AddressesTested)</strong></div>
  <div class="card"><span>Subnets scanned</span><strong>$($summary.SubnetsScanned)</strong></div>
  <div class="card"><span>Open TCP services</span><strong>$($summary.OpenTcpServicesFound)</strong></div>
</div>
"@

    $summaryTable = Convert-ObjectsToHtmlTable -InputObjects @($summary) -EmptyMessage "No summary available."
    $systemTable = Convert-ObjectsToHtmlTable -InputObjects @($localSystem) -EmptyMessage "No local system information available."
    $subnetTable = Convert-ObjectsToHtmlTable -InputObjects $scanSummaries.ToArray() -EmptyMessage "No subnet results available."
    $adapterTable = Convert-ObjectsToHtmlTable -InputObjects $adapterRows.ToArray() -EmptyMessage "No adapter information available."
    $deviceTable = Convert-ObjectsToHtmlTable -InputObjects @($deviceRows.ToArray() | Sort-Object { Convert-IPv4ToUInt32 -Address $_.IPAddress }) -EmptyMessage "No devices were discovered."
    $routeTable = Convert-ObjectsToHtmlTable -InputObjects @($routeRows) -EmptyMessage "No IPv4 routes were collected."
    $neighborTable = Convert-ObjectsToHtmlTable -InputObjects @($neighborRows) -EmptyMessage "No neighbor-cache entries were collected."

    $css = @"
@page { size: A4 landscape; margin: 10mm; }
* { box-sizing: border-box; }
body {
    font-family: "Segoe UI", Arial, sans-serif;
    margin: 0;
    color: #172033;
    background: #f3f6fa;
    font-size: 10.5px;
}
.container {
    max-width: 1500px;
    margin: 0 auto;
    padding: 24px;
}
.header {
    background: linear-gradient(135deg, #132238, #274b6d);
    color: white;
    padding: 24px 28px;
    border-radius: 12px;
    margin-bottom: 18px;
}
.header h1 {
    margin: 0 0 6px 0;
    font-size: 28px;
}
.header p {
    margin: 4px 0;
    opacity: 0.92;
}
.badge {
    display: inline-block;
    margin-top: 10px;
    padding: 5px 9px;
    border: 1px solid rgba(255,255,255,0.45);
    border-radius: 999px;
    font-size: 9px;
}
.cards {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 10px;
    margin-bottom: 18px;
}
.card {
    background: white;
    border: 1px solid #dbe3ed;
    border-radius: 10px;
    padding: 13px 15px;
}
.card span {
    display: block;
    color: #526177;
    font-size: 9px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
}
.card strong {
    display: block;
    font-size: 21px;
    margin-top: 4px;
}
.section {
    background: white;
    border: 1px solid #dbe3ed;
    border-radius: 10px;
    padding: 16px;
    margin-bottom: 14px;
}
.section h2 {
    margin: 0 0 10px 0;
    font-size: 17px;
    color: #173f63;
    border-bottom: 2px solid #e8eef5;
    padding-bottom: 7px;
}
table {
    width: 100%;
    border-collapse: collapse;
    table-layout: auto;
}
th, td {
    border: 1px solid #d8e0ea;
    padding: 6px 7px;
    text-align: left;
    vertical-align: top;
    overflow-wrap: anywhere;
}
th {
    background: #eaf1f8;
    color: #173f63;
    font-weight: 650;
}
tr:nth-child(even) td {
    background: #f8fafc;
}
.muted {
    color: #6c7889;
    font-style: italic;
}
.warning {
    border-left: 5px solid #bf7a00;
    background: #fff8e8;
}
.footer {
    color: #657287;
    font-size: 9px;
    text-align: center;
    padding: 8px;
}
code {
    background: #edf2f7;
    border-radius: 4px;
    padding: 1px 4px;
}
"@

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Windows Private Network Inventory</title>
<style>
$css
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>Windows Private Network Inventory</h1>
    <p>Computer: $([System.Net.WebUtility]::HtmlEncode($env:COMPUTERNAME))</p>
    <p>Generated: $([System.Net.WebUtility]::HtmlEncode($completedAt.ToString("yyyy-MM-dd HH:mm:ss zzz")))</p>
    <div class="badge">Authorized RFC1918 inventory - no credential attacks or vulnerability exploitation</div>
  </div>

  $summaryCards

  <div class="section">
    <h2>Executive Summary</h2>
    $summaryTable
  </div>

  <div class="section">
    <h2>Discovered Device Inventory</h2>
    $deviceTable
  </div>

  <div class="section">
    <h2>Subnet Scan Results</h2>
    $subnetTable
  </div>

  <div class="section">
    <h2>Local Windows System</h2>
    $systemTable
  </div>

  <div class="section">
    <h2>Network Adapters</h2>
    $adapterTable
  </div>

  <div class="section">
    <h2>IPv4 Routing Table</h2>
    $routeTable
  </div>

  <div class="section">
    <h2>ARP / Neighbor Cache</h2>
    $neighborTable
  </div>

  <div class="section warning">
    <h2>Interpretation and Limitations</h2>
    $warningHtml
  </div>

  <div class="footer">
    Files in this report package: PDF, HTML, CSV device inventory, JSON data, and scan log.
  </div>
</div>
</body>
</html>
"@

    Set-Content -LiteralPath $htmlPath -Value $html -Encoding UTF8
    Write-Log -Message ("HTML report created: {0}" -f $htmlPath) -Level "OK"

    $pdfResult = Convert-HtmlReportToPdf -HtmlPath $htmlPath -PdfPath $pdfPath

    if ($pdfResult.Success) {
        Write-Log -Message ("PDF report created with {0}: {1}" -f $pdfResult.Method, $pdfPath) -Level "OK"
    }
    else {
        Add-ReportWarning -Message "A PDF converter was not available. The complete HTML report was created and can be opened in a browser and printed using 'Microsoft Print to PDF'."
    }

    Write-Log -Message ("CSV device inventory: {0}" -f $csvPath) -Level "OK"
    Write-Log -Message ("JSON report data: {0}" -f $jsonPath) -Level "OK"
    Write-Log -Message ("Log file: {0}" -f $script:LogPath) -Level "OK"
    Write-Log -Message ("Completed. Devices discovered: {0}" -f $deviceRows.Count) -Level "OK"

    Write-Host ""
    Write-Host "REPORT PACKAGE" -ForegroundColor Cyan
    Write-Host "PDF : $pdfPath"
    Write-Host "HTML: $htmlPath"
    Write-Host "CSV : $csvPath"
    Write-Host "JSON: $jsonPath"
    Write-Host "LOG : $script:LogPath"
    Write-Host ""

    if ($OpenReport) {
        if (Test-Path -LiteralPath $pdfPath) {
            Start-Process -FilePath $pdfPath
        }
        else {
            Start-Process -FilePath $htmlPath
        }
    }
}
catch {
    try {
        Write-Log -Message $_.Exception.Message -Level "ERROR"
    }
    catch {
        Write-Error $_.Exception.Message
    }

    throw
}
