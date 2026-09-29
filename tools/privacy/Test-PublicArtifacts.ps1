<#
.SYNOPSIS
    Pre-publication privacy check for this repository.

.DESCRIPTION
    Scans text files for data that should not be public: full MAC addresses,
    public IPv4 addresses, email addresses, Windows SIDs, user home paths,
    credential-looking strings and packet captures. It also reads the text
    inside .pptx/.docx files. Nothing is sent anywhere; the script only reads
    files and prints findings.

    Personal terms (real hostnames, usernames) belong in a local, git-ignored
    file named .privacy-denylist.txt at the repository root, one term per line.

    Exit code 0 = clean, 1 = findings.

.PARAMETER Path
    Repository root. Defaults to the parent of tools\.

.PARAMETER TrackedOnly
    Only scan files tracked by git (what would actually be pushed).
#>
[CmdletBinding()]
param(
    [string]$Path,
    [switch]$TrackedOnly
)

Set-StrictMode -Version 2.0

$script:TextExtensions = '.md', '.txt', '.csv', '.json', '.log', '.html', '.htm', '.ps1', '.psm1', '.sh',
    '.py', '.yml', '.yaml', '.xml', '.gnmap', '.nmap', '.mmd', '.dot', '.svg', '.gitignore', '.gitattributes', '.toml', '.cfg'
$script:CaptureExtensions = '.pcap', '.pcapng', '.cap', '.etl', '.pktmon'
$script:SkipDirs = '.git', 'node_modules', '.venv', '__pycache__', '.pytest_cache', '.ruff_cache'

# Well-known anycast resolvers identify nothing about this environment.
$script:AllowedPublicIPs = '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9'

function Test-PublicIPv4 {
    param([Parameter(Mandatory)][string]$Candidate)
    $parts = $Candidate.Split('.')
    if ($parts.Count -ne 4) { return $false }
    foreach ($p in $parts) {
        if ($p.Length -gt 1 -and $p.StartsWith('0')) { return $false }  # version strings like 1.07.3.4
        $n = 0
        if (-not [int]::TryParse($p, [ref]$n) -or $n -gt 255) { return $false }
    }
    $b = [int[]]$parts
    if ($b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -ge 224) { return $false }
    if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $false }
    if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }
    if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
    if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $false }
    # RFC 5737 documentation ranges
    if ($b[0] -eq 192 -and $b[1] -eq 0 -and $b[2] -eq 2) { return $false }
    if ($b[0] -eq 198 -and $b[1] -eq 51 -and $b[2] -eq 100) { return $false }
    if ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113) { return $false }
    if ($script:AllowedPublicIPs -contains $Candidate) { return $false }
    return $true
}

function Test-FullMac {
    param([Parameter(Mandatory)][string]$Candidate)
    $hex = ($Candidate -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($hex.Length -ne 12) { return $false }
    if ($hex -eq '000000000000' -or $hex -eq 'FFFFFFFFFFFF') { return $false }
    if ($hex.StartsWith('01005E') -or $hex.StartsWith('3333')) { return $false }  # multicast
    return $true
}

function Find-SensitiveContent {
    <# Returns findings for one block of text. Pure function, used by the tests. #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Source',
        Justification = 'Read inside the $add closure.')]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [string]$Source = '<text>',
        [string[]]$DenyTerms = @()
    )
    $findings = [System.Collections.Generic.List[object]]::new()
    $lines = $Text -split "`r?`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $add = { param($kind, $value)
            $findings.Add([pscustomobject]@{ File = $Source; Line = $i + 1; Kind = $kind; Value = $value }) }

        foreach ($m in [regex]::Matches($line, '(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])')) {
            if (Test-FullMac $m.Value) { & $add 'full-mac' $m.Value }
        }
        foreach ($m in [regex]::Matches($line, '(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')) {
            if (Test-PublicIPv4 $m.Value) { & $add 'public-ipv4' $m.Value }
        }
        foreach ($m in [regex]::Matches($line, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')) {
            if ($m.Value -notmatch '@users\.noreply\.github\.com$|@example\.(com|org|net)$|^noreply@') { & $add 'email' $m.Value }
        }
        foreach ($m in [regex]::Matches($line, 'S-1-5-21-\d+-\d+-\d+(-\d+)?')) { & $add 'windows-sid' $m.Value }
        foreach ($m in [regex]::Matches($line, '(?i)\b[A-Z]:\\Users\\(?!Public\b|<)[^\\\s"''<>]+|/Users/(?!Shared\b|<)[A-Za-z0-9._-]+|/home/(?!runner\b|<)[A-Za-z0-9._-]+')) {
            & $add 'home-path' $m.Value
        }
        foreach ($m in [regex]::Matches($line, '(?i)(authorization:\s*(bearer|basic)\s+\S{8,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|xox[baprs]-[A-Za-z0-9-]{10,})')) {
            & $add 'credential' $m.Value
        }
        foreach ($term in $DenyTerms) {
            if ($term -and $line.IndexOf($term, [StringComparison]::OrdinalIgnoreCase) -ge 0) { & $add 'denylist' $term }
        }
    }
    return $findings
}

function Get-OfficeText {
    <# Text inside .pptx/.docx (zip of XML). #>
    param([Parameter(Mandatory)][string]$File)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($File)
    try {
        $sb = [System.Text.StringBuilder]::new()
        foreach ($e in $zip.Entries | Where-Object { $_.FullName -match '^(ppt/(slides|notesSlides)/|word/document|docProps/).*\.xml$' }) {
            $r = [System.IO.StreamReader]::new($e.Open())
            try { [void]$sb.AppendLine(([regex]::Replace($r.ReadToEnd(), '<[^>]+>', ' '))) } finally { $r.Dispose() }
        }
        return $sb.ToString()
    } finally { $zip.Dispose() }
}

function Get-CandidateFile {
    param([string]$Root, [switch]$TrackedOnly)
    if ($TrackedOnly) {
        Push-Location $Root
        try { return @(git ls-files | ForEach-Object { Get-Item -LiteralPath (Join-Path $Root $_) -ErrorAction SilentlyContinue }) }
        finally { Pop-Location }
    }
    return @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force | Where-Object {
            $rel = $_.FullName.Substring($Root.Length).TrimStart('\', '/')
            -not ($script:SkipDirs | Where-Object { $rel -like "$_*" -or $rel -like "*[\/]$_[\/]*" })
        })
}

function Invoke-PublicArtifactScan {
    param([Parameter(Mandatory)][string]$Root, [switch]$TrackedOnly)
    $deny = @()
    $denyFile = Join-Path $Root '.privacy-denylist.txt'
    if (Test-Path $denyFile) { $deny = @(Get-Content $denyFile | Where-Object { $_ -and -not $_.StartsWith('#') } | ForEach-Object { $_.Trim() }) }

    $all = [System.Collections.Generic.List[object]]::new()
    foreach ($f in Get-CandidateFile -Root $Root -TrackedOnly:$TrackedOnly) {
        $rel = $f.FullName.Substring($Root.Length).TrimStart('\', '/') -replace '\\', '/'
        if ($rel -eq '.privacy-denylist.txt' -or $rel -like 'artifacts/private/*') { continue }
        $ext = $f.Extension.ToLowerInvariant()
        if ($script:CaptureExtensions -contains $ext) {
            $all.Add([pscustomobject]@{ File = $rel; Line = 0; Kind = 'packet-capture'; Value = $f.Name }); continue
        }
        $text = $null
        if ($script:TextExtensions -contains $ext -or $f.Name -in '.gitignore', '.gitattributes') { $text = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 }
        elseif ($ext -in '.pptx', '.docx') { $text = Get-OfficeText -File $f.FullName }
        if ($null -eq $text) { continue }
        $found = Find-SensitiveContent -Text $text -Source $rel -DenyTerms $deny
        # Test fixtures hold synthetic MACs, IPs and paths by design; only real identifiers count there.
        if ($rel -like 'tests/*') { $found = $found | Where-Object { $_.Kind -eq 'denylist' } }
        foreach ($x in $found) { $all.Add($x) }
    }
    return $all
}

if ($MyInvocation.InvocationName -ne '.') {
    if (-not $Path) { $Path = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) '..\..' }
    $root = (Resolve-Path $Path).Path
    $results = @(Invoke-PublicArtifactScan -Root $root -TrackedOnly:$TrackedOnly)
    if ($results.Count -eq 0) {
        Write-Output 'Privacy check passed: no sensitive patterns found.'
        exit 0
    }
    $results | Sort-Object File, Line | Format-Table File, Line, Kind, Value -AutoSize | Out-String -Width 220 | Write-Output
    Write-Output "Privacy check FAILED: $($results.Count) finding(s)."
    exit 1
}
