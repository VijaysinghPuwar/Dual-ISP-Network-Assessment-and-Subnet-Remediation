BeforeAll {
    . "$PSScriptRoot/../tools/privacy/Test-PublicArtifacts.ps1"
}

Describe 'Test-PublicIPv4' {
    It 'flags <Ip> as <Expected>' -ForEach @(
        @{ Ip = '93.184.216.34'; Expected = $true }
        @{ Ip = '192.168.0.1'; Expected = $false }
        @{ Ip = '10.0.0.1'; Expected = $false }
        @{ Ip = '172.20.1.1'; Expected = $false }
        @{ Ip = '224.0.0.251'; Expected = $false }
        @{ Ip = '255.255.255.255'; Expected = $false }
        @{ Ip = '203.0.113.5'; Expected = $false }
        @{ Ip = '1.1.1.1'; Expected = $false }
        @{ Ip = '1.455.353.0'; Expected = $false }
        @{ Ip = '10.07.1.1'; Expected = $false }
    ) {
        Test-PublicIPv4 -Candidate $Ip | Should -Be $Expected
    }
}

Describe 'Find-SensitiveContent' {
    It 'returns nothing for sanitized text' {
        $clean = @'
Router A 192.168.0.1 at 3C:6A:D2:XX:XX:XX
NAS-01 LAN 2 moved to 192.168.20.2
Randomized client XX:XX:XX:XX:XX:XX (randomized)
Broadcast ff:ff:ff:ff:ff:ff, MAC redacted as ██:██:██:██:██:██
Commit author 123+someone@users.noreply.github.com
'@
        Find-SensitiveContent -Text $clean | Should -BeNullOrEmpty
    }

    It 'detects a full MAC address' {
        (Find-SensitiveContent -Text 'gw 3c:6a:d2:00:00:01').Kind | Should -Contain 'full-mac'
    }

    It 'detects a public IPv4 address and reports its line' {
        $r = Find-SensitiveContent -Text "line one`nWAN is 93.184.216.34" -Source 'x.md'
        $r.Kind | Should -Be 'public-ipv4'
        $r.Line | Should -Be 2
        $r.File | Should -Be 'x.md'
    }

    It 'detects an email address but not a GitHub noreply address' {
        @(Find-SensitiveContent -Text 'contact me at someone@example.net').Count | Should -Be 0
        (Find-SensitiveContent -Text 'contact me at person@gmail.com').Kind | Should -Contain 'email'
    }

    It 'detects a Windows SID' {
        (Find-SensitiveContent -Text 'S-1-5-21-1111111111-2222222222-333333333-1001').Kind | Should -Contain 'windows-sid'
    }

    It 'detects home directories but not placeholders' {
        (Find-SensitiveContent -Text 'C:\Users\alice\Desktop').Kind | Should -Contain 'home-path'
        (Find-SensitiveContent -Text '/Users/bob/Library').Kind | Should -Contain 'home-path'
        Find-SensitiveContent -Text 'C:\Users\<user>\Desktop and /Users/Shared' | Should -BeNullOrEmpty
    }

    It 'detects credential-looking strings' {
        (Find-SensitiveContent -Text 'Authorization: Bearer abcdefghijklmnop').Kind | Should -Contain 'credential'
        (Find-SensitiveContent -Text ('token ghp_' + ('a' * 36))).Kind | Should -Contain 'credential'
    }

    It 'applies the denylist case-insensitively' {
        (Find-SensitiveContent -Text 'host LAB-PC-7 online' -DenyTerms 'lab-pc-7').Kind | Should -Contain 'denylist'
    }
}

Describe 'Invoke-PublicArtifactScan' {
    BeforeEach {
        $root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $root | Out-Null
    }
    AfterEach { Remove-Item -Recurse -Force $root }

    It 'passes a clean tree' {
        Set-Content -Path (Join-Path $root 'README.md') -Value 'Gateway 192.168.0.1'
        Invoke-PublicArtifactScan -Root $root | Should -BeNullOrEmpty
    }

    It 'flags packet captures by extension' {
        Set-Content -Path (Join-Path $root 'capture.pcapng') -Value 'x'
        (Invoke-PublicArtifactScan -Root $root).Kind | Should -Contain 'packet-capture'
    }

    It 'ignores artifacts/private and reads the local denylist' {
        New-Item -ItemType Directory -Path (Join-Path $root 'artifacts/private') | Out-Null
        Set-Content -Path (Join-Path $root 'artifacts/private/raw.txt') -Value 'LAB-PC-7 93.184.216.34'
        Set-Content -Path (Join-Path $root 'notes.md') -Value 'seen on LAB-PC-7'
        Set-Content -Path (Join-Path $root '.privacy-denylist.txt') -Value "# local`nLAB-PC-7"
        $r = Invoke-PublicArtifactScan -Root $root
        @($r).Count | Should -Be 1
        $r.File | Should -Be 'notes.md'
    }
}
