BeforeAll {
    . "$PSScriptRoot/../tools/windows/Get-NetworkBaseline.ps1"
}

Describe 'Test-IsPrivateIPv4' {
    It 'classifies <Address> as <Expected>' -ForEach @(
        @{ Address = '192.168.0.135'; Expected = $true }
        @{ Address = '10.20.30.40'; Expected = $true }
        @{ Address = '172.16.0.1'; Expected = $true }
        @{ Address = '172.31.255.255'; Expected = $true }
        @{ Address = '172.32.0.1'; Expected = $false }
        @{ Address = '169.254.10.1'; Expected = $true }
        @{ Address = '100.64.0.1'; Expected = $true }
        @{ Address = '8.8.8.8'; Expected = $false }
        @{ Address = '203.0.113.9'; Expected = $false }
        @{ Address = 'not-an-ip'; Expected = $false }
        @{ Address = 'fe80::1'; Expected = $false }
    ) {
        Test-IsPrivateIPv4 -Address $Address | Should -Be $Expected
    }
}

Describe 'Get-IPv4NetworkAddress' {
    It 'derives <Expected> from <Address>/<Prefix>' -ForEach @(
        @{ Address = '192.168.0.135'; Prefix = 24; Expected = '192.168.0.0/24' }
        @{ Address = '192.168.20.2'; Prefix = 24; Expected = '192.168.20.0/24' }
        @{ Address = '10.1.2.3'; Prefix = 8; Expected = '10.0.0.0/8' }
        @{ Address = '172.16.5.4'; Prefix = 12; Expected = '172.16.0.0/12' }
        @{ Address = '192.168.1.77'; Prefix = 30; Expected = '192.168.1.76/30' }
        @{ Address = '192.168.1.77'; Prefix = 32; Expected = '192.168.1.77/32' }
        @{ Address = '192.168.1.77'; Prefix = 0; Expected = '0.0.0.0/0' }
    ) {
        Get-IPv4NetworkAddress -Address $Address -PrefixLength $Prefix | Should -Be $Expected
    }

    It 'shows that the two original LANs were the same prefix' {
        Get-IPv4NetworkAddress '192.168.0.135' 24 | Should -Be (Get-IPv4NetworkAddress '192.168.0.8' 24)
    }

    It 'shows that the remediated LANs are disjoint' {
        Get-IPv4NetworkAddress '192.168.0.135' 24 | Should -Not -Be (Get-IPv4NetworkAddress '192.168.20.2' 24)
    }

    It 'rejects an out-of-range prefix' {
        { Get-IPv4NetworkAddress -Address '192.168.0.1' -PrefixLength 33 } | Should -Throw
    }

    It 'rejects IPv6 input' {
        { Get-IPv4NetworkAddress -Address 'fe80::1' -PrefixLength 64 } | Should -Throw
    }
}

Describe 'ConvertTo-MaskedMac' {
    It 'keeps only the OUI of a globally administered MAC' {
        ConvertTo-MaskedMac -Mac '00-25-11-12-34-56' | Should -Be '00:25:11:XX:XX:XX'
    }
    It 'accepts colon separators and lower case' {
        ConvertTo-MaskedMac -Mac 'a8:5e:45:01:02:03' | Should -Be 'A8:5E:45:XX:XX:XX'
    }
    It 'fully masks a locally administered (randomized) MAC' {
        ConvertTo-MaskedMac -Mac '6A:00:00:00:00:01' | Should -Be 'XX:XX:XX:XX:XX:XX (randomized)'
    }
    It 'leaves the broadcast MAC readable' {
        ConvertTo-MaskedMac -Mac 'FF-FF-FF-FF-FF-FF' | Should -Be 'FF:FF:FF:FF:FF:FF'
    }
    It 'returns malformed input unchanged' {
        ConvertTo-MaskedMac -Mac 'not-a-mac' | Should -Be 'not-a-mac'
    }
    It 'handles an empty string' {
        ConvertTo-MaskedMac -Mac '' | Should -Be ''
    }
}

Describe 'Test-IsLocallyAdministeredMac' {
    It 'detects the U/L bit' {
        Test-IsLocallyAdministeredMac -Mac '02:00:00:00:00:01' | Should -BeTrue
        Test-IsLocallyAdministeredMac -Mac '00:25:11:00:00:01' | Should -BeFalse
    }
}

Describe 'Protect-Text' {
    It 'masks MACs, drops public IPs and keeps private ones' {
        $in = 'gw 192.168.0.1 at A8-5E-45-01-02-03, peer 93.184.216.34, dns 8.8.8.8'
        $out = Protect-Text -Text $in
        $out | Should -Match '192\.168\.0\.1'
        $out | Should -Match 'A8:5E:45:XX:XX:XX'
        $out | Should -Not -Match '93\.184\.216\.34'
        $out | Should -Not -Match '8\.8\.8\.8'
        $out | Should -Match '<public-ip>'
    }
    It 'keeps multicast and broadcast addresses' {
        Protect-Text -Text 'mdns 224.0.0.251 bcast 255.255.255.255' | Should -Be 'mdns 224.0.0.251 bcast 255.255.255.255'
    }
    It 'removes Windows and macOS home paths' {
        $out = Protect-Text -Text 'C:\Users\alice\Desktop\x.log and /Users/bob/Desktop/y.log'
        $out | Should -Not -Match 'alice'
        $out | Should -Not -Match 'bob'
        ([regex]::Matches($out, '<HOME>')).Count | Should -Be 2
    }
    It 'redacts supplied host and user names' {
        Protect-Text -Text 'Computer: LAB-PC-7, user lab7' -SensitiveNames 'LAB-PC-7', 'lab7' |
            Should -Be 'Computer: <redacted>, user <redacted>'
    }
    It 'ignores empty sensitive names' {
        Protect-Text -Text 'unchanged' -SensitiveNames @('', $null) | Should -Be 'unchanged'
    }
}

Describe 'ConvertTo-PublicBaseline' {
    BeforeAll {
        $raw = [pscustomobject]@{
            CollectedAt = '2026-09-28T09:00:00+05:30'
            ComputerName = 'LAB-PC-7'
            UserName = 'lab7'
            OS = 'Windows'
            Interfaces = @([pscustomobject]@{
                    Interface = 'Ethernet'; MacAddress = 'A8-5E-45-01-02-03'; IPv4Address = '192.168.0.50'
                    GatewayMac = '3C-6A-D2-AA-BB-CC'; DefaultGateway = '192.168.0.1'
                })
            ListeningTcpPorts = @(135, 445, 5040)
            Connectivity = @([pscustomobject]@{ Check = 'x'; Target = '93.184.216.34'; Result = $true })
            Note = 'log at C:\Users\lab7\Desktop'
        }
        $public = ConvertTo-PublicBaseline -Baseline $raw -AssetName 'WIN-CLIENT-09'
        $json = $public | ConvertTo-Json -Depth 6
    }
    It 'renames the host and hides the user' {
        $public.ComputerName | Should -Be 'WIN-CLIENT-09'
        $public.UserName | Should -Be '<redacted>'
    }
    It 'contains no raw identifiers' {
        $json | Should -Not -Match 'LAB-PC-7'
        $json | Should -Not -Match 'lab7'
        $json | Should -Not -Match '93\.184\.216\.34'
        $json | Should -Not -Match '01[:-]02[:-]03'
        $json | Should -Not -Match 'AA[:-]BB[:-]CC'
    }
    It 'publishes only the listener count' {
        $public.ListeningTcpPorts | Should -Be @('3 listening ports (list kept private)')
    }
    It 'does not modify the raw object' {
        $raw.ComputerName | Should -Be 'LAB-PC-7'
    }
}

Describe 'ConvertTo-BaselineMarkdown' {
    It 'renders an interface table and connectivity results' {
        $b = [pscustomobject]@{
            ComputerName = 'WIN-CLIENT-09'; CollectedAt = 'now'; OS = 'Windows'
            Interfaces = @([pscustomobject]@{ Interface = 'Ethernet'; IPv4Address = '192.168.0.50'; PrefixLength = 24
                    Network = '192.168.0.0/24'; DefaultGateway = '192.168.0.1'; GatewayMac = '3C:6A:D2:XX:XX:XX'
                    DnsServers = @('192.168.0.1'); Dhcp = 'Enabled'; RxErrors = 0; RxDiscards = 0; TxErrors = 0; TxDiscards = 0 })
            DefaultRouteCount = 1; DuplicateNeighborIPs = @(); Routes = @(); NeighborSummary = @()
            TcpStates = @([pscustomobject]@{ State = 'Established'; Count = 3 }); ListeningTcpPorts = @('3 listening ports')
            Connectivity = @([pscustomobject]@{ Check = 'Gateway echo'; Target = '192.168.0.1'; Result = $false })
        }
        $md = ConvertTo-BaselineMarkdown -Baseline $b
        $md | Should -Match '\| Ethernet \| 192\.168\.0\.50/24 \| 192\.168\.0\.0/24 \|'
        $md | Should -Match 'Duplicate IPs in neighbor cache: none'
        $md | Should -Match '\| Gateway echo \| 192\.168\.0\.1 \| FAIL \|'
    }
}
