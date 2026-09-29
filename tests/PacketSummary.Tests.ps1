BeforeAll {
    . "$PSScriptRoot/../tools/windows/Invoke-PacketSummary.ps1"
}

Describe 'Get-ArpBindingReport' {
    It 'reports a single binding per IP on a healthy segment' {
        $lines = @(
            "192.168.0.1`t3c:6a:d2:00:00:01",
            "192.168.0.1`t3c:6a:d2:00:00:01",
            "192.168.0.135`tcc:28:aa:00:00:02"
        )
        $r = @(Get-ArpBindingReport -Lines $lines)
        $r.Count | Should -Be 2
        ($r | Where-Object IP -eq '192.168.0.1').Frames | Should -Be 2
        $r.Conflict | Should -Not -Contain $true
    }

    It 'flags two MACs answering for the same gateway IP (the dual-router signature)' {
        $lines = @(
            "192.168.0.1`t3c:6a:d2:00:00:01",
            "192.168.0.1`t24:2f:d0:00:00:02"
        )
        $r = Get-ArpBindingReport -Lines $lines
        $r.DistinctMacs | Should -Be 2
        $r.Conflict | Should -BeTrue
        $r.MacOui | Should -Be '3C:6A:D2:XX:XX:XX, 24:2F:D0:XX:XX:XX'
    }

    It 'ignores RFC 5227 probes and malformed lines' {
        $r = @(Get-ArpBindingReport -Lines @("0.0.0.0`t90:09:d0:00:00:01", 'garbage', ''))
        $r.Count | Should -Be 0
    }

    It 'sorts addresses numerically, not alphabetically' {
        $r = Get-ArpBindingReport -Lines @("192.168.0.20`t00:25:11:00:00:01", "192.168.0.3`t00:25:11:00:00:02")
        $r[0].IP | Should -Be '192.168.0.3'
    }
}

Describe 'Get-StreamConcentration' {
    It 'computes the share of the worst stream' {
        $r = Get-StreamConcentration -StreamIds @('7', '7', '7', '2')
        $r.Total | Should -Be 4
        $r.Streams | Should -Be 2
        $r.TopStreamShare | Should -Be 0.75
    }
    It 'handles a capture with no retransmissions' {
        (Get-StreamConcentration -StreamIds @()).Total | Should -Be 0
    }
}

Describe 'ConvertTo-OuiMac' {
    It 'keeps the OUI' { ConvertTo-OuiMac '3c:6a:d2:00:00:01' | Should -Be '3C:6A:D2:XX:XX:XX' }
    It 'hides randomized MACs' { ConvertTo-OuiMac '6a:00:00:00:00:01' | Should -Be 'randomized' }
}
