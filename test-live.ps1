# ==============================================================================
# dpibypass -- Phase 2 Automated Live Test Runner
# Evaluates WinDivert Wire-Level Bypass Strategies against updates.discord.com
# ==============================================================================

param(
    [switch]$NoPause
)

# 1. Auto-Elevation Check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Administrative privileges required to capture packets via WinDivert." -ForegroundColor Yellow
    Write-Host "[*] Please open an Administrator PowerShell prompt and run:" -ForegroundColor Cyan
    Write-Host "    powershell -ExecutionPolicy Bypass -File .\test-live.ps1" -ForegroundColor Green
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"" -ErrorAction Stop
    } catch {
        # Headless/non-interactive subshells cannot trigger UAC
    }
    exit 1
}

# Ensure execution location is script directory
Set-Location -Path $PSScriptRoot

$reportPath = Join-Path $PSScriptRoot "live-test-report.txt"
$reportLines = [System.Collections.Generic.List[string]]::new()

function Log-Output {
    param(
        [string]$msg,
        [string]$color = "White"
    )
    Write-Host $msg -ForegroundColor $color
    $reportLines.Add($msg)
}

Log-Output "======================================================================" "Cyan"
Log-Output "         dpibypass -- Phase 2 Automated Live Test Runner                " "Cyan"
Log-Output "======================================================================" "Cyan"
Log-Output "Timestamp : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"
Log-Output "Targets   : updates.discord.com, discord.com, gateway.discord.gg, www.roblox.com"
Log-Output "Resolver  : Cloudflare DoH (https://cloudflare-dns.com/dns-query)"
Log-Output ""

# 2. Binary and Driver Check
Log-Output "[*] Verifying local binaries and driver signatures..." "Cyan"
if (-not (Test-Path ".\dpibypass.exe")) {
    Log-Output "[ERROR] dpibypass.exe not found! Please build it first with .\build.ps1." "Red"
    exit 1
}
if (-not (Test-Path ".\WinDivert.dll") -or -not (Test-Path ".\WinDivert64.sys")) {
    Log-Output "[ERROR] WinDivert.dll or WinDivert64.sys not found in project root!" "Red"
    exit 1
}

$sig = Get-AuthenticodeSignature .\WinDivert64.sys
if ($sig.Status -ne "Valid") {
    Log-Output "[ERROR] WinDivert64.sys Authenticode signature is $($sig.Status)! Refusing to run unsigned driver." "Red"
    exit 1
}
Log-Output "[OK] WinDivert64.sys driver signature is Valid." "Green"

# 3. Conflict Check
$conflicts = @()
if (Get-Process -Name "goodbyedpi" -ErrorAction SilentlyContinue) { $conflicts += "GoodbyeDPI (goodbyedpi.exe)" }
if (Get-Process -Name "zapret*" -ErrorAction SilentlyContinue) { $conflicts += "Zapret" }
if (Get-Process -Name "dpibypass" -ErrorAction SilentlyContinue) { $conflicts += "dpibypass (lingering instance)" }
$scQuery = (sc.exe query WinDivert 2>&1) | Out-String
if ($scQuery -match "RUNNING") { $conflicts += "WinDivert kernel service (state: RUNNING)" }

if ($conflicts.Count -gt 0) {
    Log-Output "[WARNING] Potential conflicting processes/services detected:" "Yellow"
    foreach ($c in $conflicts) { Log-Output "  - $c" "Yellow" }
    Log-Output "Stopping lingering dpibypass/WinDivert instances..." "Yellow"
    Get-Process -Name "dpibypass" -ErrorAction SilentlyContinue | Stop-Process -Force
    sc.exe stop WinDivert 2>$null | Out-Null
    Start-Sleep -Seconds 1
}

# 4. Baseline Test (No Bypass Running)
Log-Output "`n======================================================================" "Cyan"
Log-Output "Step 1: Baseline Connectivity Test (No Bypass Engine Running)" "Cyan"
Log-Output "======================================================================" "Cyan"
Log-Output "[*] Probing https://updates.discord.com with curl (5s timeout, standard system DNS)..."

$baselineOutput = & curl.exe -sS -I --max-time 5 https://updates.discord.com 2>&1
$baselineExitCode = $LASTEXITCODE

$baselineStatus = "UNKNOWN"
if ($baselineExitCode -eq 0 -and ($baselineOutput | Out-String) -match "HTTP/\d") {
    $firstLine = ($baselineOutput | Select-String "HTTP/" | Select-Object -First 1).Line.Trim()
    $baselineStatus = "ACCESSIBLE ($firstLine)"
    Log-Output "[*] Baseline Result: Target is ACCESSIBLE directly without bypass ($firstLine)" "Yellow"
    Log-Output "    (Note: If your ISP already allows updates.discord.com, bypass cannot be distinguished from baseline.)" "Yellow"
} else {
    $baselineStatus = "BLOCKED / TIMEOUT (ExitCode: $baselineExitCode)"
    Log-Output "[*] Baseline Result: Target is BLOCKED by ISP / Timed out (ExitCode: $baselineExitCode)" "Red"
}
& ipconfig.exe /flushdns 2>&1 | Out-Null

# 5. Automated Strategy Matrix
$testConfigPath = if (Test-Path "examples\config.phase2-test.json") { "examples\config.phase2-test.json" } elseif (Test-Path "config.phase2-test.json") { "config.phase2-test.json" } else { "config.json" }
$profiles = @(
    @{
        ID = 1
        Name = "Split + Bad Checksum"
        Args = @("run", "--mode", "packet", "--config", $testConfigPath, "--fake-mode", "wrong-chksum", "--split-offset", "sni-mid", "--intercept-dns", "--no-autolearn", "--duration-s", "20")
        Desc = "Out-of-Order Segment 2 first + Fake ClientHello with corrupted RFC 793 TCP Checksum"
    },
    @{
        ID = 2
        Name = "Split + TTL 5"
        Args = @("run", "--mode", "packet", "--config", $testConfigPath, "--fake-mode", "ttl", "--fake-ttl", "5", "--split-offset", "sni-mid", "--intercept-dns", "--no-autolearn", "--duration-s", "20")
        Desc = "Out-of-Order Segment 2 first + Low-TTL (5 hops) dummy ClientHello"
    },
    @{
        ID = 3
        Name = "Split + TTL 4"
        Args = @("run", "--mode", "packet", "--config", $testConfigPath, "--fake-mode", "ttl", "--fake-ttl", "4", "--split-offset", "sni-mid", "--intercept-dns", "--no-autolearn", "--duration-s", "20")
        Desc = "Out-of-Order Segment 2 first + Low-TTL (4 hops) dummy ClientHello (sweet spot)"
    },
    @{
        ID = 4
        Name = "Split + TTL 6"
        Args = @("run", "--mode", "packet", "--config", $testConfigPath, "--fake-mode", "ttl", "--fake-ttl", "6", "--split-offset", "sni-mid", "--intercept-dns", "--no-autolearn", "--duration-s", "20")
        Desc = "Out-of-Order Segment 2 first + Low-TTL (6 hops) dummy ClientHello"
    },
    @{
        ID = 5
        Name = "Combined (TTL 5 + BadChecksum + 2ms Delay)"
        Args = @("run", "--mode", "packet", "--config", $testConfigPath, "--fake-mode", "both", "--fake-ttl", "5", "--split-offset", "sni-mid", "--delay-ms", "2", "--intercept-dns", "--no-autolearn", "--duration-s", "20")
        Desc = "Low-TTL 5 + Bad Checksum + 2ms inter-packet delay before Segment 1"
    },
    @{
        ID = 6
        Name = "Pure Out-of-Order Split (No Fake)"
        Args = @("run", "--mode", "packet", "--config", $testConfigPath, "--fake-mode", "none", "--split-offset", "sni-mid", "--intercept-dns", "--no-autolearn", "--duration-s", "20")
        Desc = "Pure wire-level fragmentation emitting Segment 2 before Segment 1 (no fake injection)"
    },
    @{
        ID = 7
        Name = "Split + TTL 3"
        Args = @("run", "--mode", "packet", "--config", $testConfigPath, "--fake-mode", "ttl", "--fake-ttl", "3", "--split-offset", "sni-mid", "--intercept-dns", "--no-autolearn", "--duration-s", "20")
        Desc = "Out-of-Order Segment 2 first + Low-TTL (3 hops) dummy ClientHello (ultra-close middlebox)"
    },
    @{
        ID = 8
        Name = "Split + Multi-TTL (4+3)"
        Args = @("run", "--mode", "packet", "--config", $testConfigPath, "--fake-mode", "multi-ttl", "--fake-ttl", "4", "--split-offset", "sni-mid", "--intercept-dns", "--no-autolearn", "--duration-s", "20")
        Desc = "Out-of-Order Segment 2 first + Multi-hop (4 and 3 hops) dummy ClientHello to defeat ECMP shifts"
    }
)

Log-Output "`n======================================================================" "Cyan"
Log-Output "Step 2: Automated Phase 2 Strategy Matrix Evaluation" "Cyan"
Log-Output "======================================================================" "Cyan"

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($prof in $profiles) {
    Log-Output "`n----------------------------------------------------------------------"
    Log-Output "[Profile $($prof.ID)] $($prof.Name)" "Cyan"
    Log-Output "  Description : $($prof.Desc)"
    Log-Output "  Command     : dpibypass.exe $($prof.Args -join ' ')"

    # Flush Windows DNS cache before profile execution
    & ipconfig.exe /flushdns 2>&1 | Out-Null

    $logFile = Join-Path $env:TEMP "dpibypass_prof_$($prof.ID).log"
    if (Test-Path $logFile) { Remove-Item $logFile -Force }

    $stopFile = Join-Path $env:TEMP "dpibypass_prof_$($prof.ID).stop"
    if (Test-Path $stopFile) { Remove-Item $stopFile -Force -ErrorAction SilentlyContinue }

    $cmdArgs = $prof.Args + @("--stop-file", $stopFile)

    # Start dpibypass with redirected output
    $proc = Start-Process -FilePath ".\dpibypass.exe" -ArgumentList $cmdArgs -PassThru -NoNewWindow -RedirectStandardOutput $logFile -RedirectStandardError (Join-Path $env:TEMP "dpibypass_prof_$($prof.ID)_err.log")

    # Give WinDivert handle time to open and enter active packet processing loop
    $engineReady = $false
    for ($i = 0; $i -lt 30; $i++) {
        if ($proc.HasExited) {
            break
        }
        Start-Sleep -Milliseconds 100
        if (Test-Path $logFile) {
            $logContent = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
            if ($logContent -match "packet engine running") {
                $engineReady = $true
                break
            }
        }
    }
    if (-not $engineReady) {
        Start-Sleep -Milliseconds 1000
    }
    Start-Sleep -Milliseconds 200

    # Probe targets: force IPv4 UDP 53 via Resolve-DnsName and IPv4 TCP for curl
    Log-Output "  [*] Resolving updates.discord.com with Resolve-DnsName (forcing IPv4 8.8.8.8)..."
    $dnsError = $null
    $dnsIPs = @()
    try {
        $dnsRes = Resolve-DnsName -Name updates.discord.com -Server 8.8.8.8 -Type A -DnsOnly -ErrorAction Stop
        if ($dnsRes) {
            $dnsIPs = @($dnsRes | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress })
        }
    } catch {
        $dnsError = $_.Exception.Message
    }

    Log-Output "  [*] Probing https://updates.discord.com with curl -4 (6s timeout)..."
    $probeOutput = & curl.exe -4 -sS -I --max-time 6 https://updates.discord.com 2>&1
    $curlExit = $LASTEXITCODE

    Log-Output "  [*] Probing https://discord.com with curl -4 (6s timeout)..."
    $discordComOutput = & curl.exe -4 -sS -I --max-time 6 https://discord.com 2>&1
    $discordComExit = $LASTEXITCODE

    Log-Output "  [*] Probing https://gateway.discord.gg with curl -4 (6s timeout)..."
    $gatewayOutput = & curl.exe -4 -sS -I --max-time 6 https://gateway.discord.gg 2>&1
    $gatewayExit = $LASTEXITCODE

    Log-Output "  [*] Probing https://www.roblox.com with curl -4 (6s timeout)..."
    $robloxOutput = & curl.exe -4 -sS -I --max-time 6 https://www.roblox.com 2>&1
    $robloxExit = $LASTEXITCODE

    # Explicitly stop dpibypass now that all probes have completed via graceful stop-file signal
    New-Item -Path $stopFile -ItemType File -Force | Out-Null
    if (-not $proc.HasExited) {
        $proc.WaitForExit(3000) | Out-Null
    }
    if (-not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        $proc.WaitForExit(1000) | Out-Null
    }
    if (Test-Path $stopFile) { Remove-Item $stopFile -Force -ErrorAction SilentlyContinue }

    # Parse HarnessStats from engine log
    $packetsRecv = 0
    $packetsSent = 0
    $fakeSent = 0
    $segmentsSplit = 0
    $dnsIntercepted = 0
    $dnsResolved = 0
    $dnsFallbacks = 0
    $retransmissions = 0
    $escalations = 0
    $domainsLearned = 0
    if (Test-Path $logFile) {
        $engineLog = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
        if ($engineLog -match "Total Packets Intercepted\s*:\s*(\d+)") { $packetsRecv = [int]$matches[1] }
        if ($engineLog -match "Total Packets Transmitted\s*:\s*(\d+)") { $packetsSent = [int]$matches[1] }
        if ($engineLog -match "Synthetic Fake Packets Sent\s*:\s*(\d+)") { $fakeSent = [int]$matches[1] }
        if ($engineLog -match "Out-of-Order Segments Split\s*:\s*(\d+)") { $segmentsSplit = [int]$matches[1] }
        if ($engineLog -match "DNS UDP/53 Intercepted\s*:\s*(\d+)\s*\(DoH Resolved:\s*(\d+),\s*Fallbacks:\s*(\d+)\)") {
            $dnsIntercepted = [int]$matches[1]
            $dnsResolved = [int]$matches[2]
            $dnsFallbacks = [int]$matches[3]
        }
        if ($engineLog -match "Retransmissions Detected\s*:\s*(\d+)") { $retransmissions = [int]$matches[1] }
        if ($engineLog -match "Strategy Escalations\s*:\s*(\d+)") { $escalations = [int]$matches[1] }
        if ($engineLog -match "Domains Auto-Learned\s*:\s*(\d+)") { $domainsLearned = [int]$matches[1] }
    }

    # Inspect curl outcomes
    $updatesPass = $false
    $updatesStatus = ""
    $respText = ($probeOutput | Out-String).Trim()
    if ($curlExit -eq 0 -and $respText -match "HTTP/\d") {
        $match = [regex]::Match($respText, "HTTP/\S+\s+(\d+)")
        if ($match.Success) {
            $updatesStatus = $match.Groups[1].Value
        }
        $updatesPass = $true
        Log-Output "  [+] updates.discord.com: PASS (HTTP $updatesStatus)" "Green"
    } else {
        Log-Output "  [-] updates.discord.com: FAIL (Curl ExitCode: $curlExit)" "Red"
    }

    $discordComPass = $false
    $discordComStatus = ""
    $respTextDiscord = ($discordComOutput | Out-String).Trim()
    if ($discordComExit -eq 0 -and $respTextDiscord -match "HTTP/\d") {
        $match = [regex]::Match($respTextDiscord, "HTTP/\S+\s+(\d+)")
        if ($match.Success) {
            $discordComStatus = $match.Groups[1].Value
        }
        $discordComPass = $true
        Log-Output "  [+] discord.com: PASS (HTTP $discordComStatus)" "Green"
    } else {
        Log-Output "  [-] discord.com: FAIL (Curl ExitCode: $discordComExit)" "Red"
    }

    $gatewayPass = $false
    $gatewayStatus = ""
    $respTextGateway = ($gatewayOutput | Out-String).Trim()
    if ($gatewayExit -eq 0 -and $respTextGateway -match "HTTP/\d") {
        $match = [regex]::Match($respTextGateway, "HTTP/\S+\s+(\d+)")
        if ($match.Success) {
            $gatewayStatus = $match.Groups[1].Value
        }
        $gatewayPass = $true
        Log-Output "  [+] gateway.discord.gg: PASS (HTTP $gatewayStatus)" "Green"
    } else {
        Log-Output "  [-] gateway.discord.gg: FAIL (Curl ExitCode: $gatewayExit)" "Red"
    }

    $robloxPass = $false
    $robloxStatus = ""
    $robloxText = ($robloxOutput | Out-String).Trim()
    if ($robloxExit -eq 0 -and $robloxText -match "HTTP/\d") {
        $match = [regex]::Match($robloxText, "HTTP/\S+\s+(\d+)")
        if ($match.Success) {
            $robloxStatus = $match.Groups[1].Value
        }
        $robloxPass = $true
        Log-Output "  [+] www.roblox.com: PASS (HTTP $robloxStatus)" "Green"
    } else {
        Log-Output "  [-] www.roblox.com: FAIL (Curl ExitCode: $robloxExit)" "Red"
    }

    $totalProbes = 4
    $passedCount = [int]$updatesPass + [int]$discordComPass + [int]$gatewayPass + [int]$robloxPass
    $outcome = "FAIL"
    if ($passedCount -eq $totalProbes) {
        $outcome = "PASS"
    } elseif ($passedCount -gt 0) {
        $outcome = "PARTIAL"
    }

    # Rigorous DNS outcome validation:
    $sinkholed = ($dnsIPs -contains "195.175.254.2") -or (@($dnsIPs | Where-Object { $_ -match "195\.175\.254\.2" }).Count -gt 0)
    $nslookupStatus = "UNKNOWN"

    if ($sinkholed) {
        $nslookupStatus = "SINKHOLED"
        Log-Output "  [-] DNS: SINKHOLED (returned Turk Telekom 195.175.254.2)!" "Red"
    } elseif ($dnsIPs.Count -gt 0) {
        $nslookupStatus = "CLEAN"
        Log-Output "  [+] DNS: CLEAN (resolved via transparent DoH bridge: $($dnsIPs -join ', '), Intercepted: $dnsIntercepted)" "Green"
    } elseif ($dnsIntercepted -gt 0 -and $dnsResolved -gt 0) {
        $nslookupStatus = "CLEAN"
        Log-Output "  [+] DNS: CLEAN (resolved via transparent DoH bridge, Intercepted: $dnsIntercepted)" "Green"
    } elseif ($dnsError) {
        $nslookupStatus = "TIMEOUT"
        Log-Output "  [-] DNS: TIMED OUT ($dnsError)!" "Red"
    } elseif ($dnsIntercepted -eq 0 -or $dnsResolved -eq 0) {
        $nslookupStatus = "UNINTERCEPTED"
        Log-Output "  [-] DNS: UNINTERCEPTED (DNS Intercepted: $dnsIntercepted, DoH: $dnsResolved)!" "Yellow"
    } else {
        $nslookupStatus = "CLEAN"
        Log-Output "  [+] DNS: CLEAN (legitimate IP resolved via transparent DoH bridge)" "Green"
    }

    Log-Output "  [Engine Metrics] Intercepted: $packetsRecv | Transmitted: $packetsSent | Fake Packets: $fakeSent | Split Segments: $segmentsSplit | DNS Intercepted: $dnsIntercepted (DoH: $dnsResolved, Fallbacks: $dnsFallbacks) | AutoLearn: Retrans: $retransmissions, Esc: $escalations, Learned: $domainsLearned" "DarkGray"

    $results.Add([PSCustomObject]@{
        ProfileID      = $prof.ID
        Name           = $prof.Name
        Outcome        = $outcome
        UpdatesStatus  = $updatesStatus
        DiscordStatus  = $discordComStatus
        GatewayStatus  = $gatewayStatus
        RobloxStatus   = $robloxStatus
        NSLookup       = $nslookupStatus
        Intercepted    = $packetsRecv
        FakePackets    = $fakeSent
        SplitSegments  = $segmentsSplit
        DNSIntercepted = $dnsIntercepted
        DNSResolved    = $dnsResolved
        Retrans        = $retransmissions
        Escalations    = $escalations
        Learned        = $domainsLearned
    })

    # Brief pause between test profiles
    Start-Sleep -Seconds 1
}

# 6. Post-Test Safety Cleanup & Status
Log-Output "`n======================================================================" "Cyan"
Log-Output "Step 3: Cleanup & Final Verification" "Cyan"
Log-Output "======================================================================" "Cyan"

$recoveryOutput = & .\dpibypass.exe recover --status 2>&1
Log-Output ($recoveryOutput | Out-String).Trim()

# 7. Final Summary Table
Log-Output "`n======================================================================" "Cyan"
Log-Output "                      LIVE TEST SUMMARY REPORT                        " "Cyan"
Log-Output "======================================================================" "Cyan"
Log-Output "Baseline (No Bypass) : $baselineStatus`n"

$formatTable = $results | Format-Table -Property @(
    @{Label="ID"; Expression={$_.ProfileID}; Width=4},
    @{Label="Strategy Name"; Expression={$_.Name}; Width=22},
    @{Label="Outcome"; Expression={$_.Outcome}; Width=8},
    @{Label="Updates"; Expression={$_.UpdatesStatus}; Width=8},
    @{Label="Discord"; Expression={$_.DiscordStatus}; Width=8},
    @{Label="Gateway"; Expression={$_.GatewayStatus}; Width=8},
    @{Label="Roblox"; Expression={$_.RobloxStatus}; Width=8},
    @{Label="NSLookup"; Expression={$_.NSLookup}; Width=10},
    @{Label="DNS Intercept"; Expression={"$($_.DNSIntercepted) ($($_.DNSResolved))"}; Width=14},
    @{Label="Fake"; Expression={$_.FakePackets}; Width=5},
    @{Label="Split"; Expression={$_.SplitSegments}; Width=6}
) | Out-String

Log-Output $formatTable

$passMatches = @($results | Where-Object { $_.Outcome -eq "PASS" })
$passCount = $passMatches.Count
if ($passCount -gt 0) {
    Log-Output "[SUCCESS] $passCount / $($results.Count) strategies successfully bypassed ISP DPI filtering!" "Green"
    # Rank passing strategies by reliability: lowest fake/split packet overhead (0 retransmissions)
    $sortedPass = @($passMatches | Sort-Object -Property @{Expression = { [int]$_.FakePackets + [int]$_.SplitSegments }; Ascending = $true})
    $best = $sortedPass[0]
    Log-Output "[RECOMMENDATION] Use Profile $($best.ProfileID) ($($best.Name)) for your production configuration." "Green"
} else {
    $partialMatches = @($results | Where-Object { $_.Outcome -eq "PARTIAL" })
    $partialCount = $partialMatches.Count
    if ($partialCount -gt 0) {
        Log-Output "[PARTIAL] $partialCount / $($results.Count) strategies partially bypassed ISP DPI filtering." "Yellow"
        $best = $partialMatches[0]
        Log-Output "[RECOMMENDATION] Consider Profile $($best.ProfileID) ($($best.Name)) with further hop tuning." "Yellow"
    } else {
        Log-Output "[OBSERVATION] None of the tested Phase 2 profiles received an HTTP response." "Yellow"
        Log-Output "Possible causes: IP-level blackholing, RST packet injection from edge routers, or intermediate firewall." "Yellow"
    }
}

# Write complete report to disk
$reportLines | Out-File -FilePath $reportPath -Encoding ascii -Force
Write-Host "`n[Report Saved] Full detailed output written to: $reportPath" -ForegroundColor Cyan

if (-not $NoPause) {
    Write-Host ""
    Read-Host "Test complete. Press Enter to exit"
}
