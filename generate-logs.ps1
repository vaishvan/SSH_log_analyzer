# SSH Log Generator - simulates real attacks
# creates realistic ssh logs with brute force patterns

param(
    [string]$outputFile = ".\ssh_logs.txt",
    [int]$delaySeconds = 3,
    [switch]$continuous
)

# attack scenarios  
$attackPatterns = @{
    "slow_bruteforce" = @{
        ips = @("203.0.113.45", "198.51.100.23") 
        users = @("admin", "root", "user")
        delay = 10
        burstSize = 3
    }
    "fast_attack" = @{
        ips = @("185.220.101.42")
        users = @("administrator", "guest", "test", "admin", "root", "user", "oracle", "postgres")
        delay = 1
        burstSize = 8
    }
    "distributed" = @{
        ips = @("94.142.241.111", "162.243.166.97", "45.79.19.196", "139.59.109.113")
        users = @("admin", "root") 
        delay = 5
        burstSize = 2
    }
}

$legitimateTraffic = @{
    ips = @("192.168.1.10", "192.168.1.20", "10.0.0.5")
    users = @("john.doe", "admin", "service_account")
}

function Write-LogEntry {
    param(
        [string]$logType,
        [string]$ipAddr, 
        [string]$username,
        [string]$outputPath
    )
    
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logLine = "$timestamp $logType $ipAddr user:$username"
    
    # append to log file
    Add-Content -Path $outputPath -Value $logLine
    
    # show on console
    $color = if ($logType -eq "SSH_FAIL") { "Red" } else { "Green" }
    Write-Host $logLine -ForegroundColor $color
}

function New-LegitimateTraffic {
    param([string]$logFile)
    
    if ((Get-Random -Minimum 1 -Maximum 10) -le 3) {  # 30% chance
        $ip = $legitimateTraffic.ips | Get-Random
        $user = $legitimateTraffic.users | Get-Random
        Write-LogEntry -logType "SSH_SUCCESS" -ipAddr $ip -username $user -outputPath $logFile
    }
}

function Invoke-AttackPattern {
    param(
        [hashtable]$pattern,
        [string]$logFile
    )
    
    $attackIP = $pattern.ips | Get-Random
    
    for ($i = 0; $i -lt $pattern.burstSize; $i++) {
        $targetUser = $pattern.users | Get-Random
        Write-LogEntry -logType "SSH_FAIL" -ipAddr $attackIP -username $targetUser -outputPath $logFile
        
        Start-Sleep -Seconds ([Math]::Max(1, $pattern.delay / $pattern.burstSize))
    }
}

# main simulation loop
Write-Host "SSH Log Generator Started" -ForegroundColor Yellow
Write-Host "Output file: $outputFile" -ForegroundColor Cyan
Write-Host "Delay between events: $delaySeconds seconds" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop`n" -ForegroundColor Yellow

# init log file
if (Test-Path $outputFile) {
    Write-Host "Appending to existing log file..." -ForegroundColor Green
} else {
    Write-Host "Creating new log file..." -ForegroundColor Green
    New-Item -Path $outputFile -ItemType File -Force | Out-Null
}

$iteration = 0

do {
    $iteration++
    
    # generate some legitimate traffic first
    New-LegitimateTraffic -logFile $outputFile
    
    # randomly trigger attack patterns
    if ($iteration % 5 -eq 0) {  # every 5th iteration
        $patternName = $attackPatterns.Keys | Get-Random
        $pattern = $attackPatterns[$patternName]
        
        Write-Host "`n[ATTACK SIMULATION] Starting $patternName attack..." -ForegroundColor Magenta
        Invoke-AttackPattern -pattern $pattern -logFile $outputFile
        Write-Host "[ATTACK SIMULATION] $patternName completed`n" -ForegroundColor Magenta
    }
    
    Start-Sleep -Seconds $delaySeconds
    
} while ($continuous -or $iteration -lt 50)  # run 50 iterations if not continuous

Write-Host "`nLog generation completed." -ForegroundColor Green
