# Simple SIEM Dashboard - shows current threats
# displays real-time security stats

param(
    [string]$logFile = ".\ssh_logs.txt",
    [string]$alertFile = ".\alerts.log"
)

# dashboard refresh rate
$refreshSeconds = 10

function Get-AttackStatistics {
    param([string]$logPath)
    
    if (-not (Test-Path $logPath)) {
        return @{
            totalAttempts = 0
            uniqueIPs = 0
            topAttackers = @()
            recentAlerts = @()
        }
    }
    
    # parse recent log entries (last 1000 lines)
    $recentLogs = Get-Content $logPath -Tail 1000 | Where-Object { $_ -match "SSH_FAIL" }
    
    $ipCounts = @{}
    $recentAttempts = @()
    
    foreach ($logLine in $recentLogs) {
        if ($logLine -match "(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*SSH_FAIL.*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*user:(\w+)") {
            $timestamp = [datetime]::Parse($matches[1])
            $ip = $matches[2]
            $user = $matches[3]
            
            # only count recent attempts (last hour)
            if ($timestamp -gt (Get-Date).AddHours(-1)) {
                if (-not $ipCounts.ContainsKey($ip)) {
                    $ipCounts[$ip] = 0
                }
                $ipCounts[$ip]++
                
                $recentAttempts += @{
                    Time = $timestamp
                    IP = $ip
                    User = $user
                }
            }
        }
    }
    
    # get top attackers
    $topAttackers = $ipCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5
    
    return @{
        totalAttempts = $recentAttempts.Count
        uniqueIPs = $ipCounts.Count
        topAttackers = $topAttackers
        recentAttempts = $recentAttempts | Sort-Object Time -Descending | Select-Object -First 10
    }
}

function Show-Dashboard {
    param([hashtable]$stats)
    
    Clear-Host
    
    # header
    Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "           SSH SIEM DASHBOARD v1.0             " -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Last updated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""
    
    # threat overview
    Write-Host "THREAT OVERVIEW (Last Hour)" -ForegroundColor Green
    Write-Host "─────────────────────────────────" -ForegroundColor Gray
    Write-Host "Total failed attempts: " -NoNewline -ForegroundColor White
    Write-Host $stats.totalAttempts -ForegroundColor $(if($stats.totalAttempts -gt 20) {"Red"} elseif($stats.totalAttempts -gt 10) {"Yellow"} else {"Green"})
    Write-Host "Unique attacking IPs: " -NoNewline -ForegroundColor White  
    Write-Host $stats.uniqueIPs -ForegroundColor $(if($stats.uniqueIPs -gt 10) {"Red"} elseif($stats.uniqueIPs -gt 5) {"Yellow"} else {"Green"})
    Write-Host ""
    
    # top attackers
    if ($stats.topAttackers.Count -gt 0) {
        Write-Host "TOP ATTACKING IPs" -ForegroundColor Red
        Write-Host "──────────────────────" -ForegroundColor Gray
        foreach ($attacker in $stats.topAttackers) {
            $riskLevel = if ($attacker.Value -gt 10) { "HIGH" } elseif ($attacker.Value -gt 5) { "MED" } else { "LOW" }
            $color = if ($attacker.Value -gt 10) { "Red" } elseif ($attacker.Value -gt 5) { "Yellow" } else { "White" }
            Write-Host "[$riskLevel] " -NoNewline -ForegroundColor $color
            Write-Host "$($attacker.Key) " -NoNewline -ForegroundColor White
            Write-Host "($($attacker.Value) attempts)" -ForegroundColor Gray
        }
        Write-Host ""
    }
    
    # recent activity
    if ($stats.recentAttempts.Count -gt 0) {
        Write-Host "RECENT ACTIVITY" -ForegroundColor Yellow
        Write-Host "────────────────────" -ForegroundColor Gray
        foreach ($attempt in $stats.recentAttempts | Select-Object -First 8) {
            $timeStr = $attempt.Time.ToString("HH:mm:ss")
            Write-Host "[$timeStr] " -NoNewline -ForegroundColor Gray
            Write-Host $attempt.IP -NoNewline -ForegroundColor Red
            Write-Host " -> " -NoNewline -ForegroundColor White
            Write-Host $attempt.User -ForegroundColor Cyan
        }
        Write-Host ""
    }
    
    # status indicators
    $status = if ($stats.totalAttempts -gt 50) { 
        @{text="HIGH THREAT"; color="Red"} 
    } elseif ($stats.totalAttempts -gt 20) { 
        @{text="MODERATE THREAT"; color="Yellow"} 
    } elseif ($stats.totalAttempts -gt 0) { 
        @{text="LOW THREAT"; color="Green"} 
    } else { 
        @{text="ALL QUIET"; color="Green"} 
    }
    
    Write-Host "STATUS: " -NoNewline -ForegroundColor White
    Write-Host $status.text -ForegroundColor $status.color
    Write-Host ""
    Write-Host "Press Ctrl+C to exit dashboard" -ForegroundColor Gray
    Write-Host "Next refresh in $refreshSeconds seconds..." -ForegroundColor Gray
}

# main dashboard loop
Write-Host "Starting SIEM Dashboard..." -ForegroundColor Green
Write-Host "Monitoring: $logFile" -ForegroundColor Cyan

while ($true) {
    try {
        $statistics = Get-AttackStatistics -logPath $logFile
        Show-Dashboard -stats $statistics
        Start-Sleep -Seconds $refreshSeconds
    }
    catch {
        Write-Host "Dashboard error: $($_.Exception.Message)" -ForegroundColor Red
        Start-Sleep -Seconds 5
    }
}
