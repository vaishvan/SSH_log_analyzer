# ssh analyzer with threat intel and auto-blocking
# detects attacks and responds automatically

param(
    [string]$logPath = ".\ssh_logs.txt",
    [int]$threshold = 5,
    [int]$timeWindowMinutes = 1,
    [switch]$verbose,
    [switch]$exportAlerts,
    [switch]$autoBlock,
    [switch]$threatIntel,
    [string]$abuseDbKey = ""
)

# globals for tracking different attack types
$bruteForceTracking = @{}
$alertHistory = @{}
$blockedIps = @{}
$threatCache = @{}
$startTime = Get-Date

# attack patterns we look for
$attackSignatures = @{
    "dictionary_attack" = @{
        usernames = @("admin", "root", "user", "test", "guest", "administrator", "oracle", "postgres", "mysql")
        description = "dictionary username attack"
    }
    "time_based" = @{
        description = "off-hours login attempts"
        suspiciousHours = @(0,1,2,3,4,5,22,23)
    }
    "rapid_fire" = @{
        description = "rapid successive attempts"
        maxInterval = 2
    }
}

function Write-Alert {
    param([string]$message, [string]$level = "INFO", [string]$ipAddr = "")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $alertMsg = "[$timestamp] [$level] $message"
    
    # color coding for different alert levels
    $color = switch($level) {
        "CRITICAL" { "Red" }
        "HIGH" { "Magenta" }
        "MEDIUM" { "Yellow" }
        "LOW" { "Cyan" }
        default { "White" }
    }
    
    Write-Host $alertMsg -ForegroundColor $color
    
    # export to alerts log if enabled
    if ($exportAlerts) {
        Add-Content -Path "alerts.log" -Value $alertMsg
    }
}

# check ip against threat feeds
function Get-ThreatIntel {
    param([string]$ipAddr)
    
    if (-not $threatIntel) { return $null }
    
    # use cache to avoid repeated lookups
    if ($threatCache.ContainsKey($ipAddr)) {
        return $threatCache[$ipAddr]
    }
    
    $threatInfo = @{
        isMalicious = $false
        confidence = 0
        sources = @()
        lastSeen = $null
    }
    
    try {
        # check abuseipdb if api key provided
        if ($abuseDbKey -ne "") {
            $result = Get-AbuseIPDB -ip $ipAddr -apiKey $abuseDbKey
            if ($result.abuseConfidence -gt 25) {
                $threatInfo.isMalicious = $true
                $threatInfo.confidence = $result.abuseConfidence
                $threatInfo.sources += "AbuseIPDB"
                $threatInfo.lastSeen = $result.lastReportedAt
            }
        }
        
        # simple ip reputation check via dns
        $dnsResult = Test-MaliciousIP -ip $ipAddr
        if ($dnsResult) {
            $threatInfo.isMalicious = $true
            $threatInfo.sources += "DNS-BL"
            $threatInfo.confidence = [math]::Max($threatInfo.confidence, 75)
        }
        
    } catch {
        Write-Alert "threat intel lookup failed for $ipAddr" "LOW"
    }
    
    # cache result for 1 hour
    $threatCache[$ipAddr] = $threatInfo
    
    return $threatInfo
}

# check abuseipdb api
function Get-AbuseIPDB {
    param([string]$ip, [string]$apiKey)
    
    $headers = @{
        'Key' = $apiKey
        'Accept' = 'application/json'
    }
    
    $uri = "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90"
    
    try {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -TimeoutSec 10
        return $response.data
    } catch {
        return @{ abuseConfidence = 0 }
    }
}

# simple dns blacklist check
function Test-MaliciousIP {
    param([string]$ip)
    
    # reverse ip for dns blacklist lookup
    $octets = $ip.Split('.')
    $reversedIp = "$($octets[3]).$($octets[2]).$($octets[1]).$($octets[0])"
    
    # check common blacklists
    $blacklists = @(
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "cbl.abuseat.org"
    )
    
    foreach ($bl in $blacklists) {
        try {
            $lookup = "$reversedIp.$bl"
            $result = Resolve-DnsName -Name $lookup -Type A -ErrorAction SilentlyContinue
            if ($result) {
                return $true
            }
        } catch {
            # dns lookup failed, continue to next
        }
    }
    
    return $false
}

# block ip using windows firewall
function Block-IPAddress {
    param([string]$ipAddr, [string]$reason = "ssh attack")
    
    if (-not $autoBlock) { return }
    
    # check if already blocked
    if ($blockedIps.ContainsKey($ipAddr)) {
        return
    }
    
    try {
        $ruleName = "SSH_Analyzer_Block_$($ipAddr.Replace('.', '_'))"
        
        # create firewall rule to block the ip
        $cmd = "netsh advfirewall firewall add rule name=`"$ruleName`" dir=in action=block remoteip=$ipAddr"
        
        $result = cmd /c $cmd 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            $blockedIps[$ipAddr] = @{
                timestamp = Get-Date
                reason = $reason
                ruleName = $ruleName
            }
            Write-Alert "🚫 BLOCKED IP $ipAddr via Windows Firewall" "HIGH" $ipAddr
            Write-Alert "   Rule: $ruleName" "HIGH"
            Write-Alert "   Reason: $reason" "HIGH"
        } else {
            Write-Alert "failed to block $ipAddr - $result" "MEDIUM"
        }
        
    } catch {
        Write-Alert "error blocking ip $ipAddr - $($_.Exception.Message)" "MEDIUM"
    }
}

# parse different log formats
function Convert-LogEntry {
    param([string]$logLine)
    
    $entry = @{
        timestamp = $null
        ipAddress = $null
        username = $null
        eventType = "unknown"
        port = $null
        country = $null
        rawLine = $logLine
    }
    
    # linux auth.log format
    if ($logLine -match "(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*Failed password.*from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+port\s+(\d+).*for\s+(\w+)") {
        $entry.timestamp = [datetime]::ParseExact($matches[1], "MMM d HH:mm:ss", $null)
        $entry.timestamp = $entry.timestamp.AddYears((Get-Date).Year - 1900)
        $entry.ipAddress = $matches[2]
        $entry.port = $matches[3]
        $entry.username = $matches[4]
        $entry.eventType = "failed_password"
    }
    # invalid user attempts
    elseif ($logLine -match "(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*Invalid user\s+(\w+)\s+from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})") {
        $entry.timestamp = [datetime]::ParseExact($matches[1], "MMM d HH:mm:ss", $null)
        $entry.timestamp = $entry.timestamp.AddYears((Get-Date).Year - 1900)
        $entry.username = $matches[2]
        $entry.ipAddress = $matches[3]
        $entry.eventType = "invalid_user"
    }
    # custom format
    elseif ($logLine -match "(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*SSH_FAIL.*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*user:(\w+)") {
        $entry.timestamp = [datetime]::Parse($matches[1])
        $entry.ipAddress = $matches[2]
        $entry.username = $matches[3]
        $entry.eventType = "failed_login"
    }
    # connection attempts
    elseif ($logLine -match "(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*Connection.*from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})") {
        $entry.timestamp = [datetime]::Parse($matches[1])
        $entry.ipAddress = $matches[2]
        $entry.eventType = "connection_attempt"
    }
    
    return $entry
}

# detect dictionary attacks
function Find-DictAttack {
    param([string]$ipAddr, [array]$attempts)
    
    $dictUsers = $attackSignatures.dictionary_attack.usernames
    $matchedUsers = $attempts | Where-Object { $dictUsers -contains $_.username } | Select-Object -ExpandProperty username -Unique
    
    if ($matchedUsers.Count -ge 3) {
        Write-Alert "dictionary attack from $ipAddr - users: $($matchedUsers -join ', ')" "HIGH" $ipAddr
        return $true
    }
    return $false
}

# detect time-based anomalies  
function Find-TimeAnomaly {
    param([hashtable]$logEntry)
    
    $hour = $logEntry.timestamp.Hour
    $suspiciousHours = $attackSignatures.time_based.suspiciousHours
    
    if ($hour -in $suspiciousHours) {
        Write-Alert "off-hours attempt at $($logEntry.timestamp.ToString('HH:mm')) from $($logEntry.ipAddress)" "MEDIUM" $logEntry.ipAddress
        return $true
    }
    return $false
}

# track attacks and respond
function Update-AttackTracking {
    param([hashtable]$logEntry)
    
    if ($logEntry.eventType -notin @("failed_password", "failed_login", "invalid_user")) { 
        return 
    }
    
    $ipAddr = $logEntry.ipAddress
    $currentTime = Get-Date
    
    # check threat intelligence first
    $threatInfo = Get-ThreatIntel -ipAddr $ipAddr
    if ($threatInfo -and $threatInfo.isMalicious) {
        Write-Alert "🔥 KNOWN THREAT DETECTED!" "CRITICAL" $ipAddr
        Write-Alert "   IP: $ipAddr" "CRITICAL"
        Write-Alert "   Sources: $($threatInfo.sources -join ', ')" "CRITICAL"
        Write-Alert "   Confidence: $($threatInfo.confidence)%" "CRITICAL"
        
        # auto-block known threats immediately
        Block-IPAddress -ipAddr $ipAddr -reason "known threat (confidence: $($threatInfo.confidence)%)"
    }
    
    # initialize tracking for new ip
    if (-not $bruteForceTracking.ContainsKey($ipAddr)) {
        $bruteForceTracking[$ipAddr] = @{
            attempts = @()
            firstSeen = $currentTime
            lastSeen = $currentTime
            totalAttempts = 0
            uniqueUsers = @()
            threatInfo = $threatInfo
        }
    }
    
    $tracking = $bruteForceTracking[$ipAddr]
    
    # add current attempt
    $attemptInfo = @{
        timestamp = $currentTime
        username = $logEntry.username
        eventType = $logEntry.eventType
    }
    
    $tracking.attempts += $attemptInfo
    $tracking.lastSeen = $currentTime
    $tracking.totalAttempts++
    
    if ($logEntry.username -notin $tracking.uniqueUsers) {
        $tracking.uniqueUsers += $logEntry.username
    }
    
    # cleanup old attempts outside time window
    $cutoffTime = $currentTime.AddMinutes(-$timeWindowMinutes)
    $tracking.attempts = $tracking.attempts | Where-Object { $_.timestamp -gt $cutoffTime }
    
    # run detection algorithms
    $recentAttempts = $tracking.attempts.Count
    
    # standard brute force detection
    if ($recentAttempts -ge $threshold) {
        New-BruteForceAlert -ipAddress $ipAddr -attemptCount $recentAttempts -tracking $tracking
        
        # auto-block after threshold reached
        if ($recentAttempts -ge ($threshold * 2)) {
            Block-IPAddress -ipAddr $ipAddr -reason "brute force ($recentAttempts attempts)"
        }
    }
    
    # other detection patterns
    Find-DictAttack -ipAddr $ipAddr -attempts $tracking.attempts | Out-Null
    Find-TimeAnomaly -logEntry $logEntry | Out-Null
    
    # rapid-fire detection
    if ($tracking.attempts.Count -ge 2) {
        $lastTwo = $tracking.attempts | Sort-Object timestamp -Descending | Select-Object -First 2
        $interval = ($lastTwo[0].timestamp - $lastTwo[1].timestamp).TotalSeconds
        
        if ($interval -lt $attackSignatures.rapid_fire.maxInterval) {
            Write-Alert "rapid-fire attack from $ipAddr (interval: $([math]::Round($interval, 1))s)" "HIGH" $ipAddr
        }
    }
}

# generate brute force alerts with context
function New-BruteForceAlert {
    param(
        [string]$ipAddress,
        [int]$attemptCount,
        [hashtable]$tracking
    )
    
    # avoid spam alerts
    $lastAlert = $alertHistory[$ipAddress]
    if ($lastAlert -and ((Get-Date) - $lastAlert).TotalMinutes -lt 5) {
        return
    }
    
    $alertHistory[$ipAddress] = Get-Date
    
    # determine severity
    $severity = if ($attemptCount -gt 20) { "CRITICAL" }
               elseif ($attemptCount -gt 10) { "HIGH" }
               elseif ($attemptCount -gt 5) { "MEDIUM" }
               else { "LOW" }
    
    Write-Alert "🚨 brute-force attack detected!" $severity $ipAddress
    Write-Alert "   source: $ipAddress" $severity
    Write-Alert "   attempts: $attemptCount in $timeWindowMinutes min" $severity
    Write-Alert "   total: $($tracking.totalAttempts)" $severity
    Write-Alert "   users: $($tracking.uniqueUsers.Count)" $severity
    
    # show threat intel if available
    if ($tracking.threatInfo -and $tracking.threatInfo.isMalicious) {
        Write-Alert "   ⚠️ known threat: $($tracking.threatInfo.sources -join ', ')" $severity
    }
    
    # show attempted usernames
    $userList = $tracking.uniqueUsers -join ', '
    if ($userList.Length -gt 60) {
        $userList = $userList.Substring(0, 57) + "..."
    }
    Write-Alert "   targets: $userList" $severity
    
    # attack duration
    $duration = ((Get-Date) - $tracking.firstSeen).TotalMinutes
    Write-Alert "   duration: $([math]::Round($duration, 1)) min" $severity
    
    # recommendations
    switch ($severity) {
        "CRITICAL" { 
            Write-Alert "   🔥 immediate action required!" $severity
            Write-Alert "   ► check if ip is already blocked" $severity
            Write-Alert "   ► review successful logins" $severity
        }
        "HIGH" {
            Write-Alert "   ⚠️ recommended: block ip $ipAddress" $severity
        }
        "MEDIUM" {
            Write-Alert "   📋 monitor for escalation" $severity
        }
    }
    
    Write-Alert "" $severity
}

# main log monitoring with soar features
function Start-LogMonitoring {
    param([string]$logFile)
    
    Write-Alert "ssh analyzer v3.0 - threat intel + auto-blocking" "INFO"
    Write-Alert "=================================================" "INFO"
    Write-Alert "log file: $logFile" "INFO"
    Write-Alert "threshold: $threshold attempts in $timeWindowMinutes min" "INFO"
    Write-Alert "features: threat intel, auto-blocking, pattern detection" "INFO"
    if ($autoBlock) { Write-Alert "auto-block: enabled (windows firewall)" "INFO" }
    if ($threatIntel) { Write-Alert "threat intel: enabled" "INFO" }
    Write-Alert "started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
    Write-Alert "press ctrl+c to stop`n" "INFO"
    
    if (-not (Test-Path $logFile)) {
        Write-Alert "log file not found - create with generate-logs.ps1" "MEDIUM"
        return
    }
    
    $lastSize = 0
    $lineCount = 0
    
    while ($true) {
        try {
            $currentSize = (Get-Item $logFile).Length
            
            if ($currentSize -gt $lastSize) {
                # read new content only
                $content = Get-Content $logFile -Raw
                $newContent = $content.Substring($lastSize)
                $newLines = $newContent -split "`n" | Where-Object { $_ -ne "" }
                
                foreach ($line in $newLines) {
                    $lineCount++
                    
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    
                    $parsedEntry = Convert-LogEntry -logLine $line
                    
                    if ($parsedEntry.eventType -ne "unknown") {
                        if ($verbose) {
                            Write-Alert "processed: $($parsedEntry.eventType) from $($parsedEntry.ipAddress)" "LOW"
                        }
                        Update-AttackTracking -logEntry $parsedEntry
                    }
                }
                
                $lastSize = $currentSize
            }
            
            # periodic stats
            if ($lineCount % 100 -eq 0 -and $lineCount -gt 0) {
                $uptime = ((Get-Date) - $startTime).TotalMinutes
                $blockedCount = $blockedIps.Count
                Write-Alert "stats: $lineCount lines, $($bruteForceTracking.Count) ips tracked, $blockedCount blocked, uptime: $([math]::Round($uptime, 1))m" "INFO"
            }
            
            Start-Sleep -Seconds 2
        }
        catch {
            Write-Alert "error monitoring: $($_.Exception.Message)" "HIGH"
            Start-Sleep -Seconds 5
        }
    }
}

# main execution
Clear-Host
Start-LogMonitoring -logFile $logPath
