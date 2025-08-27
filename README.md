# SSH Log Analyzer - Advanced SIEM with SOAR

A PowerShell-based Security Information and Event Management (SIEM) tool with Security Orchestration, Automation and Response (SOAR) capabilities for detecting and responding to SSH attacks in real-time.

## File Structure

```
SSH_analyze/
├── ssh-analyzer-enhanced.ps1  # Main SIEM with SOAR capabilities
├── ssh-log-analyzer.ps1       # Basic SIEM analyzer
├── generate-logs.ps1          # Attack simulation & log generator  
├── dashboard.ps1             # Real-time security dashboard
├── test-enhanced.ps1         # Demo script for new features
├── config.ps1               # Configuration settings
└── README.md                # This documentation
```

## Quick Start

### 1. Basic SIEM Monitoring
```powershell
# Generate sample attack data
.\generate-logs.ps1 -outputFile "ssh_logs.txt" -delaySeconds 2

# Start basic SIEM analyzer
.\ssh-log-analyzer.ps1 -threshold 5 -timeWindowMinutes 1
```

### 2. Enhanced SIEM with SOAR (Recommended)
```powershell
# Generate test attacks
.\generate-logs.ps1 -AttackCount 20 -AttackType mixed

# Start enhanced analyzer with auto-blocking and threat intel
.\ssh-analyzer-enhanced.ps1 -autoBlock -threatIntel -verbose -exportAlerts

# With AbuseIPDB API key for better threat intel
.\ssh-analyzer-enhanced.ps1 -autoBlock -threatIntel -abuseDbKey "YOUR_API_KEY"
```

### 3. Demo the Enhanced Features
```powershell
# Run complete demo with all features
.\test-enhanced.ps1 -demo

# Cleanup firewall rules and logs when done
.\test-enhanced.ps1 -cleanup
```

### 4. Real-time Dashboard
```powershell
# Launch security dashboard
.\dashboard.ps1 -logFile "ssh_logs.txt"
```

## Configuration

Edit `config.ps1` to customize detection rules:

```powershell
$config = @{
    failedLoginThreshold = 5        # attempts before alert
    timeWindowMinutes = 1           # time window for counting  
    alertCooldownMinutes = 5        # min time between alerts
    
    # IP whitelist
    whitelistedIPs = @("192.168.1.10", "192.168.1.20")
    
    # Critical users (lower threshold)
    criticalUsers = @("root", "admin")
    criticalUserThreshold = 3
}
```

## Log Formats Supported

The analyzer supports multiple SSH log formats:

### Linux auth.log format:
```
Oct 15 14:23:45 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
```

### Windows Event Log style:
```
2024-10-15 14:23:45 LOGIN_FAILED IP:192.168.1.100 USER:admin
```

### Custom format (used by simulator):
```
2024-10-15 14:23:45 SSH_FAIL 192.168.1.100 user:admin
```

## Usage Examples

### Monitor Production Logs
```powershell
# Monitor real SSH logs on Linux server
.\ssh-log-analyzer.ps1 -logPath "\\server\logs\auth.log" -threshold 3

# Monitor Windows SSH logs
.\ssh-log-analyzer.ps1 -logPath "C:\Windows\System32\winevt\Logs\Security.evtx"
```

### Testing & Development
```powershell
# Generate test data and monitor simultaneously
Start-Job { .\generate-logs.ps1 -continuous -delaySeconds 3 }
.\ssh-log-analyzer.ps1 -threshold 3
```

### Dashboard Monitoring
```powershell
# Launch dashboard for security operations center
.\dashboard.ps1
```

## Security Considerations

- Legitimate users may trigger alerts during password resets
- Attackers can use rate-limiting to avoid detection  
- Ensure log file paths remain valid during rotation
- Consider running as Windows service for 24/7 monitoring

## Future Enhancements

- [ ] Email/SMS alert notifications
- [ ] IP geolocation and country blocking
- [ ] Integration with Windows Event Log
- [ ] Machine learning-based anomaly detection
- [ ] Database storage for historical analysis
1
## Requirements

- Windows PowerShell 5.1+ or PowerShell Core 6+
- Read access to SSH log files
- ~50MB available memory
- Network access (if monitoring remote logs)

---