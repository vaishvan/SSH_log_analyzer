# SIEM Configuration - adjust settings here
# settings for ssh log analyzer

# detection thresholds  
$config = @{
    # alert settings
    failedLoginThreshold = 5        # attempts before alert
    timeWindowMinutes = 1           # time window for counting
    alertCooldownMinutes = 5        # min time between alerts for same IP
    
    # monitoring settings
    logPollIntervalSeconds = 2      # how often to check log file
    maxLogLinesToProcess = 100      # lines to read at once
    
    # file paths
    defaultLogPath = ".\ssh_logs.txt"
    alertLogPath = ".\alerts.log"
    
    # ip whitelist - never alert on these
    whitelistedIPs = @(
        "192.168.1.10",
        "192.168.1.20", 
        "10.0.0.5"
    )
    
    # high-risk usernames - lower threshold
    criticalUsers = @(
        "root",
        "admin", 
        "administrator"
    )
    criticalUserThreshold = 3       # lower threshold for critical users
    
    # geolocation settings (future enhancement)
    enableGeoBlocking = $false
    blockedCountries = @("CN", "RU")
    
    # notification settings
    enableEmailAlerts = $false
    smtpServer = "smtp.company.com"
    alertEmailFrom = "siem@company.com"
    alertEmailTo = @("admin@company.com", "security@company.com")
}

# export config for other scripts
# Reference the config variable to avoid "assigned but never used" warning
Write-Verbose "Configuration loaded with $($config.Keys.Count) settings"
Export-ModuleMember -Variable config
