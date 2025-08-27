# test script for enhanced ssh analyzer
# demonstrates threat intel and auto-blocking features

param(
    [switch]$demo,
    [switch]$cleanup
)

if ($cleanup) {
    Write-Host "cleaning up firewall rules..." -ForegroundColor Yellow
    
    # remove any rules created by ssh analyzer
    $rules = netsh advfirewall firewall show rule name=all | Select-String "SSH_Analyzer_Block"
    if ($rules) {
        Write-Host "found existing ssh analyzer rules - removing..." -ForegroundColor Cyan
        netsh advfirewall firewall delete rule name="SSH_Analyzer_Block*"
    }
    
    # cleanup log files
    if (Test-Path "alerts.log") { Remove-Item "alerts.log" -Force }
    if (Test-Path "ssh_logs.txt") { Remove-Item "ssh_logs.txt" -Force }
    
    Write-Host "cleanup complete" -ForegroundColor Green
    exit
}

if ($demo) {
    Write-Host "starting enhanced ssh analyzer demo..." -ForegroundColor Green
    Write-Host "this will demonstrate:" -ForegroundColor Cyan
    Write-Host "  1. threat intelligence lookup" -ForegroundColor White
    Write-Host "  2. automatic ip blocking" -ForegroundColor White
    Write-Host "  3. enhanced attack detection" -ForegroundColor White
    Write-Host ""
    
    # generate some test logs first
    Write-Host "generating test attack logs..." -ForegroundColor Yellow
    .\generate-logs.ps1 -AttackCount 20 -AttackType mixed
    
    Write-Host "starting analyzer with auto-blocking enabled..." -ForegroundColor Yellow
    Write-Host "press ctrl+c to stop when you see blocking in action" -ForegroundColor Red
    Write-Host ""
    
    # start the enhanced analyzer
    .\ssh-analyzer-enhanced.ps1 -autoBlock -threatIntel -verbose -exportAlerts
}
else {
    Write-Host "enhanced ssh analyzer test script" -ForegroundColor Green
    Write-Host "usage:" -ForegroundColor Cyan
    Write-Host "  .\test-enhanced.ps1 -demo      # run demo with auto-blocking" -ForegroundColor White
    Write-Host "  .\test-enhanced.ps1 -cleanup   # remove firewall rules and logs" -ForegroundColor White
    Write-Host ""
    Write-Host "features added:" -ForegroundColor Yellow
    Write-Host "  ✓ threat intelligence integration" -ForegroundColor Green
    Write-Host "  ✓ automated ip blocking (windows firewall)" -ForegroundColor Green
    Write-Host "  ✓ enhanced pattern detection" -ForegroundColor Green
    Write-Host "  ✓ soar-like automated response" -ForegroundColor Green
}
