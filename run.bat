@echo off
title SSH SIEM Simulator - Enhanced Control Panel

:menu
cls
echo ================================================================
echo         SSH Log Analyzer - Enhanced SIEM with SOAR
echo ================================================================
echo.
echo Select an option:
echo.
echo 1. Generate sample attack logs (one-time)
echo 2. Start continuous log generation 
echo 3. Run Enhanced SIEM with Auto-blocking (RECOMMENDED)
echo 4. Run Enhanced SIEM with Threat Intel+Auto-blocking
echo 5. Run Basic SIEM analyzer (legacy)
echo 6. Demo Enhanced Features
echo 7. Launch security dashboard
echo 8. View recent alerts
echo 9. Clean up logs and firewall rules
echo 0. Exit
echo.
set /p choice="Enter your choice (0-9): "

if "%choice%"=="1" goto generate_once
if "%choice%"=="2" goto generate_continuous  
if "%choice%"=="3" goto run_enhanced
if "%choice%"=="4" goto run_enhanced_threatintel
if "%choice%"=="5" goto run_analyzer_basic
if "%choice%"=="6" goto demo_enhanced
if "%choice%"=="7" goto run_dashboard
if "%choice%"=="8" goto view_alerts
if "%choice%"=="9" goto cleanup
if "%choice%"=="0" goto exit
goto menu

:generate_once
echo.
echo Generating sample SSH logs with attack patterns...
powershell.exe -ExecutionPolicy Bypass -File "generate-logs.ps1" -outputFile "ssh_logs.txt" -delaySeconds 1
echo.
echo Sample logs generated. Press any key to return to menu.
pause >nul
goto menu

:generate_continuous
echo.
echo Starting continuous log generation...
echo Press Ctrl+C to stop generation
echo.
powershell.exe -ExecutionPolicy Bypass -File "generate-logs.ps1" -continuous -delaySeconds 2
goto menu

:run_enhanced
echo.
echo Starting Enhanced SSH SIEM with Auto-blocking...
echo Features: Attack detection, Auto-blocking, Pattern analysis
echo.
echo Generating test logs first...
powershell.exe -ExecutionPolicy Bypass -File "generate-logs.ps1" -AttackCount 15 -AttackType mixed
echo.
echo Starting enhanced analyzer...
echo Press Ctrl+C to stop monitoring
echo.
powershell.exe -ExecutionPolicy Bypass -File "ssh-analyzer-enhanced.ps1" -autoBlock -verbose -exportAlerts
goto menu

:run_enhanced_threatintel
echo.
set /p apikey="Enter AbuseIPDB API key (or press Enter to skip): "
echo.
echo Starting Enhanced SIEM with Threat Intelligence...
echo Features: Auto-blocking, Threat Intel, Advanced Detection
echo.
echo Generating test logs first...
powershell.exe -ExecutionPolicy Bypass -File "generate-logs.ps1" -AttackCount 20 -AttackType mixed
echo.
echo Starting enhanced analyzer with threat intel...
echo Press Ctrl+C to stop monitoring
echo.
if "%apikey%"=="" (
    powershell.exe -ExecutionPolicy Bypass -File "ssh-analyzer-enhanced.ps1" -autoBlock -threatIntel -verbose -exportAlerts
) else (
    powershell.exe -ExecutionPolicy Bypass -File "ssh-analyzer-enhanced.ps1" -autoBlock -threatIntel -abuseDbKey "%apikey%" -verbose -exportAlerts
)
goto menu

:demo_enhanced
echo.
echo Running Enhanced Features Demo...
echo This will demonstrate threat intelligence and auto-blocking
echo.
powershell.exe -ExecutionPolicy Bypass -File "test-enhanced.ps1" -demo
goto menu

:run_analyzer_basic
echo.
echo Starting Basic SSH SIEM Analyzer (Legacy)...
echo (5 failed attempts in 1 minute triggers alert)
echo.
powershell.exe -ExecutionPolicy Bypass -File "ssh-log-analyzer.ps1"
goto menu

:run_dashboard
echo.
echo Launching security dashboard...
echo.
powershell.exe -ExecutionPolicy Bypass -File "dashboard.ps1"
goto menu

:view_alerts
echo.
echo Recent security alerts:
echo =====================
if exist alerts.log (
    type alerts.log
) else (
    echo No alerts found.
)
echo.
echo Press any key to return to menu.
pause >nul
goto menu

:cleanup
echo.
echo Cleaning up logs and firewall rules...
echo.
echo Removing firewall rules...
powershell.exe -ExecutionPolicy Bypass -File "test-enhanced.ps1" -cleanup
echo.
echo Cleaning up log files...
if exist ssh_logs.txt del ssh_logs.txt
if exist alerts.log del alerts.log
echo.
echo Cleanup complete.
echo Press any key to return to menu.
pause >nul
goto menu

:exit
echo.
echo Goodbye!
exit /b 0
