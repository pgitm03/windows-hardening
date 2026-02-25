# =============================================================================
# Optimize-Windows.ps1
# Windows System Hardening & Performance Optimization Script
# Author: Patrick Moreno
# Description: Automates common Windows security hardening tasks and
#              performance optimizations. Must be run as Administrator.
# =============================================================================

#Requires -RunAsAdministrator

# ── Color-coded output helpers ────────────────────────────────────────────────
function Write-Info    { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warning { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail    { param($msg) Write-Host "[-] $msg" -ForegroundColor Red }

# ── Banner ────────────────────────────────────────────────────────────────────
Clear-Host
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "   Windows Security Hardening & Performance Optimizer" -ForegroundColor Cyan
Write-Host "   github.com/patrickmoreno  |  Run as Administrator" -ForegroundColor Gray
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ── Confirm before running ────────────────────────────────────────────────────
$confirm = Read-Host "This script will modify system settings. Continue? (y/n)"
if ($confirm -ne 'y') { Write-Warning "Aborted."; exit }

Write-Host ""
Write-Host "Select a mode:" -ForegroundColor White
Write-Host "  [1] Security Hardening Only"
Write-Host "  [2] Performance Optimization Only"
Write-Host "  [3] Full (Security + Performance)"
$mode = Read-Host "Enter choice (1/2/3)"
Write-Host ""

# =============================================================================
# SECTION 1 — SECURITY HARDENING
# =============================================================================

function Invoke-SecurityHardening {
    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " SECURITY HARDENING" -ForegroundColor Cyan
    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan

    # -- 1.1 Enable Windows Firewall on all profiles --
    Write-Info "Enabling Windows Firewall on all profiles..."
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        Write-Success "Firewall enabled on all profiles."
    } catch { Write-Fail "Could not enable firewall: $_" }

    # -- 1.2 Enable Windows Defender real-time protection --
    Write-Info "Enabling Windows Defender real-time protection..."
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Write-Success "Windows Defender real-time protection is ON."
    } catch { Write-Fail "Could not configure Defender: $_" }

    # -- 1.3 Disable Remote Desktop (reduces attack surface) --
    Write-Info "Disabling Remote Desktop Protocol (RDP)..."
    try {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
            -Name "fDenyTSConnections" -Value 1
        Write-Success "RDP disabled."
    } catch { Write-Fail "Could not disable RDP: $_" }

    # -- 1.4 Disable Windows Telemetry --
    Write-Info "Reducing Windows telemetry (data collection)..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
            -Name "AllowTelemetry" -Value 0 -Force -ErrorAction SilentlyContinue
        Write-Success "Telemetry set to minimum."
    } catch { Write-Fail "Could not set telemetry: $_" }

    # -- 1.5 Disable AutoRun/AutoPlay (common malware vector) --
    Write-Info "Disabling AutoRun and AutoPlay..."
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" `
            -Name "DisableAutoplay" -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf" `
            -Name "(Default)" -Value "@SYS:DoesNotExist" -Force -ErrorAction SilentlyContinue
        Write-Success "AutoRun/AutoPlay disabled."
    } catch { Write-Fail "Could not disable AutoRun: $_" }

    # -- 1.6 Check if Windows is up to date --
    Write-Info "Checking for pending Windows Updates..."
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $results = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
        if ($results.Updates.Count -eq 0) {
            Write-Success "Windows is up to date."
        } else {
            Write-Warning "$($results.Updates.Count) update(s) pending. Run Windows Update soon."
        }
    } catch { Write-Warning "Could not check for updates automatically. Check manually." }

    # -- 1.7 Disable SMBv1 (known vulnerability, used in WannaCry) --
    Write-Info "Disabling SMBv1 protocol..."
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Write-Success "SMBv1 disabled."
    } catch { Write-Fail "Could not disable SMBv1: $_" }

    # -- 1.8 Enable UAC (User Account Control) --
    Write-Info "Ensuring User Account Control (UAC) is enabled..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            -Name "EnableLUA" -Value 1
        Write-Success "UAC is enabled."
    } catch { Write-Fail "Could not verify UAC: $_" }

    # -- 1.9 Check for weak/shared local admin accounts --
    Write-Info "Checking local user accounts..."
    $localAdmins = Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.ObjectClass -eq "User" }
    Write-Host ""
    Write-Host "  Current local administrators:" -ForegroundColor White
    $localAdmins | ForEach-Object { Write-Host "    - $($_.Name)" -ForegroundColor Gray }
    Write-Host ""
    if ($localAdmins.Count -gt 2) {
        Write-Warning "More than 2 local admin accounts detected. Review if all are necessary."
    } else {
        Write-Success "Local admin accounts look reasonable."
    }

    Write-Host ""
    Write-Success "Security hardening complete."
    Write-Host ""
}

# =============================================================================
# SECTION 2 — PERFORMANCE OPTIMIZATION
# =============================================================================

function Invoke-PerformanceOptimization {
    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host " PERFORMANCE OPTIMIZATION" -ForegroundColor Cyan
    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan

    # -- 2.1 Set power plan to High Performance --
    Write-Info "Setting power plan to High Performance..."
    try {
        powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
        Write-Success "Power plan set to High Performance."
    } catch { Write-Fail "Could not set power plan: $_" }

    # -- 2.2 Disable unnecessary visual effects --
    Write-Info "Optimizing visual effects for performance..."
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" `
            -Name "VisualFXSetting" -Value 2
        Write-Success "Visual effects set to 'Adjust for best performance'."
    } catch { Write-Fail "Could not adjust visual effects: $_" }

    # -- 2.3 Clean up temp files --
    Write-Info "Clearing temporary files..."
    $tempPaths = @(
        "$env:TEMP",
        "$env:SystemRoot\Temp",
        "$env:SystemRoot\Prefetch"
    )
    $totalCleaned = 0
    foreach ($path in $tempPaths) {
        if (Test-Path $path) {
            $files = Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                try {
                    Remove-Item $file.FullName -Force -Recurse -ErrorAction SilentlyContinue
                    $totalCleaned++
                } catch { }
            }
        }
    }
    Write-Success "Cleared $totalCleaned temp files/folders."

    # -- 2.4 Disable startup programs that slow boot --
    Write-Info "Checking startup programs..."
    $startupItems = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name, Command, Location
    if ($startupItems.Count -gt 0) {
        Write-Host ""
        Write-Host "  Startup programs detected:" -ForegroundColor White
        $startupItems | ForEach-Object {
            Write-Host "    - $($_.Name)" -ForegroundColor Gray
        }
        Write-Host ""
        Write-Warning "Review these in Task Manager > Startup and disable anything you don't need."
    } else {
        Write-Success "No unexpected startup programs found."
    }

    # -- 2.5 Flush DNS cache --
    Write-Info "Flushing DNS cache..."
    try {
        ipconfig /flushdns | Out-Null
        Write-Success "DNS cache flushed."
    } catch { Write-Fail "Could not flush DNS: $_" }

    # -- 2.6 Disable SysMain (Superfetch) — helps on SSDs --
    Write-Info "Checking SysMain (Superfetch) service..."
    try {
        $sysMain = Get-Service -Name "SysMain" -ErrorAction SilentlyContinue
        if ($sysMain -and $sysMain.Status -eq "Running") {
            Stop-Service -Name "SysMain" -Force
            Set-Service -Name "SysMain" -StartupType Disabled
            Write-Success "SysMain disabled (recommended for SSD systems)."
        } else {
            Write-Success "SysMain already stopped or not present."
        }
    } catch { Write-Fail "Could not modify SysMain: $_" }

    # -- 2.7 Release and renew IP / reset network stack --
    Write-Info "Resetting network stack..."
    try {
        ipconfig /release | Out-Null
        ipconfig /renew | Out-Null
        netsh winsock reset | Out-Null
        Write-Success "Network stack reset successfully."
    } catch { Write-Fail "Network reset failed: $_" }

    Write-Host ""
    Write-Success "Performance optimization complete."
    Write-Host ""
}

# =============================================================================
# MAIN — Run selected mode
# =============================================================================

switch ($mode) {
    "1" { Invoke-SecurityHardening }
    "2" { Invoke-PerformanceOptimization }
    "3" {
        Invoke-SecurityHardening
        Invoke-PerformanceOptimization
    }
    default {
        Write-Warning "Invalid choice. Running full optimization by default."
        Invoke-SecurityHardening
        Invoke-PerformanceOptimization
    }
}

# =============================================================================
# SUMMARY
# =============================================================================
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " All tasks completed. A restart may be required for some" -ForegroundColor Cyan
Write-Host " changes (e.g. RDP, SMBv1, network reset) to take effect." -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
