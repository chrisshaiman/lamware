<#
.SYNOPSIS
    Disables Windows Defender on the Cape sandbox guest VM.

.DESCRIPTION
    Malware samples must execute without antivirus interference. This script
    is the second layer of a two-phase Defender disable strategy:

    Phase 1 (autounattend.xml specialize pass):
      - Disables WinDefend service (Start=4) before Tamper Protection activates
      - Sets Group Policy registry keys (DisableAntiSpyware, DisableAntiVirus,
        DisableRealtimeMonitoring, etc.)
      - Disables SmartScreen

    Phase 2 (this script, run by Packer provisioner):
      - Adds C:\ drive exclusion as a fallback (survives Defender re-enable)
      - Attempts Set-MpPreference settings (may silently fail if Tamper Protection
        is active, but costs nothing to try)
      - Disables Defender scheduled tasks (prevents background scans)
      - Disables SecurityHealthService (prevents tray alerts)
      - Stops the WinDefend service if it's running despite Phase 1

    On Win11 25H2+ (build 26200), Tamper Protection blocks programmatic
    changes to Defender while Windows is fully running. The specialize pass
    in autounattend.xml is the authoritative disable mechanism. This script
    provides defense-in-depth.

    Enterprise SKU (ADR-009) is required for the Group Policy keys to be
    honored without Microsoft Security Center overriding them.

    Managed by Packer. Do not edit manually.
    Author: Christopher Shaiman
    License: Apache 2.0
#>

Set-StrictMode -Version Latest
# TODO: re-enable Stop when all scripts verified working
$ErrorActionPreference = "Continue"

Write-Host "==> disable-defender: suppressing Windows Defender (Phase 2)"

# -------------------------------------------------------------------------
# 1. Add full-drive exclusion (most reliable fallback)
# -------------------------------------------------------------------------
# Even if Defender re-enables itself after an update or policy refresh,
# the exclusion ensures samples on disk are not scanned or quarantined.
# This works even when Tamper Protection is active.
Write-Host "==> Adding C:\ drive exclusion"
try {
    Add-MpPreference -ExclusionPath "C:\" -ErrorAction Stop
    Write-Host "  C:\ exclusion added"
} catch {
    Write-Warning "Failed to add C:\ exclusion: $_"
}

# -------------------------------------------------------------------------
# 2. Stop and disable WinDefend service
# -------------------------------------------------------------------------
# Phase 1 set Start=4 during specialize. If the service somehow started
# anyway, stop it now. sc.exe config may fail due to Tamper Protection
# but the specialize-phase registry edit should have already taken effect.
Write-Host "==> Stopping WinDefend service"
try {
    $svc = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Stop-Service -Name "WinDefend" -Force -ErrorAction SilentlyContinue
        Write-Host "  WinDefend stopped"
    } else {
        Write-Host "  WinDefend already stopped or not found"
    }
} catch {
    Write-Warning "Could not stop WinDefend: $_"
}

# Attempt to set service to disabled via sc.exe (may be blocked by Tamper Protection)
& sc.exe config WinDefend start= disabled 2>$null | Out-Null

# -------------------------------------------------------------------------
# 3. Real-time protection via MpPreference (best-effort)
# -------------------------------------------------------------------------
# These may silently fail if Tamper Protection is active. The specialize
# pass GP keys and the C:\ exclusion are the authoritative controls.
Write-Host "==> Attempting Set-MpPreference (may be blocked by Tamper Protection)"
try {
    Set-MpPreference -DisableRealtimeMonitoring          $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBehaviorMonitoring          $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBlockAtFirstSeen            $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection              $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisablePrivacyMode                 $true -ErrorAction SilentlyContinue
    Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true -ErrorAction SilentlyContinue
    Set-MpPreference -SubmitSamplesConsent               2     -ErrorAction SilentlyContinue
    Set-MpPreference -MAPSReporting                      0     -ErrorAction SilentlyContinue
    Write-Host "  MpPreference settings applied (verify after reboot)"
} catch {
    Write-Warning "Set-MpPreference raised an error (expected if Tamper Protection active): $_"
}

# -------------------------------------------------------------------------
# 4. Reinforce Group Policy registry keys
# -------------------------------------------------------------------------
# These were set in the specialize pass. Reapply here in case Windows
# reset them during first boot. On Enterprise SKU, GP keys override
# Defender settings even with Tamper Protection.
Write-Host "==> Reinforcing Defender Group Policy registry keys"
$defenderPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
New-Item -Path $defenderPolicyPath -Force | Out-Null
Set-ItemProperty -Path $defenderPolicyPath -Name "DisableAntiSpyware" -Value 1 -Type DWord
Set-ItemProperty -Path $defenderPolicyPath -Name "DisableAntiVirus"   -Value 1 -Type DWord

$rtpPath = "$defenderPolicyPath\Real-Time Protection"
New-Item -Path $rtpPath -Force | Out-Null
Set-ItemProperty -Path $rtpPath -Name "DisableRealtimeMonitoring"    -Value 1 -Type DWord
Set-ItemProperty -Path $rtpPath -Name "DisableBehaviorMonitoring"    -Value 1 -Type DWord
Set-ItemProperty -Path $rtpPath -Name "DisableOnAccessProtection"    -Value 1 -Type DWord
Set-ItemProperty -Path $rtpPath -Name "DisableScanOnRealtimeEnable"  -Value 1 -Type DWord

$spynetPath = "$defenderPolicyPath\Spynet"
New-Item -Path $spynetPath -Force | Out-Null
Set-ItemProperty -Path $spynetPath -Name "DisableBlockAtFirstSeen" -Value 1  -Type DWord
Set-ItemProperty -Path $spynetPath -Name "SpynetReporting"         -Value 0  -Type DWord
Set-ItemProperty -Path $spynetPath -Name "SubmitSamplesConsent"    -Value 2  -Type DWord

# -------------------------------------------------------------------------
# 5. Disable SmartScreen
# -------------------------------------------------------------------------
Write-Host "==> Disabling SmartScreen"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String -ErrorAction SilentlyContinue

# -------------------------------------------------------------------------
# 6. Disable Windows Defender scheduled tasks
# -------------------------------------------------------------------------
Write-Host "==> Disabling Defender scheduled tasks"
$defenderTasks = @(
    "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance",
    "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup",
    "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan",
    "\Microsoft\Windows\Windows Defender\Windows Defender Verification"
)
foreach ($task in $defenderTasks) {
    try {
        Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
        Write-Host "  Disabled task: $task"
    } catch {
        Write-Host "  Task not found or already disabled: $task"
    }
}

# -------------------------------------------------------------------------
# 7. Disable Windows Security Center service
# -------------------------------------------------------------------------
Write-Host "==> Disabling SecurityHealthService"
try {
    Stop-Service  -Name "SecurityHealthService" -Force -ErrorAction SilentlyContinue
    Set-Service   -Name "SecurityHealthService" -StartupType Disabled -ErrorAction SilentlyContinue
} catch {
    Write-Host "  SecurityHealthService not running or already disabled"
}

# -------------------------------------------------------------------------
# 8. Verify current state
# -------------------------------------------------------------------------
Write-Host "==> Checking Defender status"
try {
    $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($status) {
        Write-Host "  AntivirusEnabled:          $($status.AntivirusEnabled)"
        Write-Host "  RealTimeProtectionEnabled: $($status.RealTimeProtectionEnabled)"
        Write-Host "  AMServiceEnabled:          $($status.AMServiceEnabled)"
    }
} catch {
    Write-Host "  Get-MpComputerStatus failed (Defender may be fully disabled)"
}

# Check exclusions
try {
    $prefs = Get-MpPreference -ErrorAction SilentlyContinue
    if ($prefs.ExclusionPath) {
        Write-Host "  Exclusion paths: $($prefs.ExclusionPath -join ', ')"
    }
} catch {
    Write-Host "  Could not query exclusion paths"
}

Write-Host "==> disable-defender complete (Phase 2)"
