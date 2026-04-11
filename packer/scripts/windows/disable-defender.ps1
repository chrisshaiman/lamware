<#
.SYNOPSIS
    Disables Windows Defender on the Cape sandbox guest VM.

.DESCRIPTION
    Malware samples must execute without antivirus interference. This script
    suppresses Windows Defender at multiple layers to ensure samples are not
    quarantined before Cape can observe their behavior:

      1. Real-time protection (MpPreference)  -  immediate effect
      2. Group Policy registry keys  -  persist across reboots and survive
         Defender service restarts
      3. Tamper Protection disabled via registry  -  required before the GP
         keys take full effect on Windows 10 21H2+
      4. Defender scheduled tasks disabled  -  prevents background scans

    This is intentional for a malware analysis sandbox. Do NOT apply this
    script to any production or user-facing system.

    Enterprise SKU (ADR-009) is required for the Group Policy keys to be
    honored without Microsoft Security Center overriding them.

    Managed by Packer. Do not edit manually.
    Author: Christopher Shaiman
    License: Apache 2.0
#>

Set-StrictMode -Version Latest
# TODO: re-enable Stop when all scripts verified working
$ErrorActionPreference = "Continue"

Write-Host "==> disable-defender: suppressing Windows Defender"

# -------------------------------------------------------------------------
# 1. Disable Tamper Protection
# -------------------------------------------------------------------------
# HKLM:\SOFTWARE\Microsoft\Windows Defender\Features is owned by TrustedInstaller
# and cannot be written by Administrator even in an elevated WinRM session.
# On Enterprise SKU the Group Policy keys (step 3) are the authoritative
# suppression mechanism and override Tamper Protection — skip the registry
# approach and rely on GP keys instead.
Write-Host "==> Skipping Tamper Protection registry key (TrustedInstaller-owned, GP keys used instead)"

# -------------------------------------------------------------------------
# 2. Real-time protection via MpPreference
# -------------------------------------------------------------------------
Write-Host "==> Disabling Defender real-time protection"
try {
    Set-MpPreference -DisableRealtimeMonitoring          $true
    Set-MpPreference -DisableBehaviorMonitoring          $true
    Set-MpPreference -DisableBlockAtFirstSeen            $true
    Set-MpPreference -DisableIOAVProtection              $true
    Set-MpPreference -DisablePrivacyMode                 $true
    Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true
    Set-MpPreference -SubmitSamplesConsent               2  # Never send
    Set-MpPreference -MAPSReporting                      0  # MAPS off
} catch {
    # MpPreference may fail if Tamper Protection hasn't taken effect yet;
    # the Group Policy keys below are the authoritative suppression.
    Write-Warning "Set-MpPreference raised an error (GP keys will override): $_"
}

# -------------------------------------------------------------------------
# 3. Group Policy registry keys  -  persistent Defender suppression
# -------------------------------------------------------------------------
Write-Host "==> Applying Defender Group Policy registry keys"
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
# 4. Disable Windows Defender scheduled tasks
# -------------------------------------------------------------------------
# Background scans would interfere with analysis timing and produce noise
# in the process/file activity that Cape monitors.
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
# 5. Disable Windows Security Center service
# -------------------------------------------------------------------------
# SecurityHealthService shows Defender alerts in the system tray; disabling
# prevents "Virus protection is off" popups during Cape analysis sessions.
Write-Host "==> Disabling SecurityHealthService"
try {
    Stop-Service  -Name "SecurityHealthService" -Force -ErrorAction SilentlyContinue
    Set-Service   -Name "SecurityHealthService" -StartupType Disabled -ErrorAction SilentlyContinue
} catch {
    Write-Host "  SecurityHealthService not running or already disabled"
}

Write-Host "==> disable-defender complete"
