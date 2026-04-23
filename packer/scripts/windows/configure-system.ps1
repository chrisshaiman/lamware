<#
.SYNOPSIS
    System-level configuration for the Windows 10 Cape sandbox guest.

.DESCRIPTION
    Renames the computer to the Packer-supplied hostname (anti-evasion, ADR-012),
    disables services that interfere with malware analysis or waste build time,
    and configures power/sleep settings so the guest doesn't go idle during an
    analysis run.

    Managed by Packer. Do not edit manually.
    Author: Christopher Shaiman
    License: Apache 2.0
#>

Set-StrictMode -Version Latest
# TODO: re-enable Stop when all scripts verified working
$ErrorActionPreference = "Continue"

# Injected by Packer via environment_vars
$Hostname = $env:GUEST_HOSTNAME
if (-not $Hostname) {
    Write-Error "GUEST_HOSTNAME is not set"
    exit 1
}

Write-Host "==> configure-system: hostname=$Hostname"

# -------------------------------------------------------------------------
# 1. Rename computer
# -------------------------------------------------------------------------
# The autounattend.xml sets a placeholder name (DESKTOP-PKRBLD). This renames
# it to the real anti-evasion hostname. Restart is handled by the
# windows-restart provisioner that follows in the Packer build sequence.
$current = $env:COMPUTERNAME
if ($current -ne $Hostname) {
    Write-Host "==> Renaming computer: $current -> $Hostname"
    Rename-Computer -NewName $Hostname -Force
} else {
    Write-Host "==> Computer name already set to $Hostname, skipping rename"
}

# -------------------------------------------------------------------------
# 2. Disable Windows Update
# -------------------------------------------------------------------------
# Evaluation guests are ephemeral; updates during the build or analysis take
# hours and conflict with Defender disable steps. autounattend.xml already
# disables the service; belt-and-suspenders with Group Policy keys here.
Write-Host "==> Disabling Windows Update via Group Policy registry"
$wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
New-Item -Path $wuPath -Force | Out-Null
Set-ItemProperty -Path $wuPath -Name "NoAutoUpdate"    -Value 1 -Type DWord
Set-ItemProperty -Path $wuPath -Name "AUOptions"       -Value 1 -Type DWord  # Never check

$storePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
Set-ItemProperty -Path $storePath -Name "DisableWindowsUpdateAccess" -Value 1 -Type DWord

# -------------------------------------------------------------------------
# 3. Disable sleep and screensaver
# -------------------------------------------------------------------------
# A Cape analysis can run for up to an hour. Power management must not
# interrupt or lock the session during analysis.
Write-Host "==> Disabling sleep and screensaver"
powercfg /change monitor-timeout-ac 0
powercfg /change monitor-timeout-dc 0
powercfg /change disk-timeout-ac    0
powercfg /change disk-timeout-dc    0
powercfg /change standby-timeout-ac 0
powercfg /change standby-timeout-dc 0
powercfg /change hibernate-timeout-ac 0
powercfg /change hibernate-timeout-dc 0

# Screensaver via registry
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -Value "0"

# -------------------------------------------------------------------------
# 4. Disable Action Center / security notifications
# -------------------------------------------------------------------------
# Popups and tray notifications would appear in Cape's guest screenshots
# and make the environment look obviously fresh/managed.
Write-Host "==> Suppressing Action Center notifications"
$acPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
New-Item -Path $acPath -Force | Out-Null
Set-ItemProperty -Path $acPath -Name "DisableNotificationCenter" -Value 1 -Type DWord

# -------------------------------------------------------------------------
# 5. Disable SmartScreen
# -------------------------------------------------------------------------
# SmartScreen blocks unknown executables with a prompt. For automated
# sandbox detonation, samples need to run without interactive prompts.
Write-Host "==> Disabling SmartScreen"
$ssPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
New-Item -Path $ssPath -Force | Out-Null
Set-ItemProperty -Path $ssPath -Name "EnableSmartScreen" -Value 0 -Type DWord

# -------------------------------------------------------------------------
# 6. Set timezone  -  Eastern Standard Time
# -------------------------------------------------------------------------
# Matches a common US corporate timezone. Malware that checks the locale
# should see a realistic US machine identity.
Write-Host "==> Setting timezone to Eastern Standard Time"
Set-TimeZone -Id "Eastern Standard Time"

# -------------------------------------------------------------------------
# 7. Disable Windows Firewall — all profiles
# -------------------------------------------------------------------------
# The sandbox guest needs all ports accessible from the host (cape-agent on
# 8000, resultserver callbacks). Windows classifies the detonation bridge
# as "Public" (most restrictive) because it has no gateway/DNS that matches
# a known network. Disabling the firewall on all profiles ensures the agent
# is reachable regardless of how Windows classifies the network.
Write-Host "==> Disabling Windows Firewall (all profiles)"
netsh advfirewall set allprofiles state off

# Also set via registry for persistence across profile changes
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" -Name "EnableFirewall" -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" -Name "EnableFirewall" -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" -Name "EnableFirewall" -Value 0

Write-Host "==> configure-system complete (restart required for hostname change)"
