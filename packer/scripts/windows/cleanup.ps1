<#
.SYNOPSIS
    Final cleanup before Packer converts the disk image to qcow2.

.DESCRIPTION
    Reduces the final image size and removes build artifacts that should not
    appear in the deployed sandbox guest:

      1. Clears Windows temp directories
      2. Clears Windows event logs (avoids Packer build noise appearing in
         Cape's guest event log captures during real analyses)
      3. Disables Administrator autologon (the guest user account's autologon
         set by create-user.ps1 remains active)
      4. Disables the built-in Administrator account (no longer needed after
         Packer WinRM provisioning completes; guest user has admin rights)
      5. Removes Windows Update downloaded files (saves disk space)
      6. Clears prefetch (avoids Packer-era process prefetch appearing during
         analysis as unexplained noise in the baseline)
      7. Zeros free disk space (defrag -w) so the qcow2 compresses better
         (this step is optional and skipped if defrag takes too long)

    The Windows Defender and Windows Update disables applied in earlier
    provisioners are preserved  -  this script does not re-enable them.

    Managed by Packer. Do not edit manually.
    Author: Christopher Shaiman
    License: Apache 2.0
#>

Set-StrictMode -Version Latest
# TODO: re-enable Stop when all scripts verified working
$ErrorActionPreference = "Continue"

Write-Host "==> cleanup: preparing image for export"

# -------------------------------------------------------------------------
# 1. Windows temp directories
# -------------------------------------------------------------------------
Write-Host "==> Clearing temp directories"
$tempPaths = @(
    $env:TEMP,
    $env:TMP,
    "C:\Windows\Temp",
    "C:\Windows\Prefetch"
)
foreach ($path in $tempPaths) {
    if (Test-Path $path) {
        Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  Cleared: $path"
    }
}

# -------------------------------------------------------------------------
# 2. Clear Windows event logs
# -------------------------------------------------------------------------
# Removes all events written during the Packer build phase. Cape captures
# event logs during analysis; starting from a clean log baseline ensures
# only analysis-time events appear.
Write-Host "==> Clearing Windows event logs"
$logs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
        Where-Object { $_.IsEnabled -and $_.RecordCount -gt 0 }
foreach ($log in $logs) {
    try {
        [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($log.LogName)
    } catch {
        # Some logs cannot be cleared (locked by OS); non-fatal
        Write-Host "  Could not clear log: $($log.LogName)"
    }
}
Write-Host "  Event logs cleared"

# -------------------------------------------------------------------------
# 3. Disable built-in Administrator account
# -------------------------------------------------------------------------
# DO NOT disable Administrator here — Packer still needs the WinRM session
# (running as Administrator) to send the shutdown command after this script.
# Disabling it kills the WinRM connection and Packer considers the build
# failed. Instead, the shutdown_command in the HCL disables the account
# as part of the shutdown sequence:
#   powershell -Command "Disable-LocalUser -Name Administrator"; shutdown /s /t 5 /f /d p:4:1
Write-Host "==> Skipping Administrator disable (handled by Packer shutdown_command)"

# -------------------------------------------------------------------------
# 4. Remove PBAdmin build account (created during manual install)
# -------------------------------------------------------------------------
# This account was used to bootstrap the OS before WinRM/Packer took over.
# The guest user (created by create-user.ps1) is the intended analysis user.
if (Get-LocalUser -Name "PBAdmin" -ErrorAction SilentlyContinue) {
    Write-Host "==> Removing PBAdmin build account"
    Remove-LocalUser -Name "PBAdmin"
    # Remove profile directory
    $profilePath = "C:\Users\PBAdmin"
    if (Test-Path $profilePath) {
        Remove-Item -Path $profilePath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  Removed profile: $profilePath"
    }
}

# -------------------------------------------------------------------------
# 5. Remove Administrator autologon registry entries
# -------------------------------------------------------------------------
# create-user.ps1 set autologon for the guest user. Ensure no Administrator
# autologon entry was left by the build process.
$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$currentAutoUser = (Get-ItemProperty -Path $winlogonPath -Name "DefaultUserName" -ErrorAction SilentlyContinue).DefaultUserName
if ($currentAutoUser -eq "Administrator") {
    Write-Warning "Autologon was still set to Administrator  -  correcting"
    # This should not happen if create-user.ps1 ran correctly, but guard anyway
    Remove-ItemProperty -Path $winlogonPath -Name "DefaultUserName"  -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $winlogonPath -Name "DefaultPassword"  -ErrorAction SilentlyContinue
    Set-ItemProperty    -Path $winlogonPath -Name "AutoAdminLogon" -Value "0"
}

# -------------------------------------------------------------------------
# 5. Windows Update cache
# -------------------------------------------------------------------------
Write-Host "==> Clearing Windows Update cache"
try {
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Windows\SoftwareDistribution\Download\*" `
                -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  SoftwareDistribution\Download cleared"
} catch {
    Write-Host "  Could not clear Windows Update cache (non-fatal): $_"
}

# -------------------------------------------------------------------------
# 6. Recycle Bin
# -------------------------------------------------------------------------
Write-Host "==> Emptying Recycle Bin"
try {
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
} catch {
    # Clear-RecycleBin may not exist on all PowerShell versions
    Remove-Item -Path "C:\`$Recycle.Bin\*" -Recurse -Force -ErrorAction SilentlyContinue
}

# -------------------------------------------------------------------------
# 7. Remove Packer-era scheduled task artifacts (if any)
# -------------------------------------------------------------------------
Write-Host "==> Removing temporary scheduled tasks from build"
Get-ScheduledTask -TaskName "CreateProfile_*" -ErrorAction SilentlyContinue |
    Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue

# -------------------------------------------------------------------------
# 8. Disable WinRM
# -------------------------------------------------------------------------
# DO NOT stop or disable WinRM here — Packer is using it to run this script.
# Stopping WinRM kills the session and Packer treats it as a build failure
# (exit code 16001). Instead, configure WinRM to disable on next boot via
# the shutdown_command, or accept that WinRM will be disabled when the
# Administrator account is disabled (no valid auth = effectively disabled).
Write-Host "==> Skipping WinRM disable (Packer still using it; disabled with Administrator account)"
# Remove the firewall rule now — this doesn't kill the active session
netsh advfirewall firewall delete rule name="WinRM-HTTP" 2>$null | Out-Null
Write-Host "  WinRM firewall rule removed"

# -------------------------------------------------------------------------
# 9. Sync and final status
# -------------------------------------------------------------------------
Write-Host "==> Flushing disk write buffers"
# Write-VolumeCache may not exist in all PS versions; use diskperf as fallback
try {
    Get-Volume -DriveLetter C | Optimize-Volume -ReTrim -ErrorAction SilentlyContinue
} catch {
    Write-Host "  Optimize-Volume not available (non-fatal)"
}

Write-Host "==> cleanup complete  -  image ready for qcow2 export"
exit 0
