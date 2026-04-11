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
$ErrorActionPreference = "Stop"

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
# The Packer WinRM session is complete; Administrator is no longer needed.
# The guest user (created by create-user.ps1) is a local admin and has
# autologon configured.
Write-Host "==> Disabling built-in Administrator account"
Disable-LocalUser -Name "Administrator"

# -------------------------------------------------------------------------
# 4. Remove Administrator autologon registry entries
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
# WinRM was enabled during the Packer build phase so provisioner scripts
# could run. The final guest image does not need it  -  Cape communicates
# with the guest via the cape-agent.py scheduled task on port 8000, not WinRM.
# Leaving WinRM enabled (port 5985, basic auth, unencrypted) is unnecessary
# attack surface on the detonation bridge during analysis.
Write-Host "==> Disabling WinRM"
try {
    Stop-Service -Name WinRM -Force -ErrorAction SilentlyContinue
    Set-Service  -Name WinRM -StartupType Disabled
    # Remove the firewall rules added by autounattend.xml FirstLogonCommands
    netsh advfirewall firewall delete rule name="WinRM-HTTP" | Out-Null
    Write-Host "  WinRM stopped, disabled, and firewall rule removed"
} catch {
    Write-Host "  WinRM disable raised an error (non-fatal): $_"
}

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
