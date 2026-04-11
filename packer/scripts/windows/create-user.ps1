<#
.SYNOPSIS
    Creates a realistic local user account on the Cape sandbox guest.

.DESCRIPTION
    Malware that enumerates local accounts should see a realistic user (ADR-012).
    Names like "admin", "sandbox", "analyst", or "malware" are IOCs used by
    malware to detect analysis environments.

    This script:
      1. Creates a local account (GUEST_USERNAME, e.g. "jsmith")
      2. Adds the account to the local Administrators group (many samples
         require admin privileges to install services, modify registry, etc.)
      3. Sets the account to never expire (evaluation guests are ephemeral;
         Windows account expiry is not relevant)
      4. Creates the user profile directory structure by triggering a
         silent logon (so Documents/Downloads/Desktop exist for decoy files)
      5. Configures autologon to use the new account (not Administrator) so
         the guest desktop looks like a normal user session

    The Administrator build account is left enabled for the remainder of the
    Packer build (cleanup.ps1 disables it). Packer's WinRM session remains as
    Administrator throughout.

    Managed by Packer. Do not edit manually.
    Author: Christopher Shaiman
    License: Apache 2.0
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Username = $env:GUEST_USERNAME
$Password = $env:GUEST_PASSWORD
if (-not $Username) {
    Write-Error "GUEST_USERNAME is not set"
    exit 1
}
if (-not $Password) {
    Write-Error "GUEST_PASSWORD is not set"
    exit 1
}

Write-Host "==> create-user: creating local account '$Username'"

# -------------------------------------------------------------------------
# 1. Create local user account
# -------------------------------------------------------------------------
$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force

# Remove existing account if present (idempotent re-runs during build debug)
if (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue) {
    Write-Host "==> Account '$Username' already exists, removing and recreating"
    Remove-LocalUser -Name $Username
}

New-LocalUser `
    -Name                  $Username `
    -Password              $SecurePassword `
    -FullName              "John Smith" `
    -Description           "" `
    -PasswordNeverExpires  `
    -UserMayNotChangePassword | Out-Null

Write-Host "==> Created account '$Username'"

# -------------------------------------------------------------------------
# 2. Add to local Administrators group
# -------------------------------------------------------------------------
Add-LocalGroupMember -Group "Administrators" -Member $Username
Write-Host "==> Added '$Username' to Administrators"

# -------------------------------------------------------------------------
# 3. Create user profile by running a brief silent logon command
# -------------------------------------------------------------------------
# Windows defers profile directory creation until first login. We need the
# profile to exist so create-decoy-files.ps1 can write to Documents/etc.
# Using 'runas /netonly' isn't reliable in non-interactive builds; instead
# we use New-PSDrive to trigger a background logon that creates the profile.
# A simpler guaranteed approach: start a hidden process as the user.
Write-Host "==> Creating user profile for '$Username'"
$profilePath = "C:\Users\$Username"

if (-not (Test-Path $profilePath)) {
    # Schedule a dummy task as the user  -  Windows creates the profile when
    # the task runs, then we immediately delete the task.
    $taskName   = "CreateProfile_$Username"
    $secPwd     = $Password
    $action     = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c exit"
    $settings   = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 30)
    $trigger    = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)

    # -Principal and -Password are in separate parameter sets - cannot combine.
    # Use -User / -Password directly; RunLevel defaults to Limited.
    Register-ScheduledTask `
        -TaskName  $taskName `
        -Action    $action `
        -Settings  $settings `
        -Trigger   $trigger `
        -User      $Username `
        -Password  $secPwd `
        -Force | Out-Null

    # Wait for profile to be created (task runs, profile dir appears)
    $deadline = (Get-Date).AddSeconds(30)
    while (-not (Test-Path $profilePath) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 2
    }

    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

    if (Test-Path $profilePath) {
        Write-Host "==> Profile directory created: $profilePath"
    } else {
        # Fallback: create the standard folders manually if the task approach didn't work.
        # This is sufficient for decoy file placement even if the full profile hive is absent.
        Write-Host "==> Profile auto-creation timed out; creating directory structure manually"
        New-Item -ItemType Directory -Path "$profilePath\Desktop"   -Force | Out-Null
        New-Item -ItemType Directory -Path "$profilePath\Documents"  -Force | Out-Null
        New-Item -ItemType Directory -Path "$profilePath\Downloads"  -Force | Out-Null
        New-Item -ItemType Directory -Path "$profilePath\Pictures"   -Force | Out-Null
        New-Item -ItemType Directory -Path "$profilePath\Music"      -Force | Out-Null
        New-Item -ItemType Directory -Path "$profilePath\Videos"     -Force | Out-Null
    }
} else {
    Write-Host "==> Profile directory already exists: $profilePath"
}

# -------------------------------------------------------------------------
# 4. Configure autologon for the guest user account
# -------------------------------------------------------------------------
# Cape boots the VM from snapshot and immediately connects to cape-agent.py.
# The guest should auto-login to the user account so the desktop environment
# is running (some malware checks for an active desktop session).
Write-Host "==> Configuring autologon for '$Username'"
$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $winlogonPath -Name "AutoAdminLogon"    -Value "1"
Set-ItemProperty -Path $winlogonPath -Name "DefaultUserName"   -Value $Username
Set-ItemProperty -Path $winlogonPath -Name "DefaultPassword"   -Value $Password
Set-ItemProperty -Path $winlogonPath -Name "DefaultDomainName" -Value $env:COMPUTERNAME

Write-Host "==> create-user complete"
