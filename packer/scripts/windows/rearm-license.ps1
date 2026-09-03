<#
.SYNOPSIS
    Reset the Windows evaluation clock (#553).
.DESCRIPTION
    The 25H2 Enterprise Evaluation media we build from was released 2025-09-15
    and carries a shelf life of roughly a year, so the first image built from it
    on 2026-09-02 booted straight to:

        Windows 11 Enterprise Evaluation
        Windows License is expired

    That is not cosmetic. Once expired, the Windows License Manager Service
    shuts the guest down every hour -- analyses would be truncated at
    unpredictable points and it would read as sample behaviour, which is exactly
    the confound this rebuild exists to remove.

    ReArmWindows resets the evaluation period to 90 days. It can be used a
    limited number of times (0xC004D307 once exhausted). Failure here is NOT
    fatal: verify-license.ps1 decides whether the resulting state is usable, so
    a host that cannot re-arm fails on the fact rather than on the attempt.

    A restart is required for the new period to take effect.
#>
$ErrorActionPreference = 'Continue'

function Get-LicState {
    Get-CimInstance -ClassName SoftwareLicensingProduct -ErrorAction SilentlyContinue |
        Where-Object { $_.PartialProductKey -and $_.Name -like '*Windows*' } |
        Select-Object -First 1
}

$before = Get-LicState
if ($before) {
    Write-Output "==> before: LicenseStatus=$($before.LicenseStatus) grace=$($before.GracePeriodRemaining) min"
} else {
    Write-Output "==> before: no licensed Windows product found"
}

Write-Output "==> invoking ReArmWindows"
$r = Invoke-CimMethod -ClassName SoftwareLicensingService -MethodName ReArmWindows -ErrorAction SilentlyContinue
if ($null -ne $r) {
    Write-Output "    ReturnValue = $($r.ReturnValue) (0 = success)"
    if ($r.ReturnValue -ne 0) {
        Write-Output "    NOT fatal here -- verify-license.ps1 judges the resulting state."
        Write-Output "    0xC004D307 means the re-arm count is exhausted and the media needs replacing."
    }
} else {
    Write-Output "    ReArmWindows unavailable; falling back to slmgr"
    cscript //nologo "$env:SystemRoot\System32\slmgr.vbs" /rearm 2>&1 | ForEach-Object { "    $_" }
}
Write-Output "==> rearm-license complete (restart required to take effect)"
