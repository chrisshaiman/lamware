<#
.SYNOPSIS
    Fail the build if Windows is not in a usable licence state (#553).
.DESCRIPTION
    The first 25H2 image shipped with "Windows License is expired" and nobody
    noticed until the guest was screenshotted after being staged on the sandbox.
    An expired guest is shut down hourly by the Windows License Manager Service,
    which truncates analyses unpredictably.

    Reads state only. LicenseStatus values:
        0 Unlicensed   1 Licensed        2 OOB grace   3 OOT grace
        4 Non-genuine  5 Notification    6 Extended grace

    A grace period is fine for a lab guest -- that is what an evaluation IS.
    Unlicensed, non-genuine and notification are not.
#>
$ErrorActionPreference = 'Continue'

$p = Get-CimInstance -ClassName SoftwareLicensingProduct -ErrorAction SilentlyContinue |
    Where-Object { $_.PartialProductKey -and $_.Name -like '*Windows*' } |
    Select-Object -First 1

if (-not $p) {
    Write-Output "==> NO LICENSED WINDOWS PRODUCT FOUND."
    Write-Output "    Expected an evaluation product with a PartialProductKey."
    exit 1
}

$names = @{ 0 = 'Unlicensed'; 1 = 'Licensed'; 2 = 'OOB grace'; 3 = 'OOT grace'
            4 = 'Non-genuine'; 5 = 'Notification'; 6 = 'Extended grace' }
$status = [int]$p.LicenseStatus
$days = [math]::Round($p.GracePeriodRemaining / 1440, 1)
Write-Output "  product     = $($p.Name)"
Write-Output "  LicenseStatus = $status ($($names[$status]))"
Write-Output "  grace remaining = $days days"

$ok = @(1, 2, 3, 6)
if ($ok -notcontains $status) {
    Write-Output ""
    Write-Output "==> WINDOWS IS NOT USABLY LICENSED (status $status = $($names[$status]))."
    Write-Output "    An expired guest is shut down hourly by WLMS, which truncates"
    Write-Output "    analyses at unpredictable points and reads as sample behaviour."
    Write-Output "    If rearm-license.ps1 reported 0xC004D307 the re-arm count is"
    Write-Output "    exhausted and the evaluation media must be replaced (#553)."
    exit 1
}

# A grace state with almost no time left will expire mid-corpus.
if ($status -ne 1 -and $days -lt 30) {
    Write-Output ""
    Write-Output "==> ONLY $days DAYS OF GRACE REMAIN."
    Write-Output "    The image would expire during a sweep. Re-arm or replace the media."
    exit 1
}
Write-Output "==> verify-license: Windows is usably licensed"
