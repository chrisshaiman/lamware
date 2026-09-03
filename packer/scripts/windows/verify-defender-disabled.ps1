<#
.SYNOPSIS
    Fails the build if Windows Defender is still active.
.DESCRIPTION
    On 2026-09-02 a base build reported success while disable-defender.ps1 had
    been blocked in its entirety by AMSI:

        This script contains malicious content and has been blocked by your
        antivirus software.
        + FullyQualifiedErrorId : ScriptContainedMaliciousContent

    Defender flagged the script that disables Defender, PowerShell exited 0
    anyway, and Packer moved on. The result was a detonation guest with live
    antivirus -- which quarantines samples and silently invalidates every
    analysis run against it.

    Nothing checked. This script is that check. It only READS state, so it does
    not trip AMSI itself, and it exits non-zero so Packer stops.
#>
$ErrorActionPreference = 'Continue'
$problems = @()

# 1. The service. Start=4 is disabled; the specialize pass sets this before
#    Tamper Protection comes up, and it is the load-bearing mechanism.
# INFORMATIONAL, not a failure. Windows resets Start=4 to 3 and runs the
# service even when policy has disabled the engine -- measured on 2026-09-02
# after the offline hive edit landed. What matters for detonation is whether
# the engine SCANS, which is asserted below. Failing on the service state was
# testing a proxy for that, and the proxy disagrees with the real thing.
$svcStart = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' `
    -Name Start -ErrorAction SilentlyContinue).Start
$svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
Write-Output "  WinDefend Start = $svcStart, status = $(if ($svc) { $svc.Status } else { 'absent' }) (informational)"

# 2. Group Policy keys from the specialize pass.
$gp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
foreach ($v in @('DisableAntiSpyware', 'DisableAntiVirus')) {
    $got = (Get-ItemProperty $gp -Name $v -ErrorAction SilentlyContinue).$v
    Write-Output "  $v = $got (1 = disabled)"
    if ($got -ne 1) { $problems += "$v=$got, expected 1" }
}

# 3. Real-time protection as the guest itself reports it. If the service is
#    genuinely off this cmdlet is unavailable, which is a PASS, not a failure.
$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($mp) {
    Write-Output "  RealTimeProtectionEnabled = $($mp.RealTimeProtectionEnabled)"
    Write-Output "  AntivirusEnabled          = $($mp.AntivirusEnabled)"
    # THE assertions. These are the engine itself reporting whether it scans.
    if ($mp.RealTimeProtectionEnabled) { $problems += "real-time protection is ON" }
    if ($mp.AntivirusEnabled)          { $problems += "antivirus engine is ON" }
    # AMServiceEnabled is INFORMATIONAL, not an assertion. It reports whether
    # the antimalware service host is loaded, which is the same proxy as
    # "WinDefend is Running" above -- and measured on 2026-09-03 it is True on a
    # guest reporting AntivirusEnabled=False and RealTimeProtectionEnabled=False.
    # The service being resident does not mean anything is being scanned, and
    # failing on it rejected an image that was correctly disabled.
    if ($mp.PSObject.Properties.Name -contains 'AMServiceEnabled') {
        Write-Output "  AMServiceEnabled          = $($mp.AMServiceEnabled) (informational)"
    }
    if ($mp.PSObject.Properties.Name -contains 'OnAccessProtectionEnabled' -and
        $mp.OnAccessProtectionEnabled) {
        $problems += "on-access protection is ON"
    }
} else {
    Write-Output "  Get-MpComputerStatus unavailable - consistent with a disabled engine"
}

if ($problems.Count -gt 0) {
    Write-Output ""
    Write-Output "==> DEFENDER IS STILL ACTIVE. This image cannot detonate malware."
    foreach ($p in $problems) { Write-Output "      - $p" }
    Write-Output ""
    Write-Output "    Phase 1 is autounattend.xml's specialize pass; phase 2 is"
    Write-Output "    disable-defender.ps1. Check the build log for"
    Write-Output "    ScriptContainedMaliciousContent, which means phase 2 never ran."
    exit 1
}
Write-Output "==> verify-defender-disabled: Defender is disabled"
