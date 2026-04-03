<#
.SYNOPSIS
    Installs LibreOffice and configures it for malware document detonation.

.DESCRIPTION
    LibreOffice is the Office-compatible application in the `office` sandbox
    snapshot (ADR-013). It handles .doc, .docm, .xls, .xlsm, and .odt files
    with reasonable VBA macro compatibility.

    This script:
      1. Downloads the LibreOffice MSI installer from the Document Foundation CDN
      2. Installs silently (no UI, no reboot)
      3. Sets macro security to LOW for all users — macros must execute without
         prompting for automated detonation to work
      4. Registers LibreOffice as the default file handler for Office formats
         via registry (so double-clicked samples open in LibreOffice, not Notepad)

    Macro security setting (critical for detonation):
      LibreOffice stores macro security level in the user profile's
      registrymodifications.xcu. Level 0 (LOW) runs all macros without any
      confirmation dialog. This is intentional for a sandbox environment where
      automated execution is the goal.

    LIBREOFFICE_VERSION and GUEST_USERNAME are injected by Packer.

    Managed by Packer. Do not edit manually.
    Author: Christopher Shaiman
    License: Apache 2.0
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$LibreOfficeVersion  = $env:LIBREOFFICE_VERSION
$LibreOfficeChecksum = $env:LIBREOFFICE_CHECKSUM
$GuestUsername       = $env:GUEST_USERNAME
if (-not $LibreOfficeVersion) {
    Write-Error "LIBREOFFICE_VERSION is not set. Set both LIBREOFFICE_VERSION and LIBREOFFICE_CHECKSUM together in packer.auto.pkrvars.hcl."
    exit 1
}
if (-not $LibreOfficeChecksum) {
    Write-Error "LIBREOFFICE_CHECKSUM is not set. Find the SHA-256 hash on the LibreOffice download page (Checksum column) for the version you are installing."
    exit 1
}
if (-not $GuestUsername) { $GuestUsername = "jsmith" }

Write-Host "==> install-libreoffice: version=$LibreOfficeVersion user=$GuestUsername"

# -------------------------------------------------------------------------
# 1. Build download URL and fetch installer
# -------------------------------------------------------------------------
# LibreOffice CDN URL pattern:
#   https://download.documentfoundation.org/libreoffice/stable/<version>/win/x86_64/LibreOffice_<version>_Win_x86-64.msi
$MsiName  = "LibreOffice_${LibreOfficeVersion}_Win_x86-64.msi"
$Url      = "https://download.documentfoundation.org/libreoffice/stable/$LibreOfficeVersion/win/x86_64/$MsiName"
$TmpMsi   = "C:\Windows\Temp\$MsiName"

Write-Host "==> Downloading $Url"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $Url -OutFile $TmpMsi -UseBasicParsing

if (-not (Test-Path $TmpMsi)) {
    Write-Error "LibreOffice MSI not found after download: $TmpMsi"
    exit 1
}
Write-Host "==> Downloaded $('{0:N0}' -f (Get-Item $TmpMsi).Length) bytes"

# -------------------------------------------------------------------------
# Verify SHA-256 hash — supply chain integrity check
# -------------------------------------------------------------------------
$actualHash = (Get-FileHash -Path $TmpMsi -Algorithm SHA256).Hash.ToLower()
if ($actualHash -ne $LibreOfficeChecksum.ToLower()) {
    Write-Error "LibreOffice MSI hash mismatch!`n  Expected: $LibreOfficeChecksum`n  Actual:   $actualHash`nThis may indicate a compromised download. Aborting."
    Remove-Item -Path $TmpMsi -Force
    exit 1
}
Write-Host "==> LibreOffice MSI hash verified: $actualHash"

# -------------------------------------------------------------------------
# 2. Install LibreOffice silently
# -------------------------------------------------------------------------
# /qn      — quiet, no UI
# /norestart — do not reboot (we handle image shutdown explicitly)
# REBOOT=ReallySuppress — belt-and-suspenders reboot suppression
# UI_LANGS=en_US — English only; no need for additional language packs
Write-Host "==> Installing LibreOffice"
$msiArgs = @(
    "/qn",
    "/i", $TmpMsi,
    "/norestart",
    "REBOOT=ReallySuppress",
    "UI_LANGS=en_US"
)
$proc = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
    # 3010 = success, restart required (suppressed above — treat as success)
    Write-Error "LibreOffice installer exited with code $($proc.ExitCode)"
    exit 1
}
Write-Host "==> LibreOffice installed (exit code $($proc.ExitCode))"

# Verify the install directory exists
$LoInstallDir = "${env:ProgramFiles}\LibreOffice"
if (-not (Test-Path $LoInstallDir)) {
    # Try the x86 path (shouldn't happen for x86-64 installer, but be defensive)
    $LoInstallDir = "${env:ProgramFiles(x86)}\LibreOffice"
}
if (-not (Test-Path $LoInstallDir)) {
    Write-Error "LibreOffice install directory not found after install"
    exit 1
}
Write-Host "==> Verified install directory: $LoInstallDir"

# -------------------------------------------------------------------------
# 3. Set macro security to LOW for the guest user
# -------------------------------------------------------------------------
# LibreOffice reads macro security level from the user profile's
# registrymodifications.xcu on startup. We write this file for the guest
# user so that when Cape submits a document sample, VBA/Basic macros run
# without any dialog prompting for confirmation.
#
# Security level values:
#   0 = Low  (run all macros — required for detonation)
#   1 = Medium (prompt for unsigned macros)
#   2 = High (signed macros only)
#   3 = Very High (no macros)
Write-Host "==> Setting LibreOffice macro security to LOW for $GuestUsername"

$LoUserConfigDir = "C:\Users\$GuestUsername\AppData\Roaming\LibreOffice\4\user"
New-Item -ItemType Directory -Path $LoUserConfigDir -Force | Out-Null

$MacroSecurityXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<oor:items xmlns:oor="http://openoffice.org/2001/registry"
           xmlns:xs="http://www.w3.org/2001/XMLSchema"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

  <!-- Macro security: LOW (level 0) — runs all macros without prompting.
       Required for automated malware document detonation in the Cape sandbox.
       DO NOT use this setting on any non-sandboxed system. -->
  <item oor:path="/org.openoffice.Office.Common/Security/Scripting">
    <prop oor:name="MacroSecurityLevel" oor:op="fuse" oor:type="xs:int">
      <value>0</value>
    </prop>
  </item>

  <!-- Disable "Document contains macros" warning dialog -->
  <item oor:path="/org.openoffice.Office.Common/Security/Scripting">
    <prop oor:name="WarnAlienBasic" oor:op="fuse" oor:type="xs:boolean">
      <value>false</value>
    </prop>
  </item>

  <!-- Disable macro confirmation on document open -->
  <item oor:path="/org.openoffice.Office.Common/Security/Scripting">
    <prop oor:name="DisableMacros" oor:op="fuse" oor:type="xs:boolean">
      <value>false</value>
    </prop>
  </item>

</oor:items>
"@

$XcuPath = "$LoUserConfigDir\registrymodifications.xcu"
Set-Content -Path $XcuPath -Value $MacroSecurityXml -Encoding UTF8
Write-Host "==> Macro security config written to $XcuPath"

# -------------------------------------------------------------------------
# 4. Register LibreOffice as default handler for Office document formats
# -------------------------------------------------------------------------
# When Cape submits a sample by opening it, the OS needs to know which
# application to launch. Without explicit file association, .doc/.xls files
# may open in WordPad or Notepad instead of LibreOffice.
#
# HKCU:\...\UserChoice is protected by a hash on Windows 10 1803+ — direct
# writes are silently reverted. Instead we write to HKLM:\SOFTWARE\Classes,
# which sets system-level defaults with no hash protection and applies to all
# users including the guest account.
Write-Host "==> Registering system-level file associations (HKLM:\SOFTWARE\Classes)"

# Map of extension -> ProgID
# ProgIDs are registered by the LibreOffice MSI installer. We set the default
# value of the extension key so Windows resolves the ProgID on open.
$FileAssociations = @{
    ".doc"  = "LibreOffice.WriterDocument.1"
    ".docm" = "LibreOffice.WriterDocument.1"
    ".docx" = "LibreOffice.WriterDocument.1"
    ".xls"  = "LibreOffice.CalcSpreadsheet.1"
    ".xlsm" = "LibreOffice.CalcSpreadsheet.1"
    ".xlsx" = "LibreOffice.CalcSpreadsheet.1"
    ".odt"  = "LibreOffice.WriterDocument.1"
    ".ods"  = "LibreOffice.CalcSpreadsheet.1"
    ".ppt"  = "LibreOffice.ImpressPresentation.1"
    ".pptx" = "LibreOffice.ImpressPresentation.1"
    ".odp"  = "LibreOffice.ImpressPresentation.1"
}

foreach ($ext in $FileAssociations.Keys) {
    $progId  = $FileAssociations[$ext]
    $extKey  = "HKLM:\SOFTWARE\Classes\$ext"
    try {
        # Set the default ProgID for this extension at the system level
        if (-not (Test-Path $extKey)) { New-Item -Path $extKey -Force | Out-Null }
        Set-ItemProperty -Path $extKey -Name "(Default)" -Value $progId
        Write-Host "  Associated $ext -> $progId"
    } catch {
        Write-Warning "Could not set association for $ext : $_"
    }
}

# -------------------------------------------------------------------------
# 5. Remove installer temp file
# -------------------------------------------------------------------------
Remove-Item -Path $TmpMsi -Force
Write-Host "==> install-libreoffice complete"
