<#
.SYNOPSIS
    Installs Python 3 on the Cape sandbox guest.

.DESCRIPTION
    cape-agent.py (the in-guest Cape communication agent) requires Python 3.
    This script downloads the Python installer from python.org, installs it
    silently to C:\Python3, and adds it to the system PATH.

    The PYTHON_VERSION environment variable is injected by Packer from the
    var.python_version build variable. Default: 3.11.9.

    pip is upgraded so that cape-agent.py can install any additional deps
    it needs (e.g., requests, pillow) without hitting version conflicts.

    Managed by Packer. Do not edit manually.
    Author: Christopher Shaiman
    License: Apache 2.0
#>

Set-StrictMode -Version Latest
# TODO: re-enable Stop when all scripts verified working
$ErrorActionPreference = "Continue"

$PythonVersion  = $env:PYTHON_VERSION
$PythonChecksum = $env:PYTHON_CHECKSUM
if (-not $PythonVersion) {
    Write-Error "PYTHON_VERSION is not set. Set both PYTHON_VERSION and PYTHON_CHECKSUM together in packer.auto.pkrvars.hcl."
    exit 1
}
if (-not $PythonChecksum) {
    Write-Error "PYTHON_CHECKSUM is not set. Find the SHA-256 hash on the Python release page alongside 'Windows installer (64-bit)' for the version you're installing."
    exit 1
}

Write-Host "==> install-python: version=$PythonVersion"

# -------------------------------------------------------------------------
# Build download URL
# -------------------------------------------------------------------------
# python.org URL pattern: python-3.11.9-amd64.exe
$InstallerName = "python-$PythonVersion-amd64.exe"
$Url           = "https://www.python.org/ftp/python/$PythonVersion/$InstallerName"
$TmpPath       = "C:\Windows\Temp\$InstallerName"
$InstallDir    = "C:\Python3"

Write-Host "==> Downloading $Url"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $Url -OutFile $TmpPath -UseBasicParsing

# -------------------------------------------------------------------------
# Verify SHA-256 hash  -  supply chain integrity check
# -------------------------------------------------------------------------
$actualHash = (Get-FileHash -Path $TmpPath -Algorithm SHA256).Hash.ToLower()
if ($actualHash -ne $PythonChecksum.ToLower()) {
    Write-Error "Python installer hash mismatch!`n  Expected: $PythonChecksum`n  Actual:   $actualHash`nThis may indicate a compromised download. Aborting."
    Remove-Item -Path $TmpPath -Force
    exit 1
}
Write-Host "==> Python installer hash verified: $actualHash"

# -------------------------------------------------------------------------
# Silent install
# -------------------------------------------------------------------------
# /quiet           -  no UI
# InstallAllUsers=1  -  system-wide (all users, not just current session)
# PrependPath=1    -  add Python and Scripts to system PATH
# TargetDir        -  predictable install location for cape-agent.ps1 to reference
Write-Host "==> Installing Python to $InstallDir"
$installArgs = @(
    "/quiet",
    "InstallAllUsers=1",
    "PrependPath=1",
    "Include_test=0",
    "Include_doc=0",
    "Include_launcher=1",
    "TargetDir=$InstallDir"
)
$proc = Start-Process -FilePath $TmpPath -ArgumentList $installArgs -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Error "Python installer exited with code $($proc.ExitCode)"
    exit 1
}
Write-Host "==> Python installed (exit code 0)"

# -------------------------------------------------------------------------
# Reload PATH so python/pip are available in this session
# -------------------------------------------------------------------------
$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("PATH", "User")

# -------------------------------------------------------------------------
# Verify
# -------------------------------------------------------------------------
$pyExe = "$InstallDir\python.exe"
if (-not (Test-Path $pyExe)) {
    Write-Error "python.exe not found at $pyExe after install"
    exit 1
}
$ver = & $pyExe --version 2>&1
Write-Host "==> Installed: $ver"

# -------------------------------------------------------------------------
# Upgrade pip
# -------------------------------------------------------------------------
Write-Host "==> Upgrading pip"
& $pyExe -m pip install --upgrade pip --quiet

# -------------------------------------------------------------------------
# Install packages required by cape-agent.py
# -------------------------------------------------------------------------
# Pillow: used by agent.py for screenshot capture (Cape uses this for evidence)
Write-Host "==> Installing cape-agent Python dependencies"
& $pyExe -m pip install --quiet Pillow

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------
Remove-Item -Path $TmpPath -Force
Write-Host "==> install-python complete"
