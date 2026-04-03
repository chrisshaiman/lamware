<#
.SYNOPSIS
    Installs cape-agent.py (the CAPEv2 in-guest agent) on the sandbox guest.

.DESCRIPTION
    The Cape agent is a lightweight Python REST server that runs inside the
    guest VM. The Cape host communicates with it over port 8000 to:
      - Upload the malware sample
      - Execute the sample
      - Collect process memory dumps, network captures, and screenshots

    This script:
      1. Downloads agent.py from the CAPEv2 GitHub repository (raw)
      2. Installs it to C:\cape-agent\agent.py
      3. Creates a Windows Scheduled Task that starts agent.py at system
         startup under the SYSTEM account, before any user logs in

    The Scheduled Task uses SYSTEM rather than a named user so the agent is
    running before Cape sends its first command (Cape connects immediately
    after the guest boots from snapshot).

    Port 8000 is already allowed in the Windows Firewall by autounattend.xml.

    Design decision: cape-agent.py (ADR-010). capemon DLL injection is deferred
    until CPUID/timing evasion is observed in the wild requiring kernel-level hooks.

    Managed by Packer. Do not edit manually.
    Author: Christopher Shaiman
    License: Apache 2.0
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "==> install-cape-agent: downloading and installing agent.py"

$AgentDir  = "C:\cape-agent"
$AgentPath = "$AgentDir\agent.py"
$PythonExe = "C:\Python3\python.exe"

# Pin to a specific commit to prevent supply chain attacks. agent.py runs as
# SYSTEM and listens on a network port — it is the most sensitive binary in
# the guest. Update the commit SHA and checksum together when upgrading Cape.
#
# To get these values:
#   1. Browse https://github.com/kevoreilly/CAPEv2/commits/master/agent/agent.py
#   2. Pick the commit SHA you want to pin to
#   3. Download agent.py at that commit and compute its SHA-256:
#        curl -sL https://raw.githubusercontent.com/kevoreilly/CAPEv2/<commit>/agent/agent.py | sha256sum
#   4. Set both values in packer.auto.pkrvars.hcl
$AgentCommit   = $env:CAPE_AGENT_COMMIT
$AgentChecksum = $env:CAPE_AGENT_SHA256
if (-not $AgentCommit) {
    Write-Error "CAPE_AGENT_COMMIT is not set — must be a CAPEv2 repo commit SHA"
    exit 1
}
if (-not $AgentChecksum) {
    Write-Error "CAPE_AGENT_SHA256 is not set — must be the SHA-256 hash of agent.py at that commit"
    exit 1
}

$AgentUrl  = "https://raw.githubusercontent.com/kevoreilly/CAPEv2/$AgentCommit/agent/agent.py"

# -------------------------------------------------------------------------
# 1. Create install directory
# -------------------------------------------------------------------------
New-Item -ItemType Directory -Path $AgentDir -Force | Out-Null

# -------------------------------------------------------------------------
# 2. Download agent.py
# -------------------------------------------------------------------------
Write-Host "==> Downloading $AgentUrl"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $AgentUrl -OutFile $AgentPath -UseBasicParsing

if (-not (Test-Path $AgentPath)) {
    Write-Error "agent.py not found after download"
    exit 1
}
Write-Host "==> agent.py saved to $AgentPath"

# -------------------------------------------------------------------------
# 3. Verify SHA-256 hash — supply chain integrity check
# -------------------------------------------------------------------------
$actualHash = (Get-FileHash -Path $AgentPath -Algorithm SHA256).Hash.ToLower()
if ($actualHash -ne $AgentChecksum.ToLower()) {
    Write-Error "agent.py hash mismatch!`n  Expected: $AgentChecksum`n  Actual:   $actualHash`nThis may indicate a compromised download. Aborting."
    Remove-Item -Path $AgentPath -Force
    exit 1
}
Write-Host "==> agent.py hash verified: $actualHash"

# -------------------------------------------------------------------------
# 4. Verify agent.py is valid Python syntax
# -------------------------------------------------------------------------
$checkResult = & $PythonExe -m py_compile $AgentPath 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "agent.py failed syntax check: $checkResult"
    exit 1
}
Write-Host "==> agent.py syntax OK"

# -------------------------------------------------------------------------
# 5. Create a Scheduled Task to start agent.py at boot (SYSTEM account)
# -------------------------------------------------------------------------
# Using the Scheduled Task API rather than a registry Run key so that the
# agent starts before any user session begins (important for Cape to connect
# immediately after the VM boots from snapshot).
#
# Task settings:
#   - Trigger: AtStartup (fires when the OS finishes loading, before logon)
#   - RunLevel: Highest (administrative privileges — sample analysis requires it)
#   - ExecutionTimeLimit: PT0S (unlimited — agent runs for the duration of analysis)
#   - Hidden: true (no window in Task Manager's visible processes)

Write-Host "==> Creating Scheduled Task for Cape agent"
$TaskName   = "CapeAgent"
$TaskDesc   = "CAPEv2 in-guest analysis agent. Do not disable — required for malware detonation."
$Action     = New-ScheduledTaskAction `
                  -Execute    $PythonExe `
                  -Argument   $AgentPath `
                  -WorkingDirectory $AgentDir
$Trigger    = New-ScheduledTaskTrigger -AtStartup
$Principal  = New-ScheduledTaskPrincipal `
                  -UserId    "SYSTEM" `
                  -RunLevel  Highest `
                  -LogonType ServiceAccount
$Settings   = New-ScheduledTaskSettingsSet `
                  -Hidden `
                  -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
                  -MultipleInstances  IgnoreNew `
                  -RestartCount       3 `
                  -RestartInterval    (New-TimeSpan -Minutes 1)

Register-ScheduledTask `
    -TaskName   $TaskName `
    -Description $TaskDesc `
    -Action     $Action `
    -Trigger    $Trigger `
    -Principal  $Principal `
    -Settings   $Settings `
    -Force | Out-Null

Write-Host "==> Scheduled Task '$TaskName' registered"

# -------------------------------------------------------------------------
# 6. Verify the task was registered correctly
# -------------------------------------------------------------------------
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if (-not $task) {
    Write-Error "Scheduled Task '$TaskName' not found after registration"
    exit 1
}
Write-Host "==> Task state: $($task.State)"

Write-Host "==> install-cape-agent complete"
