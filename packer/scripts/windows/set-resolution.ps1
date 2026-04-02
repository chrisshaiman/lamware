<#
.SYNOPSIS
    Configures 1920x1080 screen resolution on the Cape sandbox guest.

.DESCRIPTION
    Anti-evasion measure (ADR-012): malware that queries screen dimensions
    via GetSystemMetrics(SM_CXSCREEN/SM_CYSCREEN) or EnumDisplaySettings
    should see a resolution consistent with a real corporate workstation.
    Low-resolution defaults (800x600, 1024x768) are a common VM detection IOC.

    Approach:
      - Set the resolution via CIM (Win32_VideoController + Change method) for
        immediate effect in the current session if a display adapter supports it
      - Write the preferred resolution to the standard VGA display adapter
        registry keys as a fallback that persists across reboots
      - The registry approach is the authoritative path since Packer builds
        headless (no live display to query); the resolution takes effect when
        Cape boots the VM from the snapshot with its configured display adapter

    Prerequisites: libvirt VM XML must use standard VGA with sufficient VRAM
    (>= 8 MB supports 1920x1080). The Ansible Cape role configures this.

    Managed by Packer. Do not edit manually.
    Author: Christopher Shaiman
    License: Apache 2.0
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$TargetWidth  = 1920
$TargetHeight = 1080
$TargetDepth  = 32

Write-Host "==> set-resolution: target=${TargetWidth}x${TargetHeight}@${TargetDepth}bpp"

# -------------------------------------------------------------------------
# 1. Attempt live resolution change via CIM
# -------------------------------------------------------------------------
# Will succeed in interactive (non-headless) builds; silently continues
# if there is no physical display adapter during Packer headless build.
try {
    $controller = Get-CimInstance -ClassName Win32_VideoController |
                  Select-Object -First 1

    if ($controller) {
        Write-Host "==> Video controller: $($controller.Name)"
        # Win32_VideoController has no direct Change method. Use the
        # pinvoke approach via a compiled C# snippet to call ChangeDisplaySettings.
        $changeDisplaySource = @"
using System;
using System.Runtime.InteropServices;

public class DisplayChanger {
    [StructLayout(LayoutKind.Sequential)]
    public struct DEVMODE {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string dmDeviceName;
        public short  dmSpecVersion;
        public short  dmDriverVersion;
        public short  dmSize;
        public short  dmDriverExtra;
        public int    dmFields;
        public int    dmPositionX;
        public int    dmPositionY;
        public int    dmDisplayOrientation;
        public int    dmDisplayFixedOutput;
        public short  dmColor;
        public short  dmDuplex;
        public short  dmYResolution;
        public short  dmTTOption;
        public short  dmCollate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string dmFormName;
        public short  dmLogPixels;
        public int    dmBitsPerPel;
        public int    dmPelsWidth;
        public int    dmPelsHeight;
        public int    dmDisplayFlags;
        public int    dmDisplayFrequency;
        public int    dmICMMethod;
        public int    dmICMIntent;
        public int    dmMediaType;
        public int    dmDitherType;
        public int    dmReserved1;
        public int    dmReserved2;
        public int    dmPanningWidth;
        public int    dmPanningHeight;
    }

    [DllImport("user32.dll")]
    public static extern int ChangeDisplaySettings(ref DEVMODE devMode, int flags);

    [DllImport("user32.dll")]
    public static extern bool EnumDisplaySettings(string deviceName, int modeNum, ref DEVMODE devMode);

    public static int Change(int width, int height, int bpp) {
        DEVMODE dm = new DEVMODE();
        dm.dmSize = (short)Marshal.SizeOf(dm);
        EnumDisplaySettings(null, -1, ref dm);
        dm.dmPelsWidth   = width;
        dm.dmPelsHeight  = height;
        dm.dmBitsPerPel  = bpp;
        dm.dmFields      = 0x80000 | 0x100000 | 0x40000; // width | height | bpp
        return ChangeDisplaySettings(ref dm, 0);
    }
}
"@
        Add-Type -TypeDefinition $changeDisplaySource -Language CSharp -ErrorAction SilentlyContinue
        $result = [DisplayChanger]::Change($TargetWidth, $TargetHeight, $TargetDepth)
        # Return values: 0 = DISP_CHANGE_SUCCESSFUL, 1 = restart required
        if ($result -eq 0 -or $result -eq 1) {
            Write-Host "==> Live resolution change result: $result (0=ok, 1=restart needed)"
        } else {
            Write-Host "==> Live resolution change returned $result (headless build; registry path will handle it)"
        }
    }
} catch {
    Write-Host "==> Live resolution change skipped (headless build): $_"
}

# -------------------------------------------------------------------------
# 2. Registry: set preferred resolution for the standard VGA display driver
# -------------------------------------------------------------------------
# These keys are read by the Windows display driver on startup. They ensure
# the resolution is correct when Cape boots the VM from snapshot regardless
# of the Packer build headless state.
#
# The registry path for the VGA display adapter varies by system (the GUID
# changes). We enumerate all video sub-keys and apply to each.
Write-Host "==> Writing preferred resolution to registry (display driver keys)"
$videoBasePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Video"

if (Test-Path $videoBasePath) {
    $adapterKeys = Get-ChildItem -Path $videoBasePath -ErrorAction SilentlyContinue
    foreach ($adapterKey in $adapterKeys) {
        $subKeys = Get-ChildItem -Path $adapterKey.PSPath -ErrorAction SilentlyContinue
        foreach ($subKey in $subKeys) {
            $keyPath = $subKey.PSPath
            Set-ItemProperty -Path $keyPath -Name "DefaultSettings.XResolution" -Value $TargetWidth  -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $keyPath -Name "DefaultSettings.YResolution" -Value $TargetHeight -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $keyPath -Name "DefaultSettings.BitsPerPel"  -Value $TargetDepth  -Type DWord -ErrorAction SilentlyContinue
            Write-Host "  Set resolution on: $keyPath"
        }
    }
} else {
    Write-Warning "Registry path $videoBasePath not found; display driver keys not set"
}

# -------------------------------------------------------------------------
# 3. Desktop background resolution hint (Control Panel display settings)
# -------------------------------------------------------------------------
# Some malware reads these user-level keys as a quick check.
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" `
    -Name "LogPixels"    -Value 96 -Type DWord -ErrorAction SilentlyContinue

Write-Host "==> set-resolution complete"
