<#
.SYNOPSIS
    Creates plausible decoy files in the guest user's standard folders.

.DESCRIPTION
    Anti-evasion measure (ADR-012): malware that checks whether a machine
    looks "used" by enumerating files in Documents, Downloads, or Desktop
    should find a realistic mix of everyday files  -  not an empty profile
    that signals a fresh sandbox.

    Files are:
      - Benign plain text or minimal content stubs (no macros, no scripts)
      - Named to look like normal work products
      - Mixed dates (file timestamps set to realistic past dates)
      - Not identifiable as belonging to a real person

    Files are NOT:
      - Real documents with PII
      - Macro-enabled Office files (those would trigger Defender or Office warnings)
      - Anything that could be mistaken for actual sensitive data

    GUEST_USERNAME is injected by Packer from the build variable.

    Managed by Packer. Do not edit manually.
    Author: Christopher Shaiman
    License: Apache 2.0
#>

Set-StrictMode -Version Latest
# TODO: re-enable Stop when all scripts verified working
$ErrorActionPreference = "Continue"

$Username = $env:GUEST_USERNAME
if (-not $Username) { $Username = "jsmith" }

$ProfilePath  = "C:\Users\$Username"
$DocumentsDir = "$ProfilePath\Documents"
$DownloadsDir = "$ProfilePath\Downloads"
$DesktopDir   = "$ProfilePath\Desktop"

Write-Host "==> create-decoy-files: populating profile for '$Username'"

foreach ($dir in @($DocumentsDir, $DownloadsDir, $DesktopDir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

# -------------------------------------------------------------------------
# Helper: write file and set a realistic past modification timestamp
# -------------------------------------------------------------------------
function New-DecoyFile {
    param(
        [string] $Path,
        [string] $Content,
        [int]    $DaysAgo = 30
    )
    Set-Content -Path $Path -Value $Content -Encoding UTF8
    $ts = (Get-Date).AddDays(-$DaysAgo)
    (Get-Item $Path).LastWriteTime  = $ts
    (Get-Item $Path).CreationTime   = $ts.AddDays(-5)
    (Get-Item $Path).LastAccessTime = $ts
}

# -------------------------------------------------------------------------
# Documents  -  work product files
# -------------------------------------------------------------------------
Write-Host "==> Creating Documents decoy files"

New-DecoyFile -Path "$DocumentsDir\Q3 Budget Review.txt" -DaysAgo 45 -Content @"
Q3 FY2024 Budget Review  -  Draft
Prepared by: J. Smith
Date: See file properties

Summary:
  - Travel: within 5% of forecast
  - Software licenses: renewal due Q4
  - Training: 2 staff certifications planned for Q4

Action items:
  1. Confirm headcount numbers with HR by end of month
  2. Submit renewal request for Adobe and Microsoft licenses
  3. Schedule Q4 planning meeting
"@

New-DecoyFile -Path "$DocumentsDir\Meeting Notes 2024-08-14.txt" -DaysAgo 60 -Content @"
Meeting: Weekly Sync
Date: August 14, 2024
Attendees: J. Smith, M. Johnson, S. Lee

Agenda:
  1. Project status updates
  2. Upcoming deadlines
  3. Open issues

Notes:
  - Project Alpha on track for September release
  - Need to finalize vendor contracts by Aug 30
  - M. Johnson will send updated timeline by EOD Friday

Next meeting: August 21, 2024
"@

New-DecoyFile -Path "$DocumentsDir\Home Network Setup.txt" -DaysAgo 120 -Content @"
Home Network  -  Setup Notes

Router: TP-Link Archer AX21
  - Admin page: 192.168.0.1
  - Firmware updated: Jan 2024

Devices:
  - Desktop (ethernet)
  - Laptop (wifi, 5 GHz)
  - Smart TV (wifi)
  - Ring doorbell (2.4 GHz)

ISP: Comcast / Xfinity
  - Speed: 400/10 Mbps
  - Modem: Arris SB8200

Backup: Google Drive (15 GB free tier)
"@

New-DecoyFile -Path "$DocumentsDir\Passwords_OLD.txt" -DaysAgo 200 -Content @"
** DO NOT USE  -  OUTDATED **
Old password hints (pre-2023)  -  all changed

email: [hint redacted] changed Feb 2023
bank: [hint redacted] changed Feb 2023
work VPN: set by IT, see helpdesk

Reminder: use LastPass for all current passwords
"@

New-DecoyFile -Path "$DocumentsDir\Resume_JSmith_2023.txt" -DaysAgo 300 -Content @"
John Smith
john.smith@email.com | (555) 867-5309

SUMMARY
Results-driven professional with 8+ years of experience in IT operations and
project coordination. Skilled in stakeholder communication, process improvement,
and cross-functional team collaboration.

EXPERIENCE
Senior IT Coordinator | Contoso Ltd | 2019 - Present
  - Managed desktop refresh program for 250 endpoints
  - Reduced ticket backlog by 40% through process automation
  - Coordinated with vendors for annual software licensing

IT Support Specialist | Fabrikam Inc | 2016 - 2019
  - Tier 1/2 helpdesk support (phone and in-person)
  - Active Directory user provisioning and GPO management

EDUCATION
B.S. Information Technology | State University | 2015

CERTIFICATIONS
CompTIA A+ | CompTIA Network+ | ITIL Foundation
"@

# -------------------------------------------------------------------------
# Downloads  -  typical downloaded content
# -------------------------------------------------------------------------
Write-Host "==> Creating Downloads decoy files"

New-DecoyFile -Path "$DownloadsDir\7z2301-x64.exe.txt" -DaysAgo 90 -Content @"
[This is a placeholder representing a previously downloaded installer]
7-Zip 23.01 (x64) installer  -  downloaded from 7-zip.org
SHA256: verified before install
Installed: yes  -  can delete
"@
# Rename to look like an actual file (no extension change needed for the stub)

New-DecoyFile -Path "$DownloadsDir\VPN_Setup_Guide.txt" -DaysAgo 75 -Content @"
Company VPN Setup  -  Quick Reference
IT Help Desk | Last updated: July 2024

Step 1: Download the Cisco Anyconnect client from the IT portal
Step 2: Install with default settings
Step 3: Enter server: vpn.contoso.com
Step 4: Authenticate with your domain credentials + MFA token
Step 5: Connect  -  full tunnel mode by default

Troubleshooting:
  - If connection drops: restart AnyConnect service (services.msc)
  - For persistent issues: call IT helpdesk ext. 1234
"@

New-DecoyFile -Path "$DownloadsDir\amazon_order_117-8234521-9841004.txt" -DaysAgo 40 -Content @"
Amazon.com Order Confirmation
Order #117-8234521-9841004
Placed: [see email]

Items:
  1x Logitech M720 Triathlon Mouse - `$49.99
  1x USB-C Hub 7-in-1              - `$32.99

Shipping: FREE
Estimated delivery: 2 business days

Questions? Visit amazon.com/orders
"@

New-DecoyFile -Path "$DownloadsDir\Chrome_Setup.exe.txt" -DaysAgo 180 -Content @"
[Download record  -  file installed and deleted]
Google Chrome installer  -  StandaloneSetup64.exe
Source: google.com/chrome
Version: 119.0
"@

# -------------------------------------------------------------------------
# Desktop  -  shortcuts and quick-reference items
# -------------------------------------------------------------------------
Write-Host "==> Creating Desktop decoy files"

New-DecoyFile -Path "$DesktopDir\TODO.txt" -DaysAgo 7 -Content @"
TODO - $(Get-Date -Format 'MMMM yyyy')

[ ] Expense report for conference travel
[ ] Follow up with vendor on contract renewal
[ ] Schedule 1:1 with manager
[ ] Update disaster recovery runbook
[x] Submit timesheet
[x] Complete security awareness training
"@

New-DecoyFile -Path "$DesktopDir\Notes.txt" -DaysAgo 3 -Content @"
Quick notes

Call Mark back re: project timeline  -  he said Q4 is tight
IT ticket #45821  -  laptop battery replacement (approved)
Parking: garage B, level 3 this week
Conference bridge: 1-888-555-0100 code 492817#
"@

Write-Host "==> create-decoy-files complete"
