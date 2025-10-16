***

# README – MSRC CVE Patch Compliance Script

***

## Overview

This PowerShell script automates **Microsoft Security Response Center (MSRC) CVE verification and patch compliance** across Intune-managed Windows 11 devices integrated with ConnectWise Control (ScreenConnect).

It connects to the MSRC API to retrieve vulnerability data, MS Graph to enumerate recent Intune devices, and the ConnectWise Control API to check live systems for the specified patch (KB). The result is a list of devices that are patched or unpatched based on the selected CVE.

***

## Features

- Queries the **MSRC Security Updates API** for current or custom month/year bulletins.  
- Prompts for a specific **CVE ID** and retrieves related **Windows 11 remediations (KBs)**.  
- Connects to **Microsoft Graph API** to list Intune devices active within the last 15 days.  
- Maps each Intune device’s OS version to **Windows 11 release codes** (21H2 / 22H2 / 23H2 / 24H2).  
- Connects to **ConnectWise Control** and executes `Get-Hotfix` remotely to verify patch presence.  
- Exports compliance results to text files:
  - `patched<CVE>.txt`
  - `unpatched<CVE>.txt`

***

## Prerequisites

Before running this script, install and import the following PowerShell modules:

```powershell
Install-Module Microsoft.Graph
Import-Module Microsoft.Graph

Install-Module ConnectWiseControlAPI
Import-Module ConnectWiseControlAPI

Install-Module MsrcSecurityUpdates
Import-Module MsrcSecurityUpdates
```

Additional requirements:

- **Microsoft Graph permissions**: `Device.Read.All`, `DeviceManagementManagedDevices.Read.All`
- **Intune access**: Intune administrator or read-only scope
- **ConnectWise Control credentials**: account authorized for remote command execution (no MFA)
- **PowerShell 7+** recommended for performance and error handling

***

## Workflow

1. Script prompts if you wish to search the **current month’s MSRC report**.  
2. Optionally select another **month/year** (e.g., “Oct” and “2025”).  
3. The script fetches all vulnerabilities for that bulletin via **MSRC API**.  
4. You enter the desired **CVE ID**, and the script filters for **Windows 11** remediations.  
5. Authenticates to **Microsoft Graph** to retrieve all Intune devices synced within the past 15 days.  
6. Maps each device’s **OS version → release code (21H2–24H2)**.  
7. Connects to **ConnectWise Control** and runs `Get-Hotfix` on each registered system.
8. Checks if the reported **KB ID** for the CVE is installed.
9. Exports two result files to `C:\temp\`:
   - `patched<CVE>.txt` – devices with the KB present
   - `unpatched<CVE>.txt` – devices missing the KB

***

## Output Example

After execution, you will find files like:

```
C:\temp\patchedCVE-2025-12345.txt
C:\temp\unpatchedCVE-2025-12345.txt
```

Each file contains a simple list of device names and their patch status.

***

## Notes

- Windows 10 builds below `10.0.22000` are skipped (deprecated).  
- CVE-to-KB relationships for remediations are parsed directly from MSRC data.  
- The script uses pattern matching to handle build variations (e.g., `10.0.26*` for 24H2).

***

## References

- [ConnectWiseControlAPI by christaylorcodes](https://github.com/christaylorcodes/ConnectWiseControlAPI)
- [MSRC Microsoft Security Updates API](https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API)

***

## Author

**Blake Miller**  
Cybersecurity Professional – Infrastructure & Endpoint Compliance Automation

***
