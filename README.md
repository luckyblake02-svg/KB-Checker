# DeviceKB_Check.ps1

## Overview

**DeviceKB_Check.ps1** is a PowerShell automation script built to help IT and security professionals cross-reference Microsoft CVEs and KB updates with live patch data from managed Windows devices. The script leverages three primary APIs:

- **Microsoft Graph API** – to query Intune-managed devices.
- **MSRC Security Updates API** – to retrieve CVE and remediation (patch) data.
- **ConnectWise Control API** – to remotely validate applied KB updates on devices[web:31][web:33][web:35].

By combining these integrations, the script provides an end-to-end workflow to identify unpatched systems, export vulnerability reports, and simplify patch compliance validation.

---

## Features

- Queries monthly **MSRC vulnerability catalogs** for CVE and KB relationships.
- Extracts and analyzes **Windows 11 remediation data** (21H2–24H2 build lines).
- Dynamically maps OS versions to four-character codes (e.g., 22H2, 23H2, 24H2).
- Integrates with **Microsoft Graph API** to gather Intune device inventory.
- Optionally imports CSV or **Active Directory** lists when Intune is unavailable.
- Uses **ConnectWise Control** (ScreenConnect) to remotely run “Get-HotFix” and verify patch installation.
- Produces separate reports for patched and unpatched systems, exported to `C:\Temp\[filename].txt`.

---

## Requirements

### PowerShell Modules

Install the following modules before running the script:

```
Install-Module Microsoft.Graph
Install-Module ConnectWiseControlAPI
Install-Module MsrcSecurityUpdates
```

### Permissions and Access

- **MS Graph**: Requires `Device.Read.All` and `DeviceManagementManagedDevices.Read.All` scopes.  
- **ConnectWise Control**: Use an account **without MFA** and HTTPS connectivity[web:31][web:33].
- **MSRC API**: No authentication required; uses Microsoft’s public `Get-MsrcCvrfDocument` endpoint.
- PowerShell 5.1+ (Windows) or PowerShell 7+ (cross-platform).

---

## Usage

Run the script directly or from an elevated PowerShell prompt.

```
.\DeviceKB_Check.ps1
```

You will be presented with a startup menu:

```
Welcome! What would you like to do

1: Map CVE patch status to computers.
2: Get Information on a specific CVE.
3: List all CVEs in a given month/year MSRC catalog.
4: List all CVEs fixed by a specific KB.
```

Each option triggers one of the following functions:

| Option | Function | Description |
|---------|-----------|-------------|
| 1 | `CVE2KB` | Maps a selected CVE to devices, retrieves KB fix, and checks patch status via ConnectWise |
| 2 | `CVEInfo` | Displays detailed CVE metadata, CVSS scores, FAQs, and remediation URLs |
| 3 | `CVEList` | Lists all CVEs for the selected MSRC month/year, with grid-view export |
| 4 | `KB2CVE` | Retrieves all CVEs fixed by a specific KB ID |

---

## Example Workflow

### 1. Identify Vulnerability
Search the MSRC catalog for a target CVE (e.g., CVE‑2025‑XXXX) using the **current month** or a specified date.

### 2. Retrieve Patch Information
The script maps the CVE to its corresponding KB update numbers for Windows 11 builds (e.g., KB5030213 for 23H2).

### 3. Query Devices
Choose between:
- **Intune Device List (Graph API)**  
- **CSV Import**
- **Active Directory Enumeration**

### 4. Verify Patching
If ConnectWise Control access is enabled, the script runs:
```
Get-HotFix
```
on each device and sorts them into:
- `C:\Temp\patched<CVE>.txt`
- `C:\Temp\unpatched<CVE>.txt`

---

## Output Files

The script saves results and logs to:

| File | Location | Description |
|------|-----------|-------------|
| `patched*.txt` | `C:\Temp\` | Devices with patch applied |
| `unpatched*.txt` | `C:\Temp\` | Devices missing patch |
| `debug.txt` | `C:\Temp\` | Logs of errors and status messages |
| `deviceList.csv` | `C:\Temp\` | Export of the final mapped devices if ConnectWise check skipped |

---

## Function Overview

| Function | Purpose |
|-----------|----------|
| `CVE2KB` | Pulls MSRC CVE, maps fix KBs, correlates device list, and triggers ConnectWise validation |
| `CWProbe` | Executes ConnectWise API `Invoke-CWCCommand` to gather hotfix data |
| `IntunePull` | Retrieves recent device sync details via Microsoft Graph |
| `CSVImport` | Imports or generates device inventory from CSV or Active Directory |
| `CVEInfo` | Displays extended CVE metadata and remediation paths |
| `CVEList` | Lists all cataloged CVEs for input month/year |
| `KB2CVE` | Converts KB ID to associated CVEs for reporting |
| `debugLog` | Handles output coloring and persistent logging |

---

## Notes and Limitations

- Only **Windows 11 versions 21H2 and newer** are mapped and supported.
- ConnectWise API credentials must enable **non‑MFA accounts** for automated commands[web:31][web:33].
- Output formatting may differ across PowerShell hosts that do not support ANSI colors.

---

## Credits

- **Author:** Blake Miller (luckyblake02-svg)  
- **ConnectWiseControlAPI:** by [Chris Taylor](https://github.com/christaylorcodes/ConnectWiseControlAPI)[web:31]  
- **MSRC API:** by [Microsoft](https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API)  
- **Microsoft Graph PowerShell SDK:** Microsoft official module  

---

## License

This script is licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html) (GPL-3.0).  

You are free to use, modify, and distribute this script under the terms of the GPL v3.0 license. Any derivative works or distributions must also be licensed under GPL v3.0, and must include this license notice.  

This license ensures that all modifications remain open source, preserving the freedoms to use, study, share, and improve the software.

For full license details, see [https://www.gnu.org/licenses/gpl-3.0.en.html](https://www.gnu.org/licenses/gpl-3.0.en.html).
