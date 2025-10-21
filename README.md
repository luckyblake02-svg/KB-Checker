***

# KB-Checker  

PowerShell utility for verifying **Windows KB patch compliance** across endpoints.  
It can run **standalone** on a local machine or optionally integrate with **Microsoft Intune** and **ConnectWise Control** to automate remote checking at scale.

***

## ✳️ Overview  

**DeviceKB_Check.ps1** helps administrators determine whether a specific Windows update (KB) is installed on one or more systems.  
You can run it manually, point it to a computer list, or connect to managed devices dynamically through Intune or ScreenConnect.  

Each device check runs a PowerShell-level validation and produces two export files — *patched* and *unpatched* — for quick compliance reporting.

***

## ⚙️ Workflow  

1. The script prompts for a KB identifier (e.g., `KB5054007`).  
2. Depending on available inputs or connected APIs, it determines the appropriate query mode:  
   - **Local system** check  
   - **Multiple computers** from a local file  
   - **Microsoft Intune** device inventory (if selected)  
   - **ConnectWise Control (ScreenConnect)** remote command execution (if available)  
3. Executes `Get-HotFix` (locally or remotely) and validates whether the KB is installed.  
4. Results are saved to the local path `C:\temp` as:  
   ```
   patched<KB>.txt
   unpatched<KB>.txt
   ```
5. A summary of total devices checked, patched, and unpatched is shown upon completion.

***

## 📦 Features  

- Simple PowerShell-based KB validation — no external dependencies required.  
- Optionally query **Intune-managed** devices or **ScreenConnect**-connected endpoints.  
- Supports dynamic build mapping for Windows 11 releases (21H2–24H2).  
- Includes **parallel query handling** and resilient retry logic for remote systems.  
- Generates clear plain-text compliance output suitable for audit reports or SIEM ingestion.  
- Fully offline capable — runs without any API integrations if invoked locally.

***

## 🚀 Requirements  

### Minimum  
- PowerShell 7.0 or newer  
- Windows 10/11 (build 22000+)

### Optional Modules  
```powershell
Install-Module Microsoft.Graph              # Intune integration
Install-Module ConnectWiseControlAPI        # ScreenConnect integration
Install-Module MsrcSecurityUpdates          # (Optional) MSRC metadata reference
```

***

## 🔐 Permissions (for Optional Integrations)  

**Microsoft Graph API** scopes required if Intune mode is used:
```
Device.Read.All
DeviceManagementManagedDevices.Read.All
```

***

## 💾 Output Example  

Generated export files:
```
C:\temp\patchedKB5054007.txt
C:\temp\unpatchedKB5054007.txt
```

Each file contains one device name per line representing patch status.

Console sample summary:
```
Checked 14 devices
9 patched, 5 unpatched
Results saved to C:\temp\
```

***

## 🧠 Notes  

- Compatible with Windows 11 builds 21H2 through 24H2.  
- Skips unsupported OS builds below `10.0.22000`.  
- Automatically detects missing modules and uses local fallback checks if APIs are unused.  
- Retries remote queries for temporarily disconnected or offline machines.  
- Built for both single-system use and large-scale remediation audits.  

***

## 🧾 License  

Distributed under the **GPL-3.0 License**.  
You are free to modify, extend, and integrate into enterprise automation or vulnerability compliance frameworks.

***

## 👤 Author  

**Blake Miller**  
Cybersecurity Professional – Endpoint Security & Compliance Automation  
Kansas, United States  

***

## 📚 References  

- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph)  
- [ConnectWise Control Public API](https://github.com/christaylorcodes/ConnectWiseControlAPI)  
- [MSRC Security Updates API](https://api.msrc.microsoft.com/api)  

***
