<#
You will need the following to start
Install-Module Microsoft.Graph and import
Install-Module ConnectWiseControlAPI and import
Install-Module MsrcSecurityUpdates and import
This script will ask the user for the month/year MSRC catalog they wish to look at, then connect via MSRC API and grab the list of vulnerabilities. The user will then be promped for the specific CVE ID.
Then, the remediations for Windows 11 devices will be grabbed for that specific CVE.
Then, connect to MS Graph, then download a list of all devices that have synced within the last 15 days to Intune. It will then map their OS version to a 4-character code.
Then set the indicated patch for the remediation. Finally, it will connect to ConnectWise Screenconnect, run 'Get-Hotfix' to list all applied patches, and check if any patched match the specified patch for the OS.
Patched devices get stored in $KBList, other devices get stored in $KBNotList.
ConnectWise API from https://github.com/christaylorcodes/ConnectWiseControlAPI/tree/master by christaylorcodes.
MSRC API from https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API by microsoft.
-Blake Miller
#>

#Check if we are using current month/year.
$check = Read-Host -Prompt "Would you like to search the current month MSRC report"
if ($check -match "([Yy][Ee]?[Ss]?)") {
    $month = Get-Date -Format MMM
    $year = Get-Date -Format yyy
}
else {
    $month = Read-Host -Prompt "What month would you like to search (3 letter name)"
    $year = Read-Host -Prompt "What year would you like to search (YYYY)"
}

#Query MSRC API to get Month/Year catalog.
$cve = try { Get-MsrcCvrfDocument -ID "$year-$month" }
catch { Write-Host "Query for MSRC Document for $month $year failed." ; exit 0}

#Get specific CVE.
$vuln = Read-Host -Prompt "What vulnerability would you like to look for"

#Get the exact vulnerability from MSRC.
$data = $cve.vulnerability | Where-Object CVE -eq $vuln
#List remediations for Windows 11 devices.
$patches = $data.Remediations | Where-Object FixedBuild -Match "10.0.22|10.0.26"

$ans = Read-Host -Prompt "Do you have permissions to authenticate to MS Graph and Intune?"
if ($ans -match "([Yy][Ee]?[Ss]?)") {
}
else {
    Write-Host "You will need permissions to run this." ; exit 0
}

#Authenticate to MS Graph. Requires Cloud App Admin privileges or someone who can approve Graph read permissions.
try { Write-Host "Connecting to MS Graph..." ; Connect-MgGraph -Scopes "Device.Read.All", "DeviceManagementManagedDevices.Read.All" -NoWelcome}
catch { Write-Host "Connection failed." ; exit 0 }

#Set Check in date to last 15 days.
$date = (Get-Date).AddDays(-15)

#Grab list of devices from Intune. Requires Intune administrator or read all devices.
try { Write-Host "Grabbing Intune Device List..." ; Get-MgDeviceManagementManagedDevice | Select-Object deviceName, LastSyncDateTime, OSVersion | Where-Object LastSyncDateTime -GT $date | Export-Csv -Path "C:\temp\IntuneDeviceInventory.csv" -NoTypeInformation }
catch { Write-Host "Intune query failed." ; exit 0 }

$csv = Import-Csv -Path "C:\temp\IntuneDeviceInventory.csv"

#For each item, add a "Patch" field for later.
$csv | ForEach-Object { $_ | Add-Member -NotePropertyName Patch -NotePropertyValue ""; $_ }

Write-Host "Added Patch property to list."

foreach ($dev in $csv) {
    #Store only the first 3 block of the OS version.
    $osData = ($dev.OSVersion -split '\.')[0..2] -join '.'
    #If the device is Windows 10 (Deprecated and should be its own fix.) set all values to NULL.
    if ($osData -lt "10.0.22000") {
        $dev.DeviceName = "NULL"
        $dev.LastSyncDateTime = "NULL"
        $dev.OSVersion = "NULL"
    }
    else {
        #Grab URL from vulnerability info, as this is where the KB is stored.
        $build = $patches | Where-Object FixedBuild -Match $osData | Select-Object URL
        #Extract the KB from the URL.
        $fix = try { $build.URL.Split("q=")[1] }
        catch { Write-Host "It appears that the KB for $osData doesn't come up."}
        
        switch ($osData) {
            ("10.0.22000") {
                $dev.OSVersion = "21H2"
            }
            ("10.0.22621") {
                $dev.OSVersion = "22H2"
            }
            ("10.0.22631") {
                $dev.OSVersion = "23H2"
            }
            ("10.0.26100") {
                $dev.OSVersion = "24H2"
            }
            ("10.0.26200") {
                $dev.OSVersion = "24H2"
            }
        }
        $dev.Patch = $fix
    }
}
Write-Host "Device OS mapped to 4-Character code (e.g. 24H2) and Patch property applied."

#Attempt to connect to CW API. This requires a user with NO MFA, or else connection will fail.
try { Write-Host "Attempting to connect to ConnectWise Control" ; Connect-CWC -Server 'server.connectwise.com' }
catch { Write-Host "Connection attemp failed." ; exit 0 }

#Get a list of all access CW sessions.
$access = Get-CWCSession -Type 'Access'
#Specify the group to look in for access sessions.
$group = 'All Machines by Company'
$KBList = @()
$KBNotList = @()

$green = $access | Where-Object Name -In $csv.DeviceName

foreach ($comp in $green) {
    #Store computer name into it's own variable to make it easier to call later.
    $name = $comp.Name
    #Make sure the device has been online in CW recently, and has a name that we can trace back.
    if (($name -ne "") -and ($comp.LastConnectedEventTime -gt 0)) {
        $guid = $comp.SessionID
        #Tell the machine to run 'Get-Hotfix' in powershell, listing all applied KBs.
        try { $KB = Invoke-CWCCommand -Group $group -GUID $guid -TimeOut 10000 -Powershell -Command 'Get-Hotfix' }
        catch { Write-Host "Invoke CW Command failed for $name." }
        Start-Sleep 3
    }
    #Split by newline, removing the first and second lines, as they are unnecessary.
    $lines = $KB -split "`n" | Where-Object {$_ -notmatch "^-+" -and $_ -notmatch "Source"}

    $list = foreach ($line in $lines) {
        #Create regex match to only grab the device name, and HotFixIDs.
        if ($line -match "($name)(?:.*)(KB[0-9]*)(?:.*)") {
            [PSCustomObject]@{
                Source       = $matches[1]
                HotFixID     = $matches[2]
            }
        }
    }

    #Grab all Intune device info for the current device.
    $devCheck = $csv | Where-Object DeviceName -eq $name
    #Check if the list of applied KBs contains the specified KB to look for.
    $patchCheck = $list | Where-Object HotFixID -eq $devCheck.Patch

    #If the KB is applied, this is true.
    if ($patchCheck) {
        Write-Host "Patch appears to be applied to $name!"
        $KBList += $patchCheck
    }
    else {
        Write-Host "Patch is not applied to $name, please remediate."
        $KBNotList += [PSCustomObject]@{
            Machine = $name
            MissingPatch = $devCheck.Patch
        }
    }
}

$KBList | Out-File "C:\temp\patched$vuln.txt"
$KBNotList | Out-File "C:\temp\unpatched$vuln.txt"
