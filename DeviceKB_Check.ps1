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

function CVE2KB {

    Write-Host "
    
       _____________   _______________________  ____  __.__________ 
       \_   ___ \   \ /   /\_   _____/\_____  \|    |/ _|\______   \
       /    \  \/\   Y   /  |    __)_  /  ____/|      <   |    |  _/
       \     \____\     /   |        \/       \|    |  \  |    |   \
        \______  / \___/   /_______  /\_______ \____|__ \ |______  /
               \/                  \/         \/       \/        \/ 

    " -ForegroundColor Blue

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
    catch { Write-Host "Query for MSRC Document for $month $year failed." -ForegroundColor Red ; exit 0}

    #Get specific CVE.
    $vuln = Read-Host -Prompt "What vulnerability would you like to look for"

    #Get the exact vulnerability from MSRC.
    $data = $cve.vulnerability | Where-Object CVE -eq $vuln
    #List remediations for Windows 11 devices.
    $patches = $data.Remediations | Where-Object FixedBuild -Match "10.0.22|10.0.26"

    #Create a while loop for easy return upon user input error.
    $rdy = $false
    while (!$rdy) {
        $imp = Read-Host -Prompt "Will you be using Intune to grab a device list or will you import your own CSV"
        if ($imp -match "([Ii]ntune)") {
            $csv = IntunePull ; $rdy = $true
        }
        elseif ($imp -match "([Cc][Ss][Vv])") {
            $csv = CSVImport ; $rdy = $true
        }
        else {
            Write-Host "Please enter either 'Intune' or 'CSV'" -ForegroundColor Magenta
        }
    }

    #Add Patch value to csv for each device to store KB later.
    try {$csv | Where-Object {$_ -ne $null} | ForEach-Object { $_ | Add-Member -NotePropertyName Patch -NotePropertyValue ""; $_ } | Out-Null}
    catch {Write-Host "Something went wrong adding Patch property to csv." -ForegroundColor Red}
    
    Write-Host "Added Patch property to list." -ForegroundColor Cyan

    #Declare output array.
    $out = @()

    foreach ($dev in $csv) {
        #Store only the last 3 parts of the OS version.
        $os = ($dev.OSVersion -split '\.')[0..2] -join '.'
        #Grab URL from vulnerability info, as this is where the KB is stored.
        $build = $patches | Where-Object FixedBuild -Match $os | Select-Object URL
        #Extract the KB from the URL, if it exists.
        if ($build) {
            $fix = try { $build.URL.Split("q=")[1] }
            catch { Write-Host "It appears that the KB for $os doesn't come up." -ForegroundColor Red}
        }
        #Map OS version to 4 character code.
        switch ($os) {
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

        #Add new custom devices objects to array.
        $out += [PSCustomObject] @{
            DeviceName = $dev.DeviceName
            OSVersion = $dev.OSVersion
            Patch = $dev.Patch
        }
    }
    #Clear $csv variable. I was having issues clearing console output when returning $csv from import functions.
    $csv = ""
    Write-Host "`nDevice OS mapped to 4-Character code (e.g. 24H2) and Patch property applied." -ForegroundColor Cyan

    $test = Read-Host -Prompt "`nCurrently, the only supported way to test for the patch being applied is through Connectwise. Would you like to continue"
    if ($test -match "([Yy][Ee]?[Ss]?)") {
        CWProbe $out
    }
    else {
        $out | Export-Csv -Path "C:\temp\deviceList.csv" -NoTypeInformation
        Write-Host "Nothing left to do, we have exported the current csv to your C:\Temp folder!" -ForegroundColor Cyan
    }
}
        
function CWProbe {
    
    Write-Host "
    
    _________  __      ____________              ___.           
    \_   ___ \/  \    /  \______   \_______  ____\_ |__   ____  
    /    \  \/\   \/\/   /|     ___/\_  __ \/  _ \| __ \_/ __ \ 
    \     \____\        / |    |     |  | \(  <_> ) \_\ \  ___/ 
     \______  / \__/\  /  |____|     |__|   \____/|___  /\___  >
            \/       \/                               \/     \/ 
    
    " -ForegroundColor Blue
    
    #Declare parameter as the array created in main function.
    Param (
        [PSCustomObject]$out
    )
    #Attempt to connect to CW API. This requires a user with NO MFA, or else connection will fail.
    try { Write-Host "Attempting to connect to ConnectWise Control" -ForegroundColor Cyan ; Connect-CWC -Server 'server.connectwise.com' }
    catch { Write-Host "Connection attemp failed." -ForegroundColor Red ; exit 0 }

    #Get a list of all access CW sessions.
    $access = Get-CWCSession -Type 'Access'
    #Specify the group to look in for access sessions.
    $group = 'All Machines by Company'
    #Devices with KB applied.
    $KBList = @()
    $y = 0
    #Devices without KB applied.
    $KBNotList = @()
    $n = 0

    #Green means go.
    $green = $access | Where-Object Name -In $out.DeviceName

    foreach ($comp in $green) {
        #Store computer name into it's own variable to make it easier to call later.
        $name = $comp.Name
        #Make sure the device has been online in CW recently, and has a name that we can trace back.
        if (($name -ne "") -and ($comp.LastConnectedEventTime -gt 0)) {
            $guid = $comp.SessionID
            #Tell the machine to run 'Get-Hotfix' in powershell, listing all applied KBs.
            try { $KB = Invoke-CWCCommand -Group $group -GUID $guid -TimeOut 10000 -Powershell -Command 'Get-Hotfix' -ErrorAction SilentlyContinue }
            catch { Write-Host "Invoke CW Command failed for $name." -ForegroundColor Red }
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
        $devCheck = $out | Where-Object DeviceName -eq $name
        #Check if the list of applied KBs contains the specified KB to look for.
        $patchCheck = $list | Where-Object HotFixID -eq $devCheck.Patch

        #If the KB is applied, this is true.
        if ($patchCheck) {
            Write-Host "Patch appears to be applied to $name!" -ForegroundColor Cyan
            $KBList += $patchCheck
            $y += 1
        }
        else {
            Write-Host "Patch is not applied to $name, please remediate." -ForegroundColor DarkCyan
            $KBNotList += [PSCustomObject]@{
                Machine = $name
                MissingPatch = $devCheck.Patch
            }
            $n += 1
        }
    }
    Write-Host "It appears that there are $y patched devices and $n unpatched devices total." -ForegroundColor Cyan
    
    $KBList | Out-File "C:\temp\patched$vuln.txt"
    $KBNotList | Out-File "C:\temp\unpatched$vuln.txt"
}

function IntunePull {

    Write-Host "
    
    .___        __                     __________      .__  .__   
    |   | _____/  |_ __ __  ____   ____\______   \__ __|  | |  |  
    |   |/    \   __\  |  \/    \_/ __ \|     ___/  |  \  | |  |  
    |   |   |  \  | |  |  /   |  \  ___/|    |   |  |  /  |_|  |__
    |___|___|  /__| |____/|___|  /\___  >____|   |____/|____/____/
             \/                \/     \/                          
    
    " -ForegroundColor Blue

    #Declare an array to store computers.
    $csv = @()
    $ans = Read-Host -Prompt "Do you have permissions to authenticate to MS Graph and Intune?"
    if ($ans -match "([Yy][Ee]?[Ss]?)") {
    }
    else {
        Write-Host "You will need permissions to run this." -ForegroundColor Red ; exit 0
    }

    #Authenticate to MS Graph. Requires Cloud App Admin privileges or someone who can approve Graph read permissions.
    try { Write-Host "Connecting to MS Graph..." -ForegroundColor Cyan ; Connect-MgGraph -Scopes "Device.Read.All", "DeviceManagementManagedDevices.Read.All" -NoWelcome}
    catch { Write-Host "Connection failed." -ForegroundColor Red ; exit 0 }

    #Set Check in date to last 15 days.
    $date = (Get-Date).AddDays(-15)

    #Grab list of devices from Intune. Requires Intune administrator or read all devices.
    $Tmpcsv = try { Write-Host "Grabbing Intune Device List..." -ForegroundColor Cyan ; Get-MgDeviceManagementManagedDevice | Select-Object deviceName, LastSyncDateTime, OSVersion | Where-Object LastSyncDateTime -GT $date -NoTypeInformation }
    catch { Write-Host "Intune query failed." -ForegroundColor Red ; exit 0 }

    foreach ($dev in $Tmpcsv) {
        #Store only the first 3 block of the OS version.
        $OSVersion = ($dev.OSVersion -split '\.')[0..2] -join '.'
        #If the device is Windows 10 (Deprecated and should be its own fix.) set all values to NULL.
        if ($OSVersion -lt "10.0.22000") {
            $dev.DeviceName = "NULL"
            $dev.LastSyncDateTime = "NULL"
            $dev.OSVersion = "NULL"
        }
        $csv += [PSCustomObject] {
            DeviceName = $dev.DeviceName 
            OSVersion = $dev.OSVersion
        }
    }
    return $csv
}

function CSVImport {

    Write-Host "
    
   _________   _____________   ____.___                              __   
   \_   ___ \ /   _____/\   \ /   /|   | _____ ______   ____________/  |_ 
   /    \  \/ \_____  \  \   Y   / |   |/     \\____ \ /  _ \_  __ \   __\
   \     \____/        \  \     /  |   |  Y Y  \  |_> >  <_> )  | \/|  |  
    \______  /_______  /   \___/   |___|__|_|  /   __/ \____/|__|   |__|  
           \/        \/                      \/|__|                       

    " -ForegroundColor Blue

    #Declare array to store computers.
    $csv = @()
    $src = Read-Host -Prompt "Do you have a CSV list of all devices currently"

    if ($src -match "([Yy][Ee]?[Ss]?)") {
        $path = Read-Host -Prompt "Please enter the file path for the CSV to import"
        #Import-csv does not like double quotes.
        $path = $path -replace '[""]', ''

        #Note Tmp is because we take the objects we want out of here and put them into a better object.
        $Tmpcsv = Import-Csv $path

        #This is easier than telling people to go change their spreadsheet columns to standardized naming conventions.
        $nameVar = Read-Host -Prompt "What is the name of the Device Name column"
        $osVar = Read-Host -Prompt "What is the name of the OS Version column"

        foreach ($dev in $Tmpcsv) {
            #If Windows 10 (deprecated).
            if ($dev.$osVar -lt "10.0.22000") {
                continue
            }
            else {
                $csv += [PSCustomObject]@{
                    DeviceName = $dev.$nameVar
                    OSversion = $dev.$osVar
                }
            }
        }
    }
    elseif ($src -match "([Nn][Oo]?)") {
        $chk = Read-Host -Prompt "Do you have access to list all devices in Active Directory via Powershell"

        if ($chk -match "([Yy][Ee]?[Ss]?)") {
            Write-Host "Great! We will try to grab all machines from Active Directory now." -ForegroundColor Cyan
            #Grab all Win 11 enterprise devices. Change this to whatever you're looking for.
            try { $comp = Get-ADComputer -Filter 'OperatingSystem -eq "Windows 11 Enterprise"' -Properties CN,OperatingSystem,OperatingSystemVersion | Select-Object CN,OperatingSystemVersion | Sort-Object CN }
            catch { Write-Host "Get-ADComputer failed." -ForegroundColor Red ; exit 0}

            foreach ($dev in $comp) {
                #Standard format is like 10.0 (22000). Not very nice.
                $os = $dev.OperatingSystemVersion -replace '[(]', '.' -replace '[)]', '' -replace '[ ]', ''
                $csv += [PSCustomObject]@{
                    DeviceName = $dev.CN
                    OSVersion = $os
                }
            }
        }
        else {
            Write-Host "You will need access for this" -ForegroundColor Red ; exit 0
        }
    }
    else {
        Write-Host "Please enter yes or no" -ForegroundColor Magenta ; CSVImport
    }
    return $csv
}

function CVEInfo {
    
    Write-Host " 
    
    _____________   _______________.___        _____       
    \_   ___ \   \ /   /\_   _____/|   | _____/ ____\____  
    /    \  \/\   Y   /  |    __)_ |   |/    \   __\/  _ \ 
    \     \____\     /   |        \|   |   |  \  | (  <_> )
     \______  / \___/   /_______  /|___|___|  /__|  \____/ 
            \/                  \/          \/             
    
    " -ForegroundColor Blue

    $done = $false

    while (!$done) {
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
        catch { Write-Host "Query for MSRC Document for $month $year failed." -ForegroundColor Red ; exit 0}

        #Get specific CVE.
        $vuln = Read-Host -Prompt "What vulnerability would you like to look for"

        #Get the exact vulnerability from MSRC.
        $data = $cve.vulnerability | Where-Object CVE -eq $vuln
        if ($data) {
            $title = $data.Title.Value
            #Output is HTML, so we can just remove the tags and call it a day.
            $desc = $data.Notes[0].Value -replace "</p>", '' -replace "</strong>", '' -replace "<p>", '' -replace "<strong>", ''
            $faq = $data.Notes[1].Value -replace "</p>", '' -replace "</strong>", '' -replace "<p>", '' -replace "<strong>", ''
            $cwe = $data.CWE.ID
            $cweVal = $data.CWE.Value
            $cvss = $data.CVSSScoreSets[0].BaseScore
            $cvssVec = $data.CVSSScoreSets[0].Vector

            Write-Host "`nTitle: $title`n`nDesc: $desc`n`nFAQ: $faq`n`n$cwe`n$cweVal`n`nCVSS Score: $cvss`n$cvssVec`n`n" -ForegroundColor Green
        }
        else {
            Write-Host "It doesn't appear that $vuln is mapping to a CVE in this catalog. Please try again." -ForegroundColor Red ; exit 0
        }

        $rem = Read-Host -Prompt "Would you like to see the remediations"
        if ($rem -match "([Yy][Ee]?[Ss]?)") {
            #Create loop to allow for easy retry upon user input error.
            $go = $true
            while ($go) {
                $os = Read-Host -Prompt "`nPlease enter the OS you'd like a remediation for"
                if ($os -match "([2][2-5][Hh][2])") {
                    #Map 4 digit character to OS version. Literally the opposite of what we did earlier, but its human-readable vs. machine-readable :P
                    switch ($os) {
                        ("21H2") {
                            $os = "10.0.22000"
                        }
                        ("22H2") {
                            $os = "10.0.22621"
                        }
                        ("23H2") {
                            $os = "10.0.22631"
                        }
                        ("24H2") {
                            $os = Read-Host -Prompt "There are 2 builds for 24H2, please specify"
                        }
                    }
                }
                elseif ($os -match "(10\.0\.)" -and $os -ge "10.0.22000") {
                }
                else {
                    #I need to be able to read it.
                    Write-Host "Please enter either 2XH2 format or 10.0.XXXXX format." -ForegroundColor Magenta ; exit 0
                }
                #Sometimes there are multiple values.
                foreach ($val in ($data.Remediations.URL | Where-Object FixedBuild -eq $os)) {
                    Write-Host "`nURL: $val" -ForegroundColor Green
                }
                #This is inside the loop because if they enter yes, it goes right back to OS entry instead of line 1.
                $round = Read-Host -Prompt "Would you like to look for another OS"
                if ($round -notmatch "([Yy][Ee]?[Ss]?)") {
                    #End loop if user is done.
                    $go = $false
                }
            }
        }
        $print = Read-Host -Prompt "`nWould you like this info to be printed out"
        if ($print -match "([Yy][Ee]?[Ss]?)") {
            "`n$title`n`n$desc`n`n$faq`n`n$cwe`n$cweVal`n`n$cvss`n$cvssVec" | Out-File "C:\Temp\$vuln.txt"
        }

        $check = Read-Host -Prompt "`nWould you like to search another CVE"
        if ($check -notmatch "([Yy][Ee]?[Ss]?)") {
            $done = $true
        }
    }
}

function CVEList {

    Write-Host " 
    
    _____________   _______________.____    .__          __   
    \_   ___ \   \ /   /\_   _____/|    |   |__| _______/  |_ 
    /    \  \/\   Y   /  |    __)_ |    |   |  |/  ___/\   __\
    \     \____\     /   |        \|    |___|  |\___ \  |  |  
     \______  / \___/   /_______  /|_______ \__/____  > |__|  
            \/                  \/         \/       \/        
    
    " -ForegroundColor Blue

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
    catch { Write-Host "Query for MSRC Document for $month $year failed." -ForegroundColor Red ; exit 0}

    #Sort it to look nice.
    $title = $cve.Vulnerability.Title | Sort-Object Value
    $ct = $cve.Vulnerability.Title.Count

    Write-Host "`nThere are $ct vulnerabilities. We will output them to Grid View for you. If you would like to view one, select it to output to console." -ForegroundColor Cyan
    Start-Sleep 5
    #Store the selection from the console grid view so it can be output later.
    $sel = ($title | Out-ConsoleGridView).Value

    $next = Read-Host -Prompt "Would you like to export this list, or search for information on a specific vulnerability"
    if ($next -match "([Ee]xport)") {
        $title | Out-File -Path "C:\temp\$month$year.txt"
    }
    elseif ($next -match "([Ss]earch)") {
        #If multiple values selected.
        foreach ($val in $sel) {
            Write-Host "Here was your selection: $sel" -ForegroundColor Cyan
            $vulnInfo = $cve.Vulnerability | Where-Object Title -match $val
            $vulnTitle = $vulnInfo.Title.Value
            $vulnCVE = $vulnInfo.CVE
            if ($vulnInfo.Notes.Value[0]) {
                #HTML output, parse tags.
                $vulndesc = $vulnInfo.Notes.Value[0] -replace "<p>", '' -replace "</p>", ''
                Write-Host "`nTitle: $vulnTitle`n`nCVE ID: $vulnCVE`n`nDesc: $vulndesc" -ForegroundColor Green
            }
            else {
                Write-Host "`nTitle: $vulnTitle`n`nCVE ID: $vulnCVE" -ForegroundColor Green
            }
        }
    }
}

Write-Host "

________              .__              ____  __.__________    _________ .__                   __    
\______ \   _______  _|__| ____  ____ |    |/ _|\______   \   \_   ___ \|  |__   ____   ____ |  | __
 |    |  \_/ __ \  \/ /  |/ ___\/ __ \|      <   |    |  _/   /    \  \/|  |  \_/ __ \_/ ___\|  |/ /
 |    `   \  ___/\   /|  \  \__\  ___/|    |  \  |    |   \   \     \___|   Y  \  ___/\  \___|    < 
/_______  /\___  >\_/ |__|\___  >___  >____|__ \ |______  /____\______  /___|  /\___  >\___  >__|_ \
        \/     \/             \/    \/        \/        \/_____/      \/     \/     \/     \/     \/

" -ForegroundColor Blue


$open = Read-Host -Prompt "Welcome! What would you like to do

1: Map CVE patch status to computers.
2: Get Information on a specific CVE.
3: List all CVEs in a given month/year MSRC catalog.
"

switch ($open) {
    (1) {
        Write-Host "Entering CVE2KB Function..." -ForegroundColor Cyan ; CVE2KB
    }
    (2) {
        Write-Host "Entering CVEInfo function..." -ForegroundColor Cyan ; CVEInfo
    }
    (3) {
        Write-Host "Entering CVEList function..." -ForegroundColor Cyan ; CVEList
    }
    default {
        Write-Host "You did not select an appropriate option. Please choose 1-3" -ForegroundColor Red ; exit 0
    }
}
