# This module contain generic validation functions

# Creates generic report object. This object has 4 fields: Check Name, Current Value, Required Value and Status
Function NewReportObject()
{
    $obj = New-Object psobject
    Add-Member -InputObject $obj -MemberType NoteProperty -Name 'Check Name' -Value ""
    Add-Member -InputObject $obj -MemberType NoteProperty -Name 'Current Value' -Value ""
    Add-Member -InputObject $obj -MemberType NoteProperty -Name 'Required Value' -Value ""
    Add-Member -InputObject $obj -MemberType NoteProperty -Name 'Status' -Value ""

    return $obj
}

# Updates the status field od the report object after comparing current value against required value.
Function UpdateStatus($obj)
{
    if ($obj.'Current Value' -eq $obj.'Required Value')
    {
        $obj.Status = "OK"
    }
    else
    {
        $obj.Status = "Not OK"
    }
}

# Verifies host name equals to the value in $ComputerName.
Function Verify-HostName($ComputerName, $session)
{
    Write-Info "Checking computer hostname."

    $obj = NewReportObject
    $obj.'Check Name' = "Machine Name"
    $obj.'Required Value' = $ComputerName

    $CurrentHostName = Invoke-Command -Session $session -ScriptBlock {
        hostname
    }

    $obj.'Current Value' = $CurrentHostName

    UpdateStatus $obj

    return $obj
}

# Verifies actual domain name is as configured in Environment tab in Excel, by inspecting the machine.
Function Verify-DomainName($VMEnvironment, $session)
{
    $Domain = ($VMEnvironment | where {$_.Setting -eq "Domain_Name"}).Value

    Write-Info "Checking if computer is in the domain '$Domain'."

    $obj = NewReportObject
    $obj.'Check Name' = "Domain"
    $obj.'Required Value' = $Domain

    $CurrentDomainName = Invoke-Command -Session $session -ScriptBlock {
        (gwmi win32_computersystem).domain
    }

    $obj.'Current Value' = $CurrentDomainName

    UpdateStatus $obj

    return $obj
}

# Verifies Windows is activated
Function Verify-GenuineOS($session)
{
    Write-Info "Checking if OS is genuine."

    $obj = NewReportObject
    $obj.'Check Name' = "Genuine OS"
    $obj.'Required Value' = "Yes"

    $CurrentLicenseStatus = Invoke-Command -Session $session -ScriptBlock {
        Get-CimInstance -ClassName SoftwareLicensingProduct | where PartialProductKey | where name -like "Windows*" | select Name, ApplicationId, LicenseStatus
    }

    if ($CurrentLicenseStatus.LicenseStatus -eq 1){
        $obj.'Current Value' = "Yes"
    }
    else {
        $obj.'Current Value' = "No"
    }

    UpdateStatus $obj

    return $obj
}

# Verifies SEP antivirus is installed.
Function Verify-AntiVirus($session)
{
    Write-Info "Checking if AntiVirus software installed."

    $obj = NewReportObject
    $obj.'Check Name' = "Symantec Antivirus"
    $obj.'Required Value' = "Exists"

    $AntiVirusStatus = Invoke-Command -Session $session -ScriptBlock {
        Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*  | where DisplayName -like "Symantec Endpoint*"
    }

    if ($AntiVirusStatus){
        $obj.'Current Value' = "Version $($AntiVirusStatus.DisplayVersion)"
        $obj.Status = "OK"
    }
    else {
        $obj.'Current Value' = "Doesn't Exist"
        $obj.Status = "Not OK"
    }
    return $obj
}

# Verifies Windows is up to date (no pending updates)
Function Verify-WindowsUpToDate($session)
{
    Write-Info "Checking if Windows is up to date."

    $obj = NewReportObject
    $obj.'Check Name' = "Windows is up-to-date (WSUS)"
    $obj.'Required Value' = "Yes"

    $updates = Invoke-Command -Session $session -ScriptBlock {
        $criteria = "Type='software' and IsAssigned=1 and IsHidden=0 and IsInstalled=0"

        $searcher = (New-Object -COM Microsoft.Update.Session).CreateUpdateSearcher()
        $searcher.Search($criteria).Updates
    }

    if ($updates.Count -ne 0) {
        # $updates pending
        $obj.'Current Value' = "No"
    } else {
        # system up-to-date
        $obj.'Current Value' = "Yes"
    }

    UpdateStatus $obj

    return $obj
}

# Verifies GPO is applied in the machine.
Function Verify-GPOApplied($session, $IsDC)
{
    Write-Info "Checking if GPO policies are applied."

    $obj = NewReportObject
    $obj.'Check Name' = "GPO Applied"
    $obj.'Required Value' = "Yes"

    if ($IsDC)
    {
        $PolicyCheckCount = 3
    }
    else
    {
        $PolicyCheckCount = 2
    }

    $policies = Invoke-Command -Session $session -ScriptBlock {
        gpresult /r | Select-String -list NTPforPDC,NTPGeneral,General
    }

    if ($policies.Count -lt $PolicyCheckCount) {
        # Too less group policies applied (supposed to be 3 NTPforPDC,NTPGeneral,General)
        $obj.'Current Value' = "No"
    } else {
        # All relevant group policies applied
        $obj.'Current Value' = "Yes"
    }

    UpdateStatus $obj

    return $obj
}

# Verifies machine is connected.
Function Verify-Connection($HostIP)
{
    Write-Info "Checking connection to '$HostIP'."

    $obj = NewReportObject
    $obj.'Check Name' = "Connection Established"
    $obj.'Required Value' = "Yes"

    if (Test-Connection -ComputerName $HostIP -Count 1 -Quiet){
        $obj.'Current Value' = "Yes"
    }
    else {
        $obj.'Current Value' = "No"
    }

    UpdateStatus $obj

    return $obj
}

# Verifies can log in to the machine.
Function Verify-Login($session)
{
    Write-Info "Checking Login."

    $obj = NewReportObject
    $obj.'Check Name' = "Login Suceeded"
    $obj.'Required Value' = "Yes"

    $date = Invoke-Command -Session $session -ErrorAction SilentlyContinue -ScriptBlock {
        Get-Date
    }

    if ($date){
        $obj.'Current Value' = "Yes"
    }
    else {
        $obj.'Current Value' = "No"
    }

    UpdateStatus $obj

    return $obj
}

# Verifies time is synced against the DC.
Function Verify-TimeSynced($VMEnvironment, $session)
{
    Write-Info "Checking time synchronization."

    $obj = NewReportObject
    $obj.'Check Name' = "Time Synchronization"
    $obj.'Required Value' = "Yes"

    $Domain = ($VMEnvironment | where {$_.Setting -eq "Domain_Name"}).Value

    $timeDiff = Invoke-Command -Session $session -ErrorAction SilentlyContinue -ScriptBlock {
        w32tm /stripchart /computer:$using:Domain /dataonly /samples:1 | Select-Object -last 1
    }

    if ($timeDiff -match '[+-][0-9][0-9].[0-9]*')
    {
        if ([math]::Abs($matches[0]) -lt 1.0)
        {
            $obj.'Current Value' = "Yes"
        }
        else {
            $obj.'Current Value' = "No"
        }
    }

    UpdateStatus $obj

    return $obj
}