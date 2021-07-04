# This module validates the Excel hosts tab details

# Creates an object specifically for file system information.
Function Get-HostFileSystemObj($Volumes, $CheckName, $FieldName, $RequiredValue, $DriveLetter)
{
    $obj = NewReportObject
    $obj.'Check Name' = $CheckName
    $obj.'Required Value' = $RequiredValue
    $volume = $Volumes | where DriveLetter -eq $DriveLetter
    $value = $volume.$FieldName

    if ($volume -and $FieldName -eq "Size"){
        $value = $value / 1GB
        if ($value.GetType() -eq  [System.Double])
        {
            $value = [System.Double]("{0:N2}" -f $value)
        }
    }

    if ($value -eq ""){
        $value = $null
    }

    $obj.'Current Value' = $value
    if ($FieldName -eq "Size")
    {
        if ($RequiredValue -ne "Rest")
        {
            UpdateStatus $obj
        }
    }
    else
    {
        UpdateStatus $obj
    }

    return $obj
}

# Display host's RAM memory.
Function Verify-HostMemory($VMEnvironment, $session)
{
    Write-Info "Checking VM '$ComputerName' Memory."

    $obj = NewReportObject
    $obj.'Check Name' = "Memory Size (GB)"
    #$obj.'Required Value' = $MemoryGB

    $CurrentMemoryGB = Invoke-Command -ComputerName $HostIP -Credential $credlocal -ScriptBlock {
        $InstalledRAM = Get-WmiObject -Class Win32_ComputerSystem
        [Math]::Round(($InstalledRAM.TotalPhysicalMemory/ 1GB),2)
    }

    $obj.'Current Value' = $CurrentMemoryGB

    Write-Success "VM '$ComputerName' Memory: $($CurrentMemoryGB)GB."

    #UpdateStatus $obj

    return $obj
}

# Displays hosts's CPU cores.
Function Verify-HostCPU($VMEnvironment, $session)
{
    Write-Info "Checking VM '$ComputerName' CPU cores."

    $obj = NewReportObject
    $obj.'Check Name' = "Num Of Cores"
    #$obj.'Required Value' = $NumOfCores

    $processorInfo = Invoke-Command -ComputerName $HostIP -Credential $credlocal -ScriptBlock {
        Get-WmiObject -class Win32_processor | Measure-Object -Property NumberOfCores -Sum
    }

    $obj.'Current Value' = $processorInfo.Sum
    Write-Success "VM '$ComputerName' CPU cores: $($processorInfo.Sum)."

    #UpdateStatus $obj

    return $obj
}

# Verifies host disk partitions.
Function Verify-HostPartitions($VMEnvironment, $session, $HostDisks, $ComputerName)
{
    Write-Info "Checking host '$ComputerName' partitions."

    $currentHostDisks = $HostDisks | where 'Hostname(NetBIOS)' -eq $ComputerName

    $Volumes = Invoke-Command -Session $session -ScriptBlock {
        Get-Volume
    }

    $Disks = @()

    foreach($diskInfo in $currentHostDisks)
    {
        $DriveLetter = $diskInfo.DriveLetter
        $Disks += Get-HostFileSystemObj $Volumes "Partition $DriveLetter Letter" "DriveLetter" $diskInfo.DriveLetter $DriveLetter 
        $Disks += Get-HostFileSystemObj $Volumes "Partition $DriveLetter Size (GB)" "Size" $diskInfo.'Size(GB)' $DriveLetter
    }

    return $Disks
}

# Verifies that cluster network is configured correctly on the host
Function Verify-ClusterNetwork($VMEnvironment, $HostIP, $session)
{
    $obj = NewReportObject
    $obj.'Check Name' = "Cluster (Heartbit) Network"
    $obj.'Required Value' = 'Exists'

    $ClusterNetAdapterIp = CombineIPAddress ($VMEnvironment | where {$_.Setting -eq "Heartbit_Net_Adapter_IP_Prefix"}).Value $HostIP
    
    $connected = Invoke-Command -Session $session -ScriptBlock {
        if (Test-Connection -ComputerName $using:ClusterNetAdapterIp -Count 1 -Quiet){
            return $true
    	} 
        return $false
    }

    if ($connected)
    {
        $obj.'Current Value' = "Exists"
    }
    else
    {
        $obj.'Current Value' = "Doesn't Exist"
    }

    UpdateStatus $obj

    return $obj
}

# Verifies that Live Migration network is configured correctly on the host
Function Verify-LiveMigrationNetwork($VMEnvironment, $HostIP, $session)
{
    $obj = NewReportObject
    $obj.'Check Name' = "Live Migration Network"
    $obj.'Required Value' = 'Exists'

    $LiveMigrationNetAdapterIp = CombineIPAddress ($VMEnvironment | where {$_.Setting -eq "Live_Migration_Net_Adapter_IP_Prefix"}).Value $HostIP
    
    $connected = Invoke-Command -Session $session -ScriptBlock {
        if (Test-Connection -ComputerName $using:LiveMigrationNetAdapterIp -Count 1 -Quiet){
            return $true
    	} 
        return $false
    }

    if ($connected)
    {
        $obj.'Current Value' = "Exists"
    }
    else
    {
        $obj.'Current Value' = "Doesn't Exist"
    }

    UpdateStatus $obj

    return $obj
}

#Validates the Excel hosts tab details
Function Verify-Hosts($VMEnvironment, $Hosts, $HostDisks, $credlocal)
{
    Write-Info "Verifying Hyper-V hosts configuration."

    $frag = ""

    $EnvironmentType = ($VMEnvironment | where Setting -eq "Environment").Value

    foreach ($Hst in $Hosts){
        $HostIP = $Hst.HostIP
        $ComputerName = $Hst.'Hostname(NetBIOS)'

        Write-Info "Verify Hyper-V host '$ComputerName'"

        $session = New-PSSession -Credential $credlocal -ComputerName $HostIP

        try
        {
            $HostVars = @()
            $HostVar = Verify-Connection $HostIP
            $HostVars += $HostVar
            if ($HostVar.Status -eq "OK"){
                $HostVar = Verify-Login $session
                $HostVars += $HostVar
                if ($HostVar.Status -eq "OK"){
                    $HostVars += Verify-HostName $ComputerName $session
                    $HostVars += Verify-DomainName $VMEnvironment $session
                    $HostVars += Verify-HostMemory $VMEnvironment $session
                    $HostVars += Verify-HostCPU $VMEnvironment $session
                    $HostVars += Verify-HostPartitions $VMEnvironment $session $HostDisks $ComputerName
                    $HostVars += Verify-GenuineOS $session
                    #$HostVars += Verify-AntiVirus $session
                    $HostVars += Verify-GPOApplied $session $false
                    $HostVars += Verify-TimeSynced $VMEnvironment $session
                    if ($EnvironmentType -eq 'Cluster')
                    {
                        $HostVars += Verify-ClusterNetwork $VMEnvironment $HostIP $session 
                        $HostVars += Verify-LiveMigrationNetwork $VMEnvironment $HostIP $session 
                    }
                }
            }
        }
        finally
        {        
            Remove-PSSession -Session $session
        }

        $title = "<BR><Table><tr><th><B> Hyper-V Host: $HostIP $ComputerName</B></th><tr><Table>"
        $frag += $HostVars | ConvertTo-HTML -Fragment -PreContent $title | Out-String
    }

    return $frag
}

