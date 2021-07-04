# This module validates the Excel VMs tab details.

# Verifies VM's RAM memory is as configured.
Function Verify-Memory($VMEnvironment, $session, $MemoryGB)
{
    Write-Info "Checking VM '$ComputerName' Memory."

    $obj = NewReportObject
    $obj.'Check Name' = "Memory Size (GB)"
    $obj.'Required Value' = $MemoryGB

    $CurrentMemoryGB = Invoke-Command -ComputerName $HostIP -Credential $credlocal -ScriptBlock {
        $InstalledRAM = Get-WmiObject -Class Win32_ComputerSystem
        [Math]::Round(($InstalledRAM.TotalPhysicalMemory/ 1GB),2)
    }

    $obj.'Current Value' = $CurrentMemoryGB

    Write-Success "VM '$ComputerName' Memory: $($CurrentMemoryGB)GB."

    UpdateStatus $obj

    return $obj
}

# Verifies VM's CPU cores are as configured.
Function Verify-CPU($VMEnvironment, $session, $NumOfCores)
{
    Write-Info "Checking VM '$ComputerName' CPU cores."

    $obj = NewReportObject
    $obj.'Check Name' = "Num Of Cores"
    $obj.'Required Value' = $NumOfCores

    $processorInfo = Invoke-Command -ComputerName $HostIP -Credential $credlocal -ScriptBlock {
        Get-WmiObject -class Win32_processor | Measure-Object -Property NumberOfCores -Sum
    }

    $obj.'Current Value' = $processorInfo.Sum
    Write-Success "VM '$ComputerName' CPU cores: $($processorInfo.Sum)."

    UpdateStatus $obj

    return $obj
}

# Creates an object specifically for file system information.
Function Get-FileSystemObj($Volumes, $partitions, $disks, $CheckName, $FieldName, $RequiredValue, $DriveLetter)
{
    $obj = NewReportObject
    $obj.'Check Name' = $CheckName
    $obj.'Required Value' = $RequiredValue
    $volume = $Volumes | where DriveLetter -eq $DriveLetter
    $value = $volume.$FieldName
    if ($volume -and $FieldName -eq "Size"){
        $value = Get-DiskSize $DriveLetter $partitions $disks
    }
    elseif ($value -eq ""){
        $value = $null
    }

    $obj.'Current Value' = $value
    UpdateStatus $obj

    return $obj
}

#Gets disk partition's size by its drive letter.
Function Get-DiskSize($DriveLetter, $partitions, $disks)
{
    $partition = $partitions | where DriveLetter -eq $DriveLetter
    $disk = $disks | where number -eq $partition.DiskNumber

    $size = $disk.Size / 1GB

    return $size
}

# Verifies VM's disk partitions are as configured.
Function Verify-Partitions($VMEnvironment, $session, $VMDisks, $ComputerName)
{
    Write-Info "Checking VM '$ComputerName' partitions."

    $currentVMDisks = $VMDisks | where ComputerName -eq $ComputerName

    $Volumes = Invoke-Command -Session $session -ScriptBlock {
        Get-Volume
    }

    $partitions = Invoke-Command -Session $session -ScriptBlock {
        Get-Partition
    }

    $disksOnHost = Invoke-Command -Session $session -ScriptBlock {
        Get-Disk
    }

    $Disks = @()

    foreach($diskInfo in $currentVMDisks)
    {
        $Disks += Get-FileSystemObj $Volumes $partitions $disksOnHost "Partition $($diskInfo.DriveLetter) Letter" "DriveLetter" $diskInfo.DriveLetter $diskInfo.DriveLetter 
        $Disks += Get-FileSystemObj $Volumes $partitions $disksOnHost "Partition $($diskInfo.DriveLetter) Size (GB)" "Size" $diskInfo.Capacity $diskInfo.DriveLetter
        $Disks += Get-FileSystemObj $Volumes $partitions $disksOnHost "Partition $($diskInfo.DriveLetter) Label" "FileSystemLabel" $diskInfo.Label $diskInfo.DriveLetter
    }

    return $Disks
}

# Verifies Windows VM is as configured.
Function HandleWindowsVM($VMEnvironment, $credlocal, $ComputerName, $HostIP, $IsDC)
{
    $session = New-PSSession -Credential $credlocal -ComputerName $HostIP

    try
    {
        $HostVar = Verify-Login $session
        $HostVars = @()
        $HostVars += $HostVar
        if ($HostVar.Status -eq "OK")
        {
            $HostVars += Verify-HostName $ComputerName $session
            $HostVars += Verify-DomainName $VMEnvironment $session
            $HostVars += Verify-Memory $VMEnvironment $session $VM.Memory
            $HostVars += Verify-CPU $VMEnvironment $session $VM.Cores
            $HostVars += Verify-Partitions $VMEnvironment $session $VMDisks $ComputerName
            $HostVars += Verify-GenuineOS $session 
            $HostVars += Verify-AntiVirus $session
            $HostVars += Verify-WindowsUpToDate $session
            $HostVars += Verify-GPOApplied $session $IsDC
            $HostVars += Verify-TimeSynced $VMEnvironment $session
        }
    }
    finally
    {        
        Remove-PSSession -Session $session
    }

    return $HostVars
}

# Verifies loging into Linux VM.
Function Verify-LinuxLogin($ComputerNam)
{
    Write-Info "Checking Linux VM '$ComputerName' login."

    $obj = NewReportObject
    $obj.'Check Name' = "Login Suceeded"
    $obj.'Required Value' = "Yes"

    Invoke-SSHCommand -Index 0 -Command "date" -ErrorAction Stop | Out-Null

    if ($?){
        $obj.'Current Value' = "Yes"
	}
    else {
        $obj.'Current Value' = "No"
    }

    UpdateStatus $obj

    return $obj
}

# Verifies Linux host name is as configured.
Function Verify-LinuxHostName($VMEnvironment, $ComputerName)
{
    Write-Info "Checking Linux VM '$ComputerName' hostname."

    $obj = NewReportObject
    $obj.'Check Name' = "Machine Name"
    $obj.'Required Value' = $ComputerName

    $hostname = Invoke-SSHCommand -Index 0 -Command "hostname" -ErrorAction Stop
    if ($?){
        $obj.'Current Value' = $hostname | select output -ExpandProperty output
	}

    UpdateStatus $obj

    return $obj
}

# Verifies Linux RAM memory size is as configured.
Function Verify-LinuxMemory($VMEnvironment, $Memory, $ComputerName)
{
    Write-Info "Checking Linux VM '$ComputerName' memory."

    $obj = NewReportObject
    $obj.'Check Name' = "Memory"
    $obj.'Required Value' = $Memory

    $memoryInfo = Invoke-SSHCommand -Index 0 -Command "free -m" -ErrorAction Stop
    $memorySize = $memoryInfo | select -ExpandProperty Output | Select-String "Mem:"

    if ($memorySize -match '[0-9]+') 
    {
        $totalMemSize = $matches[0]
    }

    $CurrentMemoryGB =  [math]::Round(([convert]::ToInt32($totalMemSize, 10) * 1MB) / 1GB , 0)
    $obj.'Current Value' = $CurrentMemoryGB
    Write-Success "VM '$ComputerName' Memory: $($CurrentMemoryGB)GB."

    UpdateStatus $obj

    return $obj
}

# Verifies Linux CPU cores are as configured.
Function Verify-LinuxCPU($VMEnvironment, $cores, $ComputerName)
{
    Write-Info "Checking Linux VM '$ComputerName' CPU cores."

    $obj = NewReportObject
    $obj.'Check Name' = "Num Of Cores"
    $obj.'Required Value' = $cores

    $numOfCores = Invoke-SSHCommand -Index 0 -Command "nproc" -ErrorAction Stop
    if ($?){
        $obj.'Current Value' = $numOfCores | select output -ExpandProperty output
	}

    Write-Success "VM '$ComputerName' CPU cores: $($obj.'Current Value')."

    UpdateStatus $obj

    return $obj
}

# Verifies Linux disk partitions are as configured.
Function Verify-LinuxPartitions($VMEnvironment, $VMDisks, $ComputerName)
{
    Write-Info "Checking Linux VM '$ComputerName' partitions."

    $currentVMDisks = $VMDisks | where ComputerName -eq $ComputerName

    $Disks = @()

    $currDisks = Invoke-SSHCommand -Index 0 -Command "lsblk -d -e 11 -o name,size" -ErrorAction Stop | select output -ExpandProperty output
    
    $i = 2 #The 3rd place in the array is the value we are looking for

    foreach($diskInfo in $currentVMDisks)
    {
        $partitionNum = $i - 1
        $obj = NewReportObject
        $obj.'Check Name' = "Partition $partitionNum Size"
        $obj.'Required Value' = $diskInfo.Capacity

        if ($currDisks)
        {
            if ($currDisks[$i] -match '[0-9]+T')
            {
                $currDisks[$i] -match '[0-9]+'
                $obj.'Current Value' = ([convert]::ToInt32($matches[0], 10) * 1TB) / 1GB
            }
            elseif ($currDisks[$i] -match '[0-9]+')
            {
                $obj.'Current Value' = $matches[0]
            }
        }

        UpdateStatus $obj

        $Disks += $obj
        $i++
    }
    return $Disks
}

# Verifies Linux VM is as configured.
Function HandleLinuxVM($VMEnvironment, $credlocal, $ComputerName, $HostIP)
{
    try
    {
        New-SSHSession -ComputerName $HostIP -Credential $credlocal -AcceptKey -ConnectionTimeout 20 -ErrorAction Stop | Out-Null
    }
    catch #Try again in case it fails
    {
        New-SSHSession -ComputerName $HostIP -Credential $credlocal -AcceptKey -ConnectionTimeout 20 -ErrorAction Stop | Out-Null
    }

    try
    {
        $HostVar = Verify-LinuxLogin $ComputerNam
        $HostVars = @()
        $HostVars += $HostVar
        if ($HostVar.Status -eq "OK")
        {
            $HostVars += Verify-LinuxHostName $VMEnvironment $ComputerName 
            $HostVars += Verify-LinuxMemory $VMEnvironment $VM.Memory $ComputerName
            $HostVars += Verify-LinuxCPU $VMEnvironment $VM.Cores $ComputerName
            $HostVars += Verify-LinuxPartitions $VMEnvironment $VMDisks $ComputerName
        }
    }
    finally
    {
        Remove-SSHSession 0 | Out-Null
    }

    return $HostVars
}

#Verify Excel VMs tab details
Function Verify-VMs ($VMEnvironment, $VMs, $Hosts, $VMNetwork, $VMDisks, $credlocal)
{
    Write-Info "Verify VMs Excel sheet."

    $frag = ""
    $MPS_VM_Name = ($VMEnvironment | where {$_.Setting -eq "MPS_VM_Name"}).Value
    $SDC_VM_Name = ($VMEnvironment | where {$_.Setting -eq "SDC_VM_Name"}).Value

    foreach ($VM in $VMs)
    {
        $HostIP = $VM.PrimaryIP
        $ComputerName = $VM.ComputerName

        Write-Info "Verify VM '$ComputerName'"

        $HostVars = @()
        $HostVar = Verify-Connection $HostIP
        $HostVars += $HostVar
        if ($HostVar.Status -eq "OK")
        {
            if (IsLinuxOS($VM.OSProfile))
            {
                $HostVars += HandleLinuxVM $VMEnvironment $credlocal $ComputerName $HostIP
            }
            else
            {
                #In case the VM is MPS or SDC we need to verify that NTPforPDC policy is applied as well
                if ($ComputerName -eq $MPS_VM_Name -or $ComputerName -eq $SDC_VM_Name)
                {
                    $HostVars += HandleWindowsVM $VMEnvironment $credlocal $ComputerName $HostIP $true
                }
                else
                {
                    $HostVars += HandleWindowsVM $VMEnvironment $credlocal $ComputerName $HostIP $false
                }
            }
        }

        $title = "<BR><Table><tr><th><B> Virtual Machine: $HostIP $ComputerName</B></th><tr><Table>"
        $frag += $HostVars | ConvertTo-HTML -Fragment -PreContent $title | Out-String
    }

    return $frag
}

