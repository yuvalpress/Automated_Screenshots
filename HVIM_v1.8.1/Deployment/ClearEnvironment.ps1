# This is the module is used in order to clear the Hyper-V environment created by the Hyper-V Infrastructure Management tool (HVIM). 
# It reads all of its input (other than passwords) from the input Excel file.
# The input read from the command line is saved into an XML file. The passwords are encrypted.


# Unjoins the host from the domain.
function Remove-HostFromDomain($VMEnvironment, $Hosts, $DomainAdminUser, $DomainAdminPasswordClear, $credlocal)
{
    $hostname = $Hst.'Hostname(NetBIOS)'
    Write-Info "Checking if host '$hostname' is in the domain $Domain"
    $Domain = ($VMEnvironment | where {$_.Setting -eq "Domain_Name"}).Value

    $isInDomain = Invoke-Command -ComputerName $Hst.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
		if ((gwmi win32_computersystem).partofdomain){
			if ((gwmi win32_computersystem).domain -eq $using:Domain){
				return $true
			}
            return $false
		}
    }
    if ($isInDomain){
        $hostname = $Hst.'Hostname(NetBIOS)'
        Write-Info "Removing host '$hostname' from the domain $Domain"
        $securedPassword = ConvertTo-SecureString $DomainAdminPasswordClear -AsPlainText -Force
    
        $NetBios = GetNetBios $VMEnvironment
	    $credDomain = New-Object System.Management.Automation.PSCredential ("$NetBios\$DomainAdminUser", $securedPassword)

        Invoke-Command -ComputerName $Hst.HostIP -Credential $credlocal -ScriptBlock {
            Remove-Computer -UnjoinDomainCredential $using:credDomain -Confirm:$false -Force
        }
        return $true
    }

    Write-Info "Host '$hostname' is not in the domain $Domain"
    return $false
}

# Stops all the VM's running on the specifies host and then removes them.
function Remove-VirtualMachinesFromHost($Hst, $credlocal)
{
    $hostname = $Hst.'Hostname(NetBIOS)'

    Write-Info "Stopping all VMs on host '$hostname'"
    Invoke-Command -ComputerName $Hst.HostIP -Credential $credlocal -ErrorAction SilentlyContinue -ScriptBlock {
        Get-VM | Stop-VM -TurnOff -Force
    }
    Write-Info "Removing all VMs from host '$hostname'"

    Invoke-Command -ComputerName $Hst.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock {
        Get-VM | Remove-VM -Confirm:$false -Force
    }
}

# Removes VMs roles from the cluster.
function Remove-VirtualMachinesRolesFromCluster($VMHost, $credlocal)
{
    Write-Info "Removing VM roles from cluster."

    Invoke-Command -ComputerName $VMHost.HostIP -Credential $credlocal -ErrorAction SilentlyContinue -ScriptBlock {
        Get-ClusterGroup | where GroupType -eq VirtualMachine | Remove-ClusterGroup -RemoveResources -Force
    }
}

# Removes disks and partitions.
function Remove-DisksAndPartitions($Hst, $HostDisks, $credlocal)
{
    $SpecHostDisks = $HostDisks | ? 'Hostname(NetBIOS)' -eq $Hst.'Hostname(NetBIOS)'
    $HostName = $Hst.'Hostname(NetBIOS)'

    foreach ($volume in $SpecHostDisks)
    {
        $DiskNum = $volume.DiskNum
        $IsSystemDisk = $volume.IsSystemDisk
        $DriveLetter = $volume.DriveLetter

        if ($volume.IsSystemDisk -eq 'No')
        {
            Write-Info "Disk $DiskNum on '$HostName': Clear the disk and make it offline."
            $ConfigureDisk = Invoke-Command -ComputerName $Hst.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock {
                Clear-Disk -Number $using:DiskNum -Confirm:$false -RemoveData -ErrorAction SilentlyContinue
                Set-Disk -Number $using:DiskNum -IsOffline $true
            }
        }
        else 
        {
            Write-Info "Removing partition with drive letter $DriveLetter on host '$HostName'"
            $partition = Invoke-Command -ComputerName $Hst.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock {
                Remove-Partition -DriveLetter $using:DriveLetter -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
    }
}

# Remove VM's files from host file system.
function Remove-VMs($Hst, $HostDisks, $credlocal)
{
    Write-Info "Removing VMs from disk."
    
    $SpecHostDisks = $HostDisks | ? 'Hostname(NetBIOS)' -eq $Hst.'Hostname(NetBIOS)'

    foreach ($volume in $SpecHostDisks)
    {
        $DriveLetter = $volume.DriveLetter

        Invoke-Command -ComputerName $Hst.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock {
            Remove-Item "$($using:DriveLetter):\virtual machines" -Recurse -Confirm:$false -Force -ErrorAction SilentlyContinue
        }
    }
}

# Clears host's network teaming.
function Clear-HostNetworkWrap($VMHost, $credlocal)
{
    Write-Info "Clearing Network configuration of Hyper-V host '$($Hst."Hostname(NetBIOS)")'"

    $session = New-PSSession -ComputerName $VMHost.HostIP -Credential $credlocal
 
    Clear-HostNetwork $session
    Remove-PSSession -Session $session
}

# Removes cluster quorum virtual disk.
Function Remove-ClusterQuorum($VMHost, $credlocal, $StorageType, $VMEnvironment)
{
    Write-Info "Remove Cluster Quorum"

    $status = Invoke-Command -Authentication Credssp -ComputerName $VMHost.HostIP -Credential $credlocal -ScriptBlock {
        Set-ClusterQuorum -NoWitness -ErrorAction SilentlyContinue
    }

    $diskNumber = ($VMEnvironment | where {$_.Setting -eq "QuorumDiskNumber"}).Value

    if ($StorageType -eq "Central Storage"){
        $status = Invoke-Command -Authentication Credssp -ComputerName $VMHost.HostIP -Credential $credlocal -ScriptBlock {
            Remove-ClusterResource -Name "Quorum" -Confirm:$false -Force -ErrorAction SilentlyContinue
            $disk = Get-Disk -Number $using:diskNumber
            $disk | Set-Disk -IsOffline $false
            $disk | Set-Disk -IsReadOnly $false
            $disk | Get-Partition | Remove-Partition -Confirm:$false
            $disk | Clear-Disk -RemoveData -Confirm:$false
        }
    }
}

Function Remove-ClusterSharedVolume($VMHost, $credlocal, $StorageType, $VMEnvironment)
{
    Write-Info "Remove Cluster Shared Volume"

    if ($StorageType -eq "Central Storage"){
        $diskNumber = ($VMEnvironment | where {$_.Setting -eq "CSV_DiskNumber"}).Value

        $status = Invoke-Command -Authentication Credssp -ComputerName $VMHost.HostIP -Credential $credlocal -ScriptBlock {
            Remove-ClusterSharedVolume -Name "Disk1" -ErrorAction SilentlyContinue
            Remove-ClusterResource -Name "Disk1" -Confirm:$false -Force -ErrorAction SilentlyContinue
            $disk = Get-Disk -Number $using:diskNumber
            $disk | Set-Disk -IsOffline $false
            $disk | Set-Disk -IsReadOnly $false
            $disk | Get-Partition | Remove-Partition -Confirm:$false
            $disk | Clear-Disk -RemoveData -Confirm:$false
        }
    }
}

# Remove the cluster.
Function Remove-TheCluster($VMEnvironment, $VMHost, $credlocal)
{
    $ClusterIPAddress = ($VMEnvironment | where {$_.Setting -eq "Cluster_IP_Adress"}).Value
            
    Write-Info "Checking if cluster exists."
    $cluster = Invoke-Command -Authentication Credssp -ComputerName $VMHost.HostIP -Credential $credlocal -ScriptBlock {
        Get-Cluster -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
        
    if ($cluster -ne $null){
        Write-Info "Cluster exists $($cluster.Name) destroying it."

        $RemovedResources = Invoke-Command -Authentication Credssp -ComputerName $VMHost.HostIP -Credential $credlocal -ScriptBlock {
            Get-ClusterGroup | Remove-ClusterGroup -RemoveResources -Force -ErrorAction SilentlyContinue
        }

        $RemoveCluster = Invoke-Command -Authentication Credssp -ComputerName $VMHost.HostIP -Credential $credlocal -ScriptBlock {
            Remove-Cluster -Cluster $using:ClusterIPAddress -CleanupAD -Confirm:$false -Force | Out-Null
        }
    }
    else{
        Write-Info "No Cluster exists."
    }
}

# Remove all Virtual disks and the storage pool.
Function Remove-StorageSpaces($VMHost, $credlocal)
{
    Write-Info "Remove virtual disks from hosts."

    $status = Invoke-Command -Authentication Credssp -ComputerName $VMHost.HostIP -Credential $credlocal -ScriptBlock {
        $StoragePool = Get-StoragePool -FriendlyName Pool -ErrorAction SilentlyContinue
        if ($StoragePool){
            Set-StoragePool -FriendlyName Pool -IsReadOnly $false -ErrorAction SilentlyContinue
        }

        Get-VirtualDisk | Remove-VirtualDisk -Confirm:$false
    }

    Write-Info "Remove storage pool."

    $status = Invoke-Command -Authentication Credssp -ComputerName $VMHost.HostIP -Credential $credlocal -ScriptBlock {
        $StoragePool = Get-StoragePool -FriendlyName Pool -ErrorAction SilentlyContinue
        if ($StoragePool){
            Remove-StoragePool -FriendlyName Pool -Confirm:$false
        }
    }
}

try
{
    Write-Host "***************************************************************************************************"
    Write-Host "Hyper-V Environment removal tool version: $global:version"
    Write-Host "This tool erases the Hyper-V environment and all the VMs running on it."
    Write-Host "***************************************************************************************************"

    $currentExecutingPath = Split-Path -Path (Split-Path -Path $MyInvocation.MyCommand.Definition -Parent) -Parent

# Load external scripts
    . "$currentExecutingPath\Deployment\GenericFuncs.ps1"
    . "$currentExecutingPath\Deployment\Logger.ps1"
    . "$currentExecutingPath\Deployment\Hosts.ps1"
    . "$currentExecutingPath\Validation\Validation.ps1"


    $LastSessionInfo = $null
    $LastSessionFile = "$currentExecutingPath\LastSession.xml"

    if (Test-Path $LastSessionFile)
    {
	    $LastSessionInfo = Import-Clixml $LastSessionFile
        Write-Host "Read last session info successfully."
    }

    if ($LastSessionInfo -ne $null)
	{
		$ExcelFilePathName = $LastSessionInfo.ExcelFilePathName
	}

    # Read Excel file path name from user input
    $ExcelFilePathName = ReadExcelFilePathName $ExcelFilePathName

    $ExcelFileName = Split-Path $ExcelFilePathName -Leaf
    $projLogDir = $ExcelFileName.Substring(0, $ExcelFileName.LastIndexOf("."))

    $LogPath = "$currentExecutingPath\Log\$projLogDir"

    New-Item -Path $currentExecutingPath -Name "Log\$projLogDir" -ItemType Directory -Force | Out-Null

    try { 
        Start-Log -LogPath "$LogPath\ClearEnvironment.log"
    } 
    catch { 
	    Write-Host "Failed to create log file at: $LogPath\Clear_Deployment.log"
    } 

    Write-Info "Excel file path name is: $ExcelFilePathName"
    Write-Info "Run from: $currentExecutingPath"

    #Load-HyperVModule

    if (!(Get-Module -ListAvailable -Name ImportExcel)) {
	    Write-Info "ImportExcel Module is now installing..."
	    Import-Module .\ImportExcel-master\Install.ps1
    }

    $HostAdminUser = "Administrator"
    $HostAdminPassword = Read-SecuredString "Host admin user [$HostAdminUser] password" $LastSessionInfo.HostAdminPassword
    $HostAdminPasswordClear = (New-Object PSCredential "User",$HostAdminPassword).GetNetworkCredential().Password

    $DomainAdminUser = "Hercules"
    $DomainAdminPassword = Read-SecuredString "Domain admin user [$DomainAdminUser] password" $LastSessionInfo.DomainAdminPassword
    $DomainAdminPasswordClear = (New-Object PSCredential "User",$DomainAdminPassword).GetNetworkCredential().Password

    $RequiredVMAdminPassword = $LastSessionInfo.RequiredVMAdminPassword

    $shouldRemoveAllPartitions = Read-String 'Erase all partitions also?[y/n]' 'n'

    # Save user's input into XML file
    $LastSessionInfo = New-Object PSobject
    $LastSessionInfo | Add-Member -MemberType NoteProperty -Name "ExcelFilePathName" -Value $ExcelFilePathName
	$LastSessionInfo | Add-Member -MemberType NoteProperty -Name "HostAdminPassword" -Value $HostAdminPassword
    $LastSessionInfo | Add-Member -MemberType NoteProperty -Name "DomainAdminPassword" -Value $DomainAdminPassword
    $LastSessionInfo | Add-Member -MemberType NoteProperty -Name "RequiredVMAdminPassword" -Value $RequiredVMAdminPassword

    $LastSessionInfo | Export-Clixml $LastSessionFile

    ### Import from Excel configuration file ###
    $VMEnvironment = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname Environment
    $Hosts = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname Hosts | where Enabled -eq Yes
    $HostNetwork = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname HostNetwork
    $HostDisks = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname HostDisks

    $StorageType = ($VMEnvironment | where {$_.Setting -eq "Storage_Type"}).Value

    $securedPassword = ConvertTo-SecureString $HostAdminPasswordClear -AsPlainText -Force
    $credlocal = New-Object System.Management.Automation.PSCredential (".\$HostAdminUser", $securedPassword)

    $VMHost = $Hosts[0]
    $OwnerHost = $null
    $environment = ($VMEnvironment | where {$_.Setting -eq "Environment"}).Value
    if ($environment -eq "Cluster"){
        EnableCredSSP $VMEnvironment $Hosts $credlocal

    	$cluster = Invoke-Command -Authentication Credssp -ComputerName $VMHost.HostIP -Credential $credlocal -ErrorAction SilentlyContinue -ScriptBlock { 
            Get-Cluster
        }

        if ($cluster -ne $null)
        {
            $OwnerHost = Get-ClusterOwnerHost $Hosts $HostAdminUser $HostAdminPasswordClear
            Remove-VirtualMachinesRolesFromCluster $OwnerHost $credlocal
            Remove-ClusterQuorum $OwnerHost $credlocal $StorageType $VMEnvironment
            Remove-ClusterSharedVolume $VMHost $credlocal $StorageType $VMEnvironment
            Remove-TheCluster $VMEnvironment $OwnerHost $credlocal
        }
    }


    $HostsToRestart = @()
    foreach ($Hst in $Hosts){
        if (Remove-HostFromDomain $VMEnvironment $Hst $DomainAdminUser $DomainAdminPasswordClear $credlocal)
        {
            $HostsToRestart += $Hst
        }
    }

    if ($HostsToRestart -ne @()){
        Write-Info "Restarting Hyper-V hosts: $($HostsToRestart.HostIP)."
        Restart-Computer -ComputerName $HostsToRestart.HostIP -Credential $credlocal -Force -Wait
    }


    foreach ($Hst in $Hosts){
        Remove-VirtualMachinesFromHost $Hst $credlocal
        if ($shouldRemoveAllPartitions -eq 'y'){
            Remove-DisksAndPartitions $Hst $HostDisks $credlocal
        }
        else {
            Remove-VMs $Hst $HostDisks $credlocal
        }

        Clear-HostNetworkWrap $Hst $credlocal

	    if ($StorageType -eq "Storage Spaces"){
	        if ($environment -eq "Cluster"){
	            Remove-StorageSpaces $Hst $credlocal
	        }
	    }
    }
}
catch [Exception]
{
    $exceptionInfo = (echo $_ | format-list -force | out-string)
    Write-Error $exceptionInfo
}
finally
{
    try{
        Stop-Log
    }
    catch{}
    Write-Host "`nHyper-V removal tool execution ended."
}


