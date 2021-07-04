# This module deals with deploying regular VMs, and install OS on them.

#Create the virtual machine
Function Create-VirtualMachine{
	param( [Parameter(Mandatory=$true)][Object]$VMConfig, 
            [Parameter(Mandatory=$true)][Object]$VMEnvironment,
            [Parameter(Mandatory=$true)][Object]$credlocal)

	# VM Name
	$VMName = $VMConfig.ComputerName

	# Hyper-V host
	$HostIP = $VMConfig.HostIP

	# Path to put VM vrtial disks
	$VMPath = $VMConfig.Volume

	$VMSwitchName = $VMConfig.vSwitchName 

	######################################################
	###           VM Creation and Configuration        ###
	######################################################

	## Creation of the VM
	# Creation without VHD and with a default memory value (will be changed a    fter)

	Write-Info "Creating Virtual Machine '$VMName' at '$VMPath' on host '$HostIP'."

    $session = New-PSSession -ComputerName $HostIP -Credential $credlocal

    try
    {
	    $VMAlreadyExist = Invoke-Command -Session $session -ScriptBlock{
							    Get-VM $using:VMName -ErrorAction SilentlyContinue
						    }
	    if ($VMAlreadyExist -ne $null ){
		    Write-Warning "VM with the same name '$VMName' already exists."
		    $answer = Read-Host "Do you want to continue?[y/n]"
		    if ($answer -ne 'y'){
			    exit
		    }
	    }

	    If  (IsLinuxOS($VMConfig.OSProfile)){
		    $TemplatePathOnServer = ($VMEnvironment | where {$_.Setting -eq "TemplatePathOnServer"}).Value
		    $SysTemplateName = GetTemplateFileName $VMConfig.OSProfile
		    $SysVHDPath = "$TemplatePathOnServer\$SysTemplateName"
		    $VMPath = "$VMPath\$VMName"

		    $returnInfo = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock{
			    $templateXML = (get-item "$using:SysVHDPath\Virtual Machines\*.xml").Name
			    Import-VM -Path "$using:SysVHDPath\Virtual Machines\$templateXML" -VhdDestinationPath $using:VMPath -VirtualMachinePath $using:VMPath `
                                -SnapshotFilePath $using:VMPath -SmartPagingFilePath $using:VMPath -Copy -GenerateNewId | Out-Null
			    Rename-VM -Name $using:SysTemplateName -NewName $using:VMName | Out-Null
			    Add-VMNetworkAdapter -VMName $using:VMName -SwitchName $using:VMSwitchName
		    } 
	    }
	    else
	    {
		    Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock{
			    New-VM -Name $using:VMName -Path $using:VMPath -NoVHD -Generation 2 -MemoryStartupBytes 1GB -SwitchName $using:VMSwitchName
		    }
	    }

	    if (!$?)
	    {
		    Write-Error "Failed to create $VMName VM. `n$returnInfo"
		    return $false
	    }

	    # Processor Number
	    $ProcessorCount = $VMConfig.Cores

	    # Memory 
	    $StaticMemory = "$($VMConfig.Memory * 1GB)"

	    Write-Info "Configuring settings of Virtual Machine '$VMName'."

	    ## Changing the number of processor and the memory
	    Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock{
		    Set-VM -Name $using:VMName -ProcessorCount $using:ProcessorCount -StaticMemory -MemoryStartupBytes $using:StaticMemory `
				    -AutomaticStartAction Start -AutomaticStopAction Shutdown
	    }
	    if (!$?)
	    {
		    Write-Error "Failed to change setting of $VMName VM."
		    return $false
	    }

	    return $true
    }
    finally
    {
        Remove-PSSession -Session $session
    }
}

# Get the template file name from the template identifier in excel file
Function GetTemplateFileName(
	[Parameter(Mandatory=$true,
				Position=1,
				ParameterSetName='OSProfile',
				ValueFromPipeline=$true)]
				[String]$OSProfile)
{
	$TemplateFileName = "WindowsServer2012R2Template.vhdx" #default

	if ($OSProfile -contains 'WindowsServer2012R2') { 
		$TemplateFileName = "WindowsServer2012R2Template.vhdx"
	}
	if ($OSProfile -contains 'WindowsServer2016') { 
		$TemplateFileName = "WindowsServer2016Template.vhdx"
	}
	elseif ($OSProfile -contains 'Ubuntu') {
		$TemplateFileName = "UbuntuTemplate"
	}

	return $TemplateFileName
}

# Create system disk by copiying the VHDX template file and configuring the VM to boot from it
Function Create-SystemVirtualDisk{
	param(  [Parameter(Mandatory=$true)][Object]$VMConfig, 
			[Parameter(Mandatory=$false)][Object]$VMDisks, 
			[Parameter(Mandatory=$true)][String]$TemplatePath,
            [Parameter(Mandatory=$true)][Object]$credlocal)

	# VM Name
	$VMName = $VMConfig.ComputerName

	# Hyper-V host
	$HostIP = $VMConfig.HostIP

	# Path to put VM vrtial disks
	$VMPath = $VMConfig.Volume

	# Sysprep VHD path (The VHD will be copied to the VM folder)
	$SysTemplateName = GetTemplateFileName $VMConfig.OSProfile
	$SysVHDPath = "$TemplatePath\$SysTemplateName"

	## Copy VHD(X) OS disk
	$VMPathName = $VMPath + "\" + $VMName
	$NewDiskName = "$($VMName)_C.vhdx"

	Write-Info "Converting & copying VHDX $SysVHDPath to $VMPathName\$NewDiskName of VM '$VMName'..."
	Invoke-Command -ComputerName $HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
		Convert-VHD -Path $using:SysVHDPath -DestinationPath "$using:VMPathName\$using:NewDiskName" -VHDType Fixed
		#Convert-VHD -Path $using:SysVHDPath -DestinationPath "$using:VMPathName\$using:NewDiskName" -VHDType Dynamic
	}
	#Resize C Disk
	$VMDisk = $VMDisks | where {$_.ComputerName -eq $VMName -and $_.DriveLetter -eq 'C'}
	if ($VMDisk -ne $null) {
		Invoke-Command -ComputerName $HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
	    	Resize-VHD -Path "$using:VMPathName\$using:NewDiskName" -SizeBytes ($using:VMDisk.Capacity * 1GB)
		}
	}
	Write-Info "Attaching virtual hard disk to VM '$VMName'."

	# Attach the VHD(x) to the VM
	Invoke-Command -ComputerName $HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
		Add-VMHardDiskDrive -VMName $using:VMName -Path "$using:VMPathName\$using:NewDiskName"
	}

	Write-Info "Set '$NewDiskName' virtual hard disk to be the first boot device for '$VMName'."
	# Change the boot order to the VHDX first
	Invoke-Command -ComputerName $HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
		$OsVirtualDrive = Get-VMHardDiskDrive -VMName $using:VMName -ControllerNumber 0
	    Set-VMFirmware -VMName $using:VMName -FirstBootDevice $OsVirtualDrive
	}
}

# Create additional empty virtual disks accoring to specification in VMDisks excel tab
Function Create-AdditionalVirtualDisks{
	param(  [Parameter(Mandatory=$true)][Object]$VMConfig, 
			[Parameter(Mandatory=$true)][Object]$VMDisks, 
			[Parameter(Mandatory=$true)][String]$TemplatePath,
            [Parameter(Mandatory=$true)][Object]$credlocal )

	# VM Name
	$VMName = $VMConfig.ComputerName

	# Hyper-V host
	$HostIP = $VMConfig.HostIP

	# Path to put VM vrtial disks
	$VMPath = $VMConfig.Volume

	### Additional virtual drives
	$DiskDrives  = @()
	foreach ($VMDisk in $VMDisks)
	{
		if ($VMDisk.ComputerName -eq $VMName) {
			$Drive       = New-Object System.Object
			$Drive       | Add-Member -MemberType NoteProperty -Name Path -Value $($VMPath + "\" + $VMName)
			$Drive       | Add-Member -MemberType NoteProperty -Name Size -Value $($VMDisk.Capacity * 1GB)
			$Drive       | Add-Member -MemberType NoteProperty -Name Label -Value $VMDisk.Label
			$Drive       | Add-Member -MemberType NoteProperty -Name DriveLetter -Value $VMDisk.DriveLetter
			$Drive       | Add-Member -MemberType NoteProperty -Name Type -Value Fixed
			$DiskDrives += $Drive
		}
	}

    $diskNum = 1
	Foreach ($Disk in ($DiskDrives | where DriveLetter -ne 'C')){
        if ($Disk.DriveLetter)
        {
    		$DiskPathName = $Disk.Path + "\" + $VMName + "_" + $Disk.DriveLetter + ".vhdx"
        }
        else
        {
        	$DiskPathName = $Disk.Path + "\" + $VMName + "_" + $diskNum + ".vhdx"
        }
		Write-Info "Creating aditional VHD with size $($Disk.Size/1GB)GB at $DiskPathName using VHDXTool."
		Invoke-Command -ComputerName $HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
            cmd /c "$using:TemplatePath\Tools\vhdxtool.exe" create -f "$using:DiskPathName" -s $using:Disk.Size
		}
    
		Write-Info "Attaching '$DiskPathName' to VM '$VMName'."
		# Attach the VHD(x) to the Vm
		Invoke-Command -ComputerName $HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
			Add-VMHardDiskDrive -VMName $using:VMName -Path $using:DiskPathName
		}
        $diskNum++
	}
}

# Create disk partitions and format them
function Create-Partitions{
	param(  [Parameter(Mandatory=$true)]$VMConfig, 
			[Parameter(Mandatory=$true)]$VMDisks,
            [Parameter(Mandatory=$true)][Object]$credlocal)

	$VMName = $VMConfig.ComputerName
	$VM_IPAddress = $VMConfig.PrimaryIP
	$VMName = $VMConfig.ComputerName
	$HostIP = $VMConfig.HostIP

	$DiskNumber = 0

	Foreach ($VMDisk in ($VMDisks | where ComputerName -eq $VMName)){
		$DriveLetter = $VMDisk.DriveLetter
		$Label = $VMDisk.Label

		if($VMDisk.DriveLetter -ne 'C')
		{
			$DiskNumber++
			Write-Info "Make Disk $DiskNumber online and writable of VM '$VMName'."
			Invoke-Command -ComputerName $VM_IPAddress -Credential $credlocal -ErrorAction Stop -ScriptBlock {
				Set-Disk -Number $using:DiskNumber -IsOffline $False
				Set-Disk -Number $using:DiskNumber -IsReadonly $False
			} 
			Write-Info "Initialize Disk $DiskNumber of VM '$VMName'."
			Invoke-Command -ComputerName $VM_IPAddress -Credential $credlocal -ErrorAction Stop -ScriptBlock {
				Initialize-Disk -Number $using:DiskNumber
			} 
			Write-Info "Create new partition on disk $DiskNumber of VM '$VMName'."
			Invoke-Command -ComputerName $VM_IPAddress -Credential $credlocal -ErrorAction Stop -ScriptBlock {
				New-Partition -DiskNumber $using:DiskNumber -DriveLetter $using:DriveLetter -UseMaximumSize
			} 
			Write-Info "Formating volume on drive $DriveLetter of VM '$VMName'."
			Invoke-Command -ComputerName $VM_IPAddress -Credential $credlocal -ErrorAction Stop -ScriptBlock {
                if ($using:Label){
				    Format-Volume -FileSystem NTFS -NewFileSystemLabel "$using:Label" -DriveLetter $using:DriveLetter -Confirm:$false
                }
                else{
				    Format-Volume -FileSystem NTFS -DriveLetter $using:DriveLetter -Confirm:$false
                }
                
			}
		} 
		# Expand C partition
		else { 
				Write-Info "Expanding disk C drive partition of VM '$VMName'."
			    Invoke-Command -ComputerName $VM_IPAddress -Credential $credlocal -ErrorAction Stop -ScriptBlock {
					$CDrivePartition = Get-Partition -DiskNumber $using:DiskNumber | where DriveLetter -eq 'C'
					$SizeMax = ($CDrivePartition | Get-PartitionSupportedSize).SizeMax
					$CDrivePartition | Resize-Partition -Size $SizeMax
                    if ($using:Label){
    					Get-WmiObject win32_volume -Filter "DriveLetter = `"$using:DriveLetter`"" | label $using:Label
                    }
				}
		}
	}
}

# Create virtual Network Cards data structure accoring to specification in VMNetwork excel tab
Function Create-NICs{
	param(  [Parameter(Mandatory=$true)][Object]$VMConfig, 
			[Parameter(Mandatory=$true)][Object]$VMNetwork)

	# VM Name
	$VMName = $VMConfig.ComputerName

	$NICs  = @()

	$NICID = 1
	foreach($netCfg in $VMNetwork)
	{
		if ($netCfg.ComputerName -eq $VMName){
			$NIC   = New-Object System.Object
			$NIC   | Add-Member -MemberType NoteProperty -Name VMSwitch -Value $netCfg.vSwitchName
			$NIC   | Add-Member -MemberType NoteProperty -Name VLAN -Value $netCfg.VLANID
			$NIC   | Add-Member -MemberType NoteProperty -Name NICID -Value $NICID
			$NIC   | Add-Member -MemberType NoteProperty -Name VMQ -Value $False
			$NIC   | Add-Member -MemberType NoteProperty -Name IPsecOffload -Value $false
			$NIC   | Add-Member -MemberType NoteProperty -Name SRIOV -Value $False
			$NIC   | Add-Member -MemberType NoteProperty -Name MacSpoofing -Value $False
			$NIC   | Add-Member -MemberType NoteProperty -Name DHCPGuard -Value $False
			$NIC   | Add-Member -MemberType NoteProperty -Name RouterGuard -Value $False
			$NIC   | Add-Member -MemberType NoteProperty -Name NICTeaming -Value $False
			$NICs += $NIC

			$NICID++
		}
	}

	return $NICs
}

# Add main virtual network adaper to the VM
Function Configure-VMMainNetworkAdapter{
	param( [Parameter(Mandatory=$true)][Object]$VMConfig, 
            [Parameter(Mandatory=$true)][Object]$credlocal )

	$VMName = $VMConfig.ComputerName

	# Hyper-V host
	$HostIP = $VMConfig.HostIP

	### Network Adapters
	# Primary Network interface: VMSwitch 
	$VlanId       = 0
	$VMQ          = $False
	$IPSecOffload = $False
	$SRIOV        = $False
	$MacSpoofing  = $False
	$DHCPGuard    = $False
	$RouterGuard  = $False
	$NicTeaming   = $False
     
	Write-Info "Configure primary network adapter of VM '$VMName'."

	# You can copy/delete the above block and set it for additional NI -ComputerName $HostIP

	## Configure the primary network adapter

	Invoke-Command -ComputerName $HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
		$PrimaryNetAdapter = Get-VM $using:VMName | Get-VMNetworkAdapter

		if ($using:VlanId -gt 0){$PrimaryNetAdapter | Set-VMNetworkAdapterVLAN -Access -VlanId $using:VlanId }
		else{$PrimaryNetAdapter | Set-VMNetworkAdapterVLAN -untagged }

		if ($using:VMQ){$PrimaryNetAdapter | Set-VMNetworkAdapter -VmqWeight 100 }
		Else {$PrimaryNetAdapter | Set-VMNetworkAdapter -VmqWeight 0 }

		if ($using:IPSecOffload){$PrimaryNetAdapter | Set-VMNetworkAdapter -IPsecOffloadMaximumSecurityAssociation 512}
		Else {$PrimaryNetAdapter | Set-VMNetworkAdapter -IPsecOffloadMaximumSecurityAssociation 0}

		if ($using:SRIOV){$PrimaryNetAdapter | Set-VMNetworkAdapter -IovQueuePairsRequested 1 -IovInterruptModeration Default -IovWeight 100}
		Else{$PrimaryNetAdapter | Set-VMNetworkAdapter -IovWeight 0}

		if ($using:MacSpoofing){$PrimaryNetAdapter | Set-VMNetworkAdapter -MacAddressSpoofing on}
		Else {$PrimaryNetAdapter | Set-VMNetworkAdapter -MacAddressSpoofing off}

		if ($using:DHCPGuard){$PrimaryNetAdapter | Set-VMNetworkAdapter -DHCPGuard on}
		Else {$PrimaryNetAdapter | Set-VMNetworkAdapter -DHCPGuard off}

		if ($using:RouterGuard){$PrimaryNetAdapter | Set-VMNetworkAdapter -RouterGuard on}
		Else {$PrimaryNetAdapter | Set-VMNetworkAdapter -RouterGuard off}

		if ($using:NicTeaming){$PrimaryNetAdapter | Set-VMNetworkAdapter -AllowTeaming on}
		Else {$PrimaryNetAdapter | Set-VMNetworkAdapter -AllowTeaming off}
	}
}

# Add additional virtual network adapters to the VM
Function AddConfigure-ExtraNetworkAdapters{
	param(  [Parameter(Mandatory=$true)][Object]$VMConfig, 
            [Parameter(Mandatory=$true)][Object]$VMNetwork,
            [Parameter(Mandatory=$true)][Object]$credlocal )

	# VM Name
	$VMName = $VMConfig.ComputerName

	# Hyper-V host
	$HostIP = $VMConfig.HostIP

	### Network Adapters
	# Primary Network interface: VMSwitch 
	$VlanId       = 0
	$VMQ          = $False
	$IPSecOffload = $False
	$SRIOV        = $False
	$MacSpoofing  = $False
	$DHCPGuard    = $False
	$RouterGuard  = $False
	$NicTeaming   = $False
     
	## Additional NICs
	$extrarNICs  = Create-NICs $VMConfig $VMNetwork

	Write-Info "Adding additional network adapters to VM '$VMName'."

    try
    {
        $session = New-PSSession -ComputerName $HostIP -Credential $credlocal

	    # foreach additional network adapters
	    Foreach ($NetAdapter in $extrarNICs){
		    $NICName = "Network Adapter $($NetAdapter.NICID)"
		    # add the NIC
		    Write-Info "Adding $NICName to VM '$VMName'."
            #$NetAdapterMAC = Get-FreeMACAddress($session)

		    Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock{
			    Add-VMNetworkAdapter -VMName $using:VMName -SwitchName $using:NetAdapter.VMSwitch -Name $using:NICName #-StaticMacAddress $using:NetAdapterMAC
		    }
    
		    Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock{
			    $ExtraNic = Get-VM -Name $using:VMName | Get-VMNetworkAdapter -Name $using:NICName

			    # Configure the NIC regarding the option
			    if ($using:NetAdapter.VLAN -gt 0){$ExtraNic | Set-VMNetworkAdapterVLAN -Access -VlanId $using:NetAdapter.VLAN}
			    else{$ExtraNic | Set-VMNetworkAdapterVLAN -untagged}

			    if ($using:NetAdapter.VMQ){$ExtraNic | Set-VMNetworkAdapter -VmqWeight 100}
			    Else {$ExtraNic | Set-VMNetworkAdapter -VmqWeight 0}

			    if ($using:NetAdapter.IPSecOffload){$ExtraNic | Set-VMNetworkAdapter -IPsecOffloadMaximumSecurityAssociation 512}
			    Else {$ExtraNic | Set-VMNetworkAdapter -IPsecOffloadMaximumSecurityAssociation 0}

			    if ($using:NetAdapter.SRIOV){$ExtraNic | Set-VMNetworkAdapter -IovQueuePairsed 1 -IovInterruptModeration Default -IovWeight 100}
			    Else{$ExtraNic | Set-VMNetworkAdapter -IovWeight 0}

			    if ($using:NetAdapter.MacSpoofing){$ExtraNic | Set-VMNetworkAdapter -MacAddressSpoofing on}
			    Else {$ExtraNic | Set-VMNetworkAdapter -MacAddressSpoofing off}

			    if ($using:NetAdapter.DHCPGuard){$ExtraNic | Set-VMNetworkAdapter -DHCPGuard on}
			    Else {$ExtraNic | Set-VMNetworkAdapter -DHCPGuard off}

			    if ($using:NetAdapter.RouterGuard){$ExtraNic | Set-VMNetworkAdapter -RouterGuard on}
			    Else {$ExtraNic | Set-VMNetworkAdapter -RouterGuard off}

			    if ($using:NetAdapter.NicTeaming){$ExtraNic | Set-VMNetworkAdapter -AllowTeaming on}
			    Else {$ExtraNic | Set-VMNetworkAdapter -AllowTeaming off}
		    }
	    }
    }
    finally 
    {
        Remove-PSSession -Session $session
    }
}

# Configure the integration services of the VM
# Currently, disable time synchronization in case it is required.
Function Configure-IntegrationTools{
	param( [Parameter(Mandatory=$true)][Object]$VMConfig,
            [Parameter(Mandatory=$true)][Object]$credlocal )
    
	$VMName = $VMConfig.ComputerName
	$HostIP = $VMConfig.HostIP

	Write-Info "Configure integration services."

	if ($VMConfig.HostTimeSync -ne "Yes"){
		Invoke-Command -ComputerName $HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
			Get-VMIntegrationService -VMName $using:VMName -Name "Time Synchronization" | Disable-VMIntegrationService
		}
	}
}

# This generic functions is used in order to configure network adapter using WMI
Function Set-VMNetworkConfiguration {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true,
				   Position=1,
				   ParameterSetName='DHCP',
				   ValueFromPipeline=$true)]
		[Parameter(Mandatory=$true,
				   Position=0,
				   ParameterSetName='Static',
				   ValueFromPipeline=$true)]
		[Object]$NetworkAdapter,

		[Parameter(Mandatory=$true,
				   Position=1,
				   ParameterSetName='Static')]
		[String[]]$IPAddress=@(),

		[Parameter(Mandatory=$false,
				   Position=2,
				   ParameterSetName='Static')]
		[String[]]$Subnet=@(),

		[Parameter(Mandatory=$false,
				   Position=3,
				   ParameterSetName='Static')]
		[String[]]$DefaultGateway = @(),

		[Parameter(Mandatory=$false,
				   Position=4,
				   ParameterSetName='Static')]
		[String[]]$DNSServer = @(),

		[Parameter(Mandatory=$false,
				   Position=5,
				   ParameterSetName='Static')]
		[String[]]$HostIP,
        [Parameter(Mandatory=$true)][Object]$credlocal
	)

	$status = Invoke-Command -ComputerName $HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
		$VM = Get-WmiObject -Namespace 'root\virtualization\v2' -Class 'Msvm_ComputerSystem' | Where-Object { $_.ElementName -eq $using:NetworkAdapter.VMName }
		$VMSettings = $VM.GetRelated('Msvm_VirtualSystemSettingData') | Where-Object { $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' }    
		$VMNetAdapters = $VMSettings.GetRelated('Msvm_SyntheticEthernetPortSettingData')

		$NetworkSettings = @()
		foreach ($NetAdapter in $VMNetAdapters) {
			if ($NetAdapter.ElementName -eq $using:NetworkAdapter.Name){
				$NetworkSettings = $NetworkSettings + $NetAdapter.GetRelated("Msvm_GuestNetworkAdapterConfiguration")
				break
			}
		}

		$NetworkSettings[0].IPAddresses = $using:IPAddress
		$NetworkSettings[0].Subnets = $using:Subnet
		$NetworkSettings[0].DefaultGateways = $using:DefaultGateway
		$NetworkSettings[0].DNSServers = $using:DNSServer
		$NetworkSettings[0].ProtocolIFType = 4096
		$NetworkSettings[0].DHCPEnabled = $false

		$Service = Get-WmiObject -Class "Msvm_VirtualSystemManagementService" -Namespace "root\virtualization\v2"
		$setIP = $Service.SetGuestNetworkAdapterConfiguration($VM, $NetworkSettings[0].GetText(1))

		if ($setip.ReturnValue -eq 4096) {
			$job=[WMI]$setip.job 

			while ($job.JobState -eq 3 -or $job.JobState -eq 4) {
				start-sleep 1
				$job=[WMI]$setip.job
			}

			if ($job.JobState -eq 7) {
				return $true
			}
			else {
				$job.GetError()
				return $false
			}
		} elseif($setip.ReturnValue -eq 0) {
			return $true
		}
	}

	return $status
}

# Configure all the network adapters
Function Configure-NetworkAdapters{
	param(  [Parameter(Mandatory=$true)][Object]$VMConfig, 
			[Parameter(Mandatory=$true)][Object]$VMNetwork, 
			[Parameter(Mandatory=$true)][Object]$VMEnvironment,
            [Parameter(Mandatory=$true)][Object]$credlocal)

	$VMName = $VMConfig.ComputerName
	$HostIP = $VMConfig.HostIP
	$VM_IPAddress = $VMConfig.PrimaryIP
	$DefaultGW = $VMConfig.DefaultGateway
	$Subnet = $VMConfig.Subnet
    $PrimaryDNS = ($VMEnvironment | where {$_.Setting -eq "Domain_IP"}).Value

	$DNS = $PrimaryDNS,$($VMConfig.SecondaryDNS)

	Write-Info "Configuring addtional NICs for VM '$VMName'."

	$NICID = 1
	$NetInfoList = $VMNetwork | where ComputerName -eq $VMName

	foreach($NetInfo in $NetInfoList){
		$NextIPAddress = $NetInfo.IP
		$Subnet = $NetInfo.Subnet

		$NICName = "Network Adapter " + $NICID

        $NetworkAdapter = Invoke-Command -ComputerName $HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
			Get-VMNetworkAdapter -VMName $using:VMName -Name $using:NICName
		}

        #Only IP and Subnet should be configured for the other network adapters.
        #However on linux we need to configure also DNS (so we set it as the adapter IP address), otherwise it will cause a network configuration issue.
        $status = $NetworkAdapter | Set-VMNetworkConfiguration -HostIP $HostIP -IPAddress $NextIPAddress -Subnet $Subnet -DNSServer $DNS -credlocal $credlocal -ErrorAction SilentlyContinue # -DefaultGateway $DefaultGW

        $retry = 0
        while ($status.Error -ne $null -And $retry -lt 10){
            $retry++
		    Write-Warning "Failed to configure network adapter '$NICName' on '$VMName'. Will retry in 10 seconds..."
            Start-Sleep 10
		    Write-Info "Trying again to Configure network settings for addtional NIC for VM '$VMName."
            $status = $NetworkAdapter | Set-VMNetworkConfiguration -HostIP $HostIP -IPAddress $NextIPAddress -Subnet $Subnet -DNSServer $DNS -credlocal $credlocal -ErrorAction SilentlyContinue # -DefaultGateway $DefaultGW
        } 

		if ($status.Error -eq $null){ 
			Write-Info "Changed '$NICName' NIC network settings of VM '$VMName'"
		}
		else{ 
            Write-Error "Failed to configure network adapter '$NICName' on '$VMName'"
			Write-Error ($status | format-list -force | out-string)
		}
		$NICID++
	}
}

# Configure the main network adapter
Function Configure-MainNetworkAdapter{
	param(  [Parameter(Mandatory=$true)][Object]$VMConfig, 
			[Parameter(Mandatory=$true)][Object]$VMEnvironment,
            [Parameter(Mandatory=$true)][Object]$credlocal
	)

	$VMName = $VMConfig.ComputerName
	$HostIP = $VMConfig.HostIP
	$VM_IPAddress = $VMConfig.PrimaryIP
	$DefaultGW = $VMConfig.DefaultGateway
	$Subnet = $VMConfig.Subnet
    $PrimaryDNS = ($VMEnvironment | where {$_.Setting -eq "Domain_IP"}).Value
	$DNS = $PrimaryDNS,$($VMConfig.SecondaryDNS)
    
	#network settings on VM
	Write-Info "Configure network settings for main NIC of VM '$VMName'."

    for ($i=0; $i -lt 10; $i++)
    {
        $NetworkAdapter = Invoke-Command -ComputerName $HostIP -Credential $credlocal -ErrorAction SilentlyContinue -ScriptBlock{
        	Get-VMNetworkAdapter -VMName $using:VMName -Name "Network Adapter"
		}
        if ($NetworkAdapter -ne $null)
        {
            break
        }
        else
        {
            Start-Sleep 5
        }
    }

   
    $status = $NetworkAdapter | Set-VMNetworkConfiguration -HostIP $HostIP -IPAddress $VM_IPAddress -Subnet $Subnet -DefaultGateway $DefaultGW -DNSServer $DNS -credlocal $credlocal -ErrorAction SilentlyContinue
    $retry = 0
    while ($status.Error -ne $null -And $retry -lt 10){
        $retry++
		Write-Warning "Failed to configure main network adapter on VM '$VMName'. Will retry in 10 seconds..."
        Start-Sleep 10
		Write-Info "Trying again to Configure network settings for main NIC of VM '$VMName'."
        $status = $NetworkAdapter | Set-VMNetworkConfiguration -HostIP $HostIP -IPAddress $VM_IPAddress -Subnet $Subnet -DefaultGateway $DefaultGW -DNSServer $DNS -credlocal $credlocal -ErrorAction SilentlyContinue
    } 

	if ($status.Error -eq $null){ 
		Write-Info "Changed main NIC network settings of VM '$VMName'"
	}
	else{ 
        Write-Error "Failed to configure main network adapter on VM '$VMName'"
		Write-Error ($status | format-list -force | out-string)
        return $false
	}

	Write-Info "Checking network connection to VM '$VMName' at '$VM_IPAddress'"

    WaitFor-HostConnection $VM_IPAddress

	return $true
}

# Adds/Join VM to the domain
Function Add-ToDomain{
	param(  [Parameter(Mandatory=$true)][Object]$VMConfig, 
			[Parameter(Mandatory=$true)][Object]$VMEnvironment, 
			[Parameter(Mandatory=$true)][String]$VMAdminUser, 
			[Parameter(Mandatory=$true)][String]$VMAdminPassword, 
			[Parameter(Mandatory=$true)][String]$DomainAdminUser,
			[Parameter(Mandatory=$true)][String]$DomainAdminPassword,
            [Parameter(Mandatory=$true)][Object]$credlocal )
	$VMName = $VMConfig.ComputerName
	$HostIP = $VMConfig.HostIP
	$VM_IPAddress = $VMConfig.PrimaryIP

	$Domain = ($VMEnvironment | where {$_.Setting -eq "Domain_Name"}).Value
	$NetBios = GetNetBios $VMEnvironment
  
	$securedPassword = ConvertTo-SecureString $VMAdminPassword -AsPlainText -Force
    
	$VMCredlocal = New-Object System.Management.Automation.PSCredential (".\$VMAdminUser", $securedPassword)

	WaitFor-NetworkInterface $VMName $HostIP $credlocal

	if ($VMConfig.JoinToDomain -eq "Yes" -And $Domain -ne $null) 
	{ 
		Write-Info "Add DNS suffix '$Domain' to main network card of VM '$VMName'."

		Invoke-Command -ComputerName $VM_IPAddress -Credential $VMCredlocal -ErrorAction Stop -ScriptBlock{
			$NetworkAdapter = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | where IPAddress -eq $using:VM_IPAddress
			$NetworkAdapter.SetDNSDomain($using:Domain) 
		}

		$domainAdmin = "$NetBios\$DomainAdminUser"
		$PasswordDomain = ConvertTo-SecureString $DomainAdminPassword -AsPlainText -Force
		$credDomain = New-Object System.Management.Automation.PSCredential ($domainAdmin, $PasswordDomain)


        if ($VMConfig.OrganizationalUnit -eq $null -or $VMConfig.OrganizationalUnit -eq "None")
        {
    		Write-Info "Adding '$VMName' VM to domain '$Domain'..."
		    Invoke-Command -ComputerName $VM_IPAddress -Credential $VMCredlocal -ErrorAction Stop -ScriptBlock{
			    Add-Computer -Domain $using:Domain -LocalCredential $using:credlocal -Credential $using:credDomain
		    }
        }
        else
        {
    		Write-Info "Adding '$VMName' VM to domain '$Domain' to OU $($VMConfig.OrganizationalUnit)..."
            $Domain_IP = ($VMEnvironment | where {$_.Setting -eq "Domain_IP"}).Value
            $OUPath = Invoke-Command -ComputerName $Domain_IP -Credential $credDomain -ErrorAction Stop -ScriptBlock{
                $OrganizationalUnit = $using:VMConfig.OrganizationalUnit

                (Get-ADOrganizationalUnit -Filter 'Name -like $OrganizationalUnit' ).distinguishedname
            }

		    Invoke-Command -ComputerName $VM_IPAddress -Credential $VMCredlocal -ErrorAction Stop -ScriptBlock{
			    Add-Computer -Domain $using:Domain -OUPath $using:OUPath -LocalCredential $using:credlocal -Credential $using:credDomain
		    }
        }


		if ($?){ 
			Write-Info "'$vmname' VM was added to domain '$Domain' successsfully!"
		}
		else{ 
			Write-Error $error[0]
		}
	}
}

# Add a VM as a cluster resource.
Function Add-VMToTheCluster ($VMName, $HostIP, $DomainAdminUser, $DomainAdminPasswordClear, $VMEnvironment)
{
    Write-Info "Adding VM '$VMName' to the cluster."
	$Domain = ($VMEnvironment | where {$_.Setting -eq "Domain_Name"}).Value
    $ClusterIP = ($VMEnvironment | where {$_.Setting -eq "Cluster_IP_Adress"}).Value
	$NetBios = GetNetBios $VMEnvironment

	$securedPassword = ConvertTo-SecureString $DomainAdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential ("$NetBios\$DomainAdminUser", $securedPassword)

	$status = Invoke-Command -Authentication Credssp -ComputerName $HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
        $vmID = (Get-VM $using:VMName).id
        $addedObj = Add-ClusterVirtualMachineRole -VMName $using:VMName -Name $using:VMName -VMId $VMId -Cluster $using:ClusterIP
        if ($addedObj -ne $null){
            return $true
        }

        return $false
    }
    if ($status){
        Write-Success "VM '$VMName' was added to the cluster successfully!"
    } else {
       Write-Failure "Failed to add VM '$VMName' to the cluster."
    }
}


# Deploy regular VM
Function Deploy-RegularVM(
    [Parameter(Mandatory=$true)]$VMConfig, 
	[Parameter(Mandatory=$false)]$VMDisks, 
	[Parameter(Mandatory=$false)]$VMNetwork, 
	[Parameter(Mandatory=$true)]$VMEnvironment,
    [Parameter(Mandatory=$true)]$VMInfo,
    [Parameter(Mandatory=$false)]$JoinToDomain)
{
	Write-Info "Deployment of Virtual Machine '$($VMConfig.ComputerName)' started."

	$securedPassword = ConvertTo-SecureString $VMInfo.VMAdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential (".\$($VMInfo.HostAdminUser)", $securedPassword)

	Create-VirtualMachine $VMConfig $VMEnvironment $credlocal | Out-Null
        
	Configure-IntegrationTools $VMConfig $credlocal
	
    If  (!(IsLinuxOS($VMConfig.OSProfile))){
	    Create-SystemVirtualDisk $VMConfig $VMDisks $VMInfo.TemplatePath $credlocal
    }
	Configure-VMMainNetworkAdapter $VMConfig $credlocal

    if ($VMNetwork -Ne $null)
    {
	    AddConfigure-ExtraNetworkAdapters $VMConfig $VMNetwork $credlocal
    }

    if ($VMDisks -Ne $null)
    {
	    Create-AdditionalVirtualDisks $VMConfig $VMDisks $VMInfo.TemplatePath $credlocal | Out-Null
    }

	Invoke-Command -ComputerName $VMConfig.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
		Start-VM -Name $using:VMConfig.ComputerName
	}

	WaitFor-IntegrationTool $VMConfig.ComputerName $VMConfig.HostIP $credlocal
	WaitFor-NetworkInterface $VMConfig.ComputerName $VMConfig.HostIP $credlocal

	Configure-MainNetworkAdapter $VMConfig $VMEnvironment $credlocal

    if ($VMNetwork -Ne $null)
    {
	    Configure-NetworkAdapters $VMConfig $VMNetwork $VMEnvironment $credlocal
    }

    If  (!(IsLinuxOS($VMConfig.OSProfile))){
        if ($VMDisks -ne $null)
        {
    	    Create-Partitions $VMConfig $VMDisks $credlocal
        }
	    Rename-AdminUser $VMConfig.PrimaryIP $VMConfig.ComputerName $VMInfo.RequiredVMAdminUser $credlocal
        
        Change-AdminUserPassword $VMConfig.PrimaryIP $VMConfig.ComputerName $VMInfo.RequiredVMAdminUser $VMInfo.VMAdminPasswordClear $VMInfo.RequiredVMAdminPasswordClear

	    Rename-ComputerHostName $VMConfig.PrimaryIP $VMConfig.ComputerName $VMInfo.RequiredVMAdminUser $VMInfo.RequiredVMAdminPasswordClear

	    Restart-ComputerWait $VMConfig.PrimaryIP $VMConfig.ComputerName $VMInfo.RequiredVMAdminUser $VMInfo.RequiredVMAdminPasswordClear


        if ($JoinToDomain){
	        Add-ToDomain $VMConfig $VMEnvironment $VMInfo.RequiredVMAdminUser $VMInfo.RequiredVMAdminPasswordClear $VMInfo.DomainAdminUser `
                         $VMInfo.DomainAdminPasswordClear $credlocal

            Restart-ComputerWait $VMConfig.PrimaryIP $VMConfig.ComputerName $VMInfo.RequiredVMAdminUser $VMInfo.RequiredVMAdminPasswordClear
        }
    }
    else
    {
	    Rename-ComputerHostNameLinux $VMConfig.PrimaryIP $VMConfig.ComputerName $VMInfo.RequiredVMAdminUser $VMInfo.RequiredVMAdminPasswordClear | Out-Null
    }
	
    if ($VMInfo.AddToCluster)
    {
        Write-Info "Adding VM $($VMConfig.ComputerName) to the cluster."
        Add-VMToTheCluster $VMConfig.ComputerName $VMConfig.HostIP $VMInfo.DomainAdminUser $VMInfo.DomainAdminPasswordClear $VMEnvironment
    }

	return $true
}


# Deploy all the VMs that needs to be deployed.
Function Deploy-VMs(
    [Parameter(Mandatory=$true)]$currentExecutingPath,
    [Parameter(Mandatory=$true)]$LogPath,
    [Parameter(Mandatory=$true)]$RegularVMs, 
	[Parameter(Mandatory=$false)]$VMDisks, 
	[Parameter(Mandatory=$false)]$VMNetwork, 
	[Parameter(Mandatory=$true)]$VMEnvironment,
	[Parameter(Mandatory=$true)]$hosts,
	[Parameter(Mandatory=$true)]$VMInfo)
{

    $UseJobs = ($VMEnvironment | where {$_.Setting -eq "UseJobs"}).Value 

	if ($UseJobs -eq 'No'){ # The deployment will be sequencial
		foreach ($VMConfig in $RegularVMs){
            $JoinToDomain = $false
            if ($VMConfig.JoinToDomain -eq 'Yes'){
                $JoinToDomain = $true
            }
			if (Deploy-RegularVM $VMConfig $VMDisks $VMNetwork $VMEnvironment $VMInfo $JoinToDomain){
                Write-Success "Finished deployment of '$($VMConfig.ComputerName)' VM sucessfully."
            }
            else
            {
                Write-Failure "Failed to deploy '$($VMConfig.ComputerName)' VM."
            }
		}

		return
	}

    $VMDeployJobs = @()

    foreach ($hst in $hosts) # The deployment will be in pa
    {
        $hostVMs = $RegularVMs | where HostIP -eq $hst.HostIP
        if ($hostVMs -eq $null) # No VM is should be deployed on this host
        {
            continue
        }

        ## Deployment ###
		Write-Info "Creating a job for deployment of host '$($hst.'Hostname(NetBIOS)')' VMs."

        # Runs the Deploy-RegularVM function as a job
        $VMDeployJobs += Start-Job -Name $hst.'Hostname(NetBIOS)' -ScriptBlock {
            param($currentExecutingPath, $LogPath, $VMDisks, $VMNetwork, $VMEnvironment, $VMInfo, $hostVMs, $hst)
            try
            {
			    . "$currentExecutingPath\Deployment\Logger.ps1"
                . "$currentExecutingPath\Deployment\GenericFuncs.ps1"
                . "$currentExecutingPath\Deployment\VMDeploy.ps1"
			    Start-Log -LogPath "$LogPath\$($hst.'Hostname(NetBIOS)').log"
                Load-HyperVModule

                foreach ($VMConfig in $hostVMs)
                {
                    $JoinToDomain = $false
                    if ($VMConfig.JoinToDomain -eq 'Yes'){
                        $JoinToDomain = $true
                    }

                    if (Deploy-RegularVM $VMConfig $VMDisks $VMNetwork $VMEnvironment $VMInfo $JoinToDomain){
                        Write-Success "Finished deployment of '$($VMConfig.ComputerName)' VM."
                    }
                    else
                    {
                        Write-Failure "Failed to deploy '$($VMConfig.ComputerName)' VM."
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
            }
        } -ArgumentList $currentExecutingPath, $LogPath, $VMDisks, $VMNetwork, $VMEnvironment, $VMInfo, $hostVMs, $hst
    }

    # Read the output of the jobs and remove the jobs that have completed
    $continue = $true
    while ($continue) {
        foreach ($job in $VMDeployJobs) {
            Receive-Job -Job $job
            if ($Job.State -eq "Completed"){
                Remove-Job -Job $Job
            }

            $NotCompletedJobs = $VMDeployJobs | where State -ne "Completed"
            if ($NotCompletedJobs -eq $null){
                $continue = $false
                break
            }
        }

        $VMDeployJobs = $VMDeployJobs | where State -ne Completed

        Sleep 1    # Wait 1 sec for each iteration    
    }
}

# Deploy the SDC (SEcondary DC) VM
Function Deploy-SDC(
    [Parameter(Mandatory=$true)]$VMConfig, 
	[Parameter(Mandatory=$false)]$VMDisks, 
	[Parameter(Mandatory=$false)]$VMNetwork, 
	[Parameter(Mandatory=$true)]$VMEnvironment, 
	[Parameter(Mandatory=$true)]$VMInfo)
{

	Write-Info "Deployment of SDC Virtual Machine '$($VMConfig.ComputerName)' started."
    if (!(Deploy-RegularVM $VMConfig $VMDisks $VMNetwork $VMEnvironment $VMInfo $true)){
        Write-Error "Failed to deploy SDC VM."
        return $false;
    }

    $NetBios = GetNetBios $VMEnvironment

    $securedPassword = ConvertTo-SecureString $VMInfo.DomainAdminPasswordClear -AsPlainText -Force
    $credlocal = New-Object System.Management.Automation.PSCredential ("$NetBios\$($VMInfo.DomainAdminUser)", $securedPassword)
    $Domain = ($VMEnvironment | where {$_.Setting -eq "Domain_Name"}).Value

    $DomainAdminUser = "$NetBioss\$($VMInfo.DomainAdminUser)"

    AddHyperVTools $VMConfig.PrimaryIP $DomainAdminUser $VMInfo.DomainAdminPasswordClear
    AddRSATVTools $VMConfig.PrimaryIP $DomainAdminUser $VMInfo.DomainAdminPasswordClear
    $environment = ($VMEnvironment | where {$_.Setting -eq "Environment"}).Value
    if ($environment -eq "Cluster")
    {
        AddFailoverClusterTools $VMConfig.PrimaryIP $DomainAdminUser $VMInfo.DomainAdminPasswordClear
    }

    #First we disable the client role
    Write-Info "Disable WSMan CredSSP on client."
    Disable-WSManCredSSP -Role Client | Out-Null

	#For kerberos second hop problem this should be run on the local (client) machine
    Write-Info "Enable WSMan CredSSP on client."
	Enable-WSManCredSSP -Role Client -DelegateComputer * -Force | Out-Null

    Write-Info "Installing AD-Domain-Services feature on SDC VM."
    $status = Invoke-Command -ComputerName $VMConfig.PrimaryIP -Credential $credlocal -ErrorAction Stop -ScriptBlock {
        Enable-WSManCredSSP -Role Server -Force
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools -WarningAction SilentlyContinue
        Start-Sleep -Seconds 10
    }

    if ($status.Success){
        Write-Info "Promoting SDC VM as a secondary DC."

        $addToDC = Invoke-Command -ComputerName $VMConfig.PrimaryIP -Authentication Credssp -Credential $credlocal -ErrorAction Stop -ScriptBlock {
            Install-ADDSDomainController -CreateDnsDelegation:$false -DatabasePath 'C:\Windows\NTDS' -DomainName $using:Domain `
            -InstallDns:$true -LogPath 'C:\Windows\NTDS' -NoGlobalCatalog:$false -SiteName 'Default-First-Site-Name' `
            -SysvolPath 'C:\Windows\SYSVOL' -NoRebootOnCompletion:$false -Force:$true -CriticalReplicationOnly:$false `
            -SafeModeAdministratorPassword $using:securedPassword -WarningAction SilentlyContinue
        }
    }

    if ($addToDC.Status -eq "Error"){
        return $false
    }
     
    return $true
}

