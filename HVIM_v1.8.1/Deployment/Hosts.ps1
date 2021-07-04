# This module contains all the functions that deals with the Hyper-V hosts

<#
	use gpedit.msc and look at the following policy: Computer Configuration ->
	Administrative Templates -> System -> Credentials Delegation -> Allow Fresh Credentials with NTLM-only Server
	Authentication.  Verify that it is enabled and configured with an SPN appropriate for the target computer. For
	example, for a target computer name "myserver.domain.com", the SPN can be one of the following:
	WSMAN/myserver.domain.com or WSMAN/*.domain.com.
#>

# Enables CredSSP authentication on a computer.
# This is used for solving kerberos second hop problem. 
Function EnableCredSSP(
	[Parameter(Mandatory=$true)][Object] $VMEnvironment,
	[Parameter(Mandatory=$true)][Object] $Hosts,
	[Parameter(Mandatory=$true)][Object] $credlocal)
{
    #Add cluster feature on Hyper-V hosts
	foreach ($HostIP in $Hosts.HostIP){
	    #For kerberos second hop problem this should be run on host machine
        Write-Info "Enable WSMan CredSSP on server at $HostIP."
	    Invoke-Command -ComputerName $HostIP -Credential $credlocal -ErrorAction SilentlyContinue -ScriptBlock { 
            Enable-WSManCredSSP -Role Server -Force 
        } | Out-Null
	}

    #First we disable the client role
    Write-Info "Disable WSMan CredSSP on client."
    Disable-WSManCredSSP -Role Client | Out-Null

	#For kerberos second hop problem this should be run on the local (client) machine
    Write-Info "Enable WSMan CredSSP on client."
	Enable-WSManCredSSP -Role Client -DelegateComputer * -Force | Out-Null
}

# Create an Hyper-V cluster
Function Create-Cluster(
	[Parameter(Mandatory=$true)][Object] $VMEnvironment,
	[Parameter(Mandatory=$true)][Object] $Hosts,
	[Parameter(Mandatory=$true)][string] $DomainUser, 
	[Parameter(Mandatory=$true)][string] $DomainPassword)
{
	$ClusterName = ($VMEnvironment | where {$_.Setting -eq "Cluster_Name"}).Value
	$ClusterIPAddress = ($VMEnvironment | where {$_.Setting -eq "Cluster_IP_Adress"}).Value
	$Domain = ($VMEnvironment | where {$_.Setting -eq "Domain_Name"}).Value
	$NetBios = GetNetBios $VMEnvironment

    # The Hyper-V hosts are nodes in the cluster
	$Nodes = @()
	
	foreach ($Node in $Hosts."Hostname(NetBIOS)"){
		$Nodes += "$Node.$Domain"
	}

	$securedPassword = ConvertTo-SecureString $DomainPassword -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential ("$NetBios\$DomainUser", $securedPassword)

    EnableCredSSP $VMEnvironment $Hosts $credlocal

    foreach ($hst in $Hosts)
    {
        $HostIP = $hst.HostIP
        Write-Info "Add failover clustering feature to server at $HostIP."
        $feature = Invoke-Command -ComputerName $HostIP -Credential $credlocal -ScriptBlock { 
            Add-windowsfeature failover-clustering –includeallsubfeature –includemanagementtools
        }
        if ($feature.RestartNeeded -eq  'Yes'){
            Write-Info "Restarting server at $HostIP."
            Restart-Computer -ComputerName $HostIP -Credential $credlocal -Wait -Force -ErrorAction Stop
        }
    }

    $mainHost = $Hosts[0]


    Write-Info "Checking if cluster already exists."
	$cluster = Invoke-Command -Authentication Credssp -ComputerName $mainHost.HostIP -Credential $credlocal -ErrorAction SilentlyContinue -ScriptBlock { 
        Get-Cluster
    }

    if ($cluster -ne $null)
    {
        Write-Warning "Cluster '$($cluster.name)' already exists"
        return
    }

<#
    Write-Info "Running cluster validation tests."
	Invoke-Command -Authentication Credssp -ComputerName $mainHost.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock { 
        Test-Cluster -Node $using:nodes
    }
	if (!$?){
		Write-Error "Test Cluster failed. Will not try to create a cluster."
		return $false
	}
#>
    WaitFor-HostConnection $mainHost.HostIP

    Write-Info "Creating cluster '$ClusterName' on IP $ClusterIPAddress"

    for ($i = 0; $i -lt 5 ;$i = $i + 1)
	{
    	#creating a cluster
	    Invoke-Command -Authentication Credssp -ComputerName $mainHost.HostIP -Credential $credlocal -ScriptBlock {
		    param($ClusterName, $nodes, $ClusterIPAddress)				
		    New-Cluster -Name $ClusterName -Node $nodes[0] -StaticAddress $ClusterIPAddress -NoStorage | Out-Null
       
	    } -ArgumentList $ClusterName, $nodes, $ClusterIPAddress
	    $cluster = Invoke-Command -Authentication Credssp -ComputerName $mainHost.HostIP -Credential $credlocal -ErrorAction SilentlyContinue -ScriptBlock { 
            Get-Cluster
        }

		If ($cluster -eq $null)
        { 
            Write-Info "Failed to create Cluster '$ClusterName' on IP $ClusterIPAddress. Will try again in 10 seconds."        
            Start-Sleep -Seconds 10
        }
        else
        {
			break;
		}
	}

    #AddTo-HostsFile $ClusterIPAddress $ClusterName #Add Cluster host name to host file on client for DNS resolving

	if ($cluster -eq $null){
		Write-Error "Failed to create cluster."
		return
	}

	Write-Success "Cluster $ClusterName created sucessfully."
}

# Get the host that currently owns the cluster.
Function Get-ClusterOwnerHost($hosts, $HostAdminUser, $HostAdminPasswordClear)
{
	$securedPassword = ConvertTo-SecureString $HostAdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential (".\$HostAdminUser", $securedPassword)

    $hst = $hosts[0]

    $OwnerNode = Invoke-Command -ComputerName $hst.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
        $ClusterNodes = (Get-ClusterNode).Name
        foreach ($node in $ClusterNodes)
        {
            $resource = Get-ClusterNode -name $node | Get-ClusterResource  -Name "Cluster IP Address"
            if ($resource -ne $null)
            {
                return $node
            }
        }
        return $null
    }

    $OwnerHost = $Hosts | where 'Hostname(NetBIOS)' -eq $OwnerNode

    return $OwnerHost
}

# Add an Hyper-V host to the domain
Function Add-HostToDomain (
    [Parameter(Mandatory=$true)][Object] $VMEnvironment, 
    [Parameter(Mandatory=$true)][String] $HostIP,  # The Hyper-V host IP
    [Parameter(Mandatory=$true)][String] $HostAdminUser, 
    [Parameter(Mandatory=$true)][String] $HostAdminPasswordClear, 
    [Parameter(Mandatory=$true)][String] $DomainAdminUser, 
    [Parameter(Mandatory=$true)][String] $DomainAdminPasswordClear)
{
	$securedPassword = ConvertTo-SecureString $HostAdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential (".\$HostAdminUser", $securedPassword)

	$Domain = ($VMEnvironment | where {$_.Setting -eq "Domain_Name"}).Value
	$NetBios = GetNetBios $VMEnvironment

	$isAlreadyInDomain = Invoke-Command -ComputerName $HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
		if ((gwmi win32_computersystem).partofdomain){
			if ((gwmi win32_computersystem).domain -eq $using:Domain){
				return $true
			}
		}
		return $false
	}

	if ($isAlreadyInDomain){
		Write-Info "Hyper-V Host with IP $HostIP is already in the domain '$Domain'."
		return $false
	}
	
	Invoke-Command -ComputerName $HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
		$NetworkAdapter = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | where IPAddress -eq $using:HostIP
		$NetworkAdapter.SetDNSDomain($using:Domain) 
	}

	$domainAdmin = "$NetBios\$DomainAdminUser"
	$PasswordDomain = ConvertTo-SecureString $DomainAdminPasswordClear -AsPlainText -Force
	$credDomain = New-Object System.Management.Automation.PSCredential ($domainAdmin, $PasswordDomain)

	Write-Info "Adding Hyper-V Host with IP $HostIP to domain '$Domain'..."
    
	Invoke-Command -ComputerName $HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
		Add-Computer -Domain $using:Domain -LocalCredential $using:credlocal -Credential $using:credDomain
	}

	if (!$?){
		Write-Error $error[0]
        return $false
	}

	Write-Success "Hyper-V Host with IP $HostIP was added to domain '$Domain' successsfully!"

    return $true
}

# Create the Hyper-V host network configuration
# If already exists it will skip it.
Function Create-HostNetwork(
    [Parameter(Mandatory=$true)][Object] $VMEnvironment, 
    [Parameter(Mandatory=$true)][Object] $HostNetwork,
    [Parameter(Mandatory=$true)][Object] $Hst,
    [Parameter(Mandatory=$true)][String] $HostAdminUser, 
    [Parameter(Mandatory=$true)][String] $HostAdminPasswordClear)
{
    $securedPassword = ConvertTo-SecureString $HostAdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential (".\$HostAdminUser", $securedPassword)

    $HostName = $Hst.'Hostname(NetBIOS)'

    try
    {
        $session = New-PSSession -ComputerName $Hst.HostIP -Credential $credlocal
        $ManagementTeamingName = ($HostNetwork | where { $_.'Hostname(NetBIOS)' -eq $Hst.'Hostname(NetBIOS)' -and $_.IsForManagement -eq 'Yes'}).TeamingName

        # Check if failover team with the relevant name already exists.
        $NetTeaming = Invoke-Command -Session $session -ScriptBlock {
            Get-NetLBFOTeam –Name $using:ManagementTeamingName -ErrorAction SilentlyContinue
        }

        # If failover team already exists leave the network as is.
        if ($NetTeaming -ne $null){
            Write-Info "Hyper-V Host '$HostName' network is already configured."
            return $true
        }
    
        $MACAddressRange = Get-FreeMACAddressRange($session)

        #Configure MAC address range for the Hyper-V host
        Write-Info "Configure Hyper-V Host '$HostName' MAC address range."
        Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
            Set-VMHost -MacAddressMinimum $using:MACAddressRange.MacAddressMinimum -MacAddressMaximum $using:MACAddressRange.MacAddressMaximum
        }

        $Environment = ($VMEnvironment | where Setting -eq "Environment").Value

        if ($Environment -match "Standalone") {
            $status = Create-HostNetworkStandalone $session $HostNetwork $Hst
        }
        else {
            $status = Create-HostNetworkCluster $session $HostNetwork $Hst $VMEnvironment
        }

        $status = $status -and (Create-HostNetworkStandaloneExtra $session $HostNetwork $HostName)

        return $status
    } 
    finally 
    {
        Remove-PSSession -Session $session
    }
}

# Create a basic Hyper-V host network for standalone configuration
Function Create-HostNetworkStandalone(
    [Parameter(Mandatory=$true)][Object] $session,
    [Parameter(Mandatory=$true)][Object] $HostNetwork,
    [Parameter(Mandatory=$true)][Object] $Hst)
{
    $ManagementNetAdapterIp = $Hst.HostIP
    $HostName = $Hst.'Hostname(NetBIOS)'
    $ManagementNetAdapterPrefix = GetMaskPrefix($Hst.SubnetMask)
    $ManagementNetAdapterGateway = $Hst.DefaultGateway
    $HostName = $Hst.'Hostname(NetBIOS)'

    $NetAdapterNames = ($HostNetwork | where { $_.'Hostname(NetBIOS)' -eq $HostName -and $_.IsForManagement -eq 'Yes'}).TeamingNICs

	$NetAdapter1 = $NetAdapterNames.Split(',')[0].Trim()
	$NetAdapter2 = $NetAdapterNames.Split(',')[1].Trim()

    $ManagementNetAdapterDnsServers = ($VMEnvironment | where {$_.Setting -eq "Domain_IP"}).Value,($VMEnvironment | where {$_.Setting -eq "SDC_Domain_IP"}).Value

    $ManagementTeamingName = ($HostNetwork | where { $_.'Hostname(NetBIOS)' -eq $HostName -and $_.IsForManagement -eq 'Yes'}).TeamingName
    $ManagementVSwitchName = ($HostNetwork | where { $_.'Hostname(NetBIOS)' -eq $HostName -and $_.IsForManagement -eq 'Yes'}).vSwitchName

    Write-Info "Hyper-V Host '$HostName' network will now be configured for Standalone environment."
    Write-Info "Configuring teaming, vSwitch and virtual network adapter on host '$HostName' for '$NetAdapter1' and '$NetAdapter2' for Load Balancing and Fail Over."

    $NetConfigure = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
        ### Installing MPIO ###
        #Enable-WindowsOptionalFeature –Online –FeatureName MultiPathIO
        
        ### Creating Team from two 10 GbE adapters. The adapter names should be specified as 10GbE1 or whatever name is desired.
        New-NetLBFOTeam –Name $using:ManagementTeamingName –TeamMembers $using:NetAdapter1,$using:NetAdapter2 `
                                –TeamingMode SwitchIndependent –LoadBalancingAlgorithm Dynamic -Confirm:$false
    
        # Assuming all networks will go through this team.
        New-VMSwitch $using:ManagementVSwitchName –NetAdapterName $using:ManagementTeamingName –MinimumBandwidthMode Weight -Confirm:$false

        #Disable VMQ
        Get-NetAdapter | where {$_.HardwareInterface -eq $True} | Disable-NetAdapterVmq -ErrorAction SilentlyContinue

        # Create network adapter and configure it
        New-NetIPAddress -InterfaceAlias "vEthernet ($using:ManagementVSwitchName)" -Confirm:$false `
                        -IPAddress $using:ManagementNetAdapterIp `
                        -PrefixLength $using:ManagementNetAdapterPrefix `
                        -DefaultGateway $using:ManagementNetAdapterGateway

    }

    Invoke-Command -Session $session -ScriptBlock {
        # Set default QoS bucket which will be used by VM traffic
        Set-VMSwitch $using:ManagementVSwitchName –DefaultFlowMinimumBandwidthWeight 5

        # Set weight for management vNIC
        Set-VMNetworkAdapter -ManagementOS -Name $using:ManagementVSwitchName -MinimumBandwidthWeight 5

        # Set DNS addresses
        Set-DnsClientServerAddress -InterfaceAlias "vEthernet ($using:ManagementVSwitchName)" -ServerAddresses $using:ManagementNetAdapterDnsServers

        # Set VLAN as none
        Get-VMNetworkAdapter -ManagementOS $using:ManagementVSwitchName | Set-VMNetworkAdapterVlan -Access -VlanId 0
    }


    if (!$NetConfigure){
        Write-Failure "Failed to configure network on host '$HostName'."
        return $false
    }

    Write-Success "Created network configuration on host '$HostName' sucessfully."

    return $true
}

# Create an extra switch/teaming Hyper-V host network for standalone configuration
Function Create-HostNetworkStandaloneExtra(
    [Parameter(Mandatory=$true)][Object] $session,
    [Parameter(Mandatory=$true)][Object] $HostNetwork,
    [Parameter(Mandatory=$true)][String] $HostName)
{
    $HostNetworkExtra = ($HostNetwork | where { $_.'Hostname(NetBIOS)' -eq $HostName -and $_.IsForManagement -ne 'Yes'})

    foreach ($HostNetwork in $HostNetworkExtra){
        $NetAdapterNames = $HostNetwork.TeamingNICs

	    $NetAdapter1 = $NetAdapterNames.Split(',')[0].Trim()
	    $NetAdapter2 = $NetAdapterNames.Split(',')[1].Trim()

        $TeamingName = $HostNetwork.TeamingName
        $VSwitchName = $HostNetwork.vSwitchName

        Write-Info "Hyper-V Host '$HostName' network will now be configured for additional teaming and vSwitches."
        Write-Info "Adding additional teaming and vSwitch on host '$HostName' for '$NetAdapter1' and '$NetAdapter2'."
        $NetConfigure = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
            New-NetLBFOTeam –Name $using:TeamingName –TeamMembers $using:NetAdapter1,$using:NetAdapter2 –TeamingMode SwitchIndependent –LoadBalancingAlgorithm Dynamic -Confirm:$false
            New-VMSwitch $using:VSwitchName –NetAdapterName $using:TeamingName -Confirm:$false -AllowManagementOS 0
        }

        if (!$NetConfigure){
            Write-Failure "Failed adding additional teaming and vSwitch on host '$HostName'."
            return $false
        }

        Write-Success "Created extra network configuration with vwitch '$VSwitchName' on host '$HostName' sucessfully."
    }

    return $true
}

# Create a basic Hyper-V host network for cluster configuration
Function Create-HostNetworkCluster(
    [Parameter(Mandatory=$true)][Object] $session,
    [Parameter(Mandatory=$true)][Object] $HostNetwork,
    [Parameter(Mandatory=$true)][Object] $Hst,
    [Parameter(Mandatory=$true)][Object] $VMEnvironment)

{
    Write-Info "Hyper-V Host network will now be configured for Cluster environment."

    $ManagementNetAdapterIp = $Hst.HostIP
    $HostName = $Hst.'Hostname(NetBIOS)'
    $ManagementNetAdapterPrefix = GetMaskPrefix($Hst.SubnetMask)
    $ManagementNetAdapterGateway = $Hst.DefaultGateway

    $ClusterNetAdapterVlan = ($VMEnvironment | where {$_.Setting -eq "Heartbit_Network_VLAN"}).Value
    $ClusterNetAdapterIp = CombineIPAddress ($VMEnvironment | where {$_.Setting -eq "Heartbit_Net_Adapter_IP_Prefix"}).Value $ManagementNetAdapterIp
    $ClusterNetAdapterPrefix = GetMaskPrefix ($VMEnvironment | where {$_.Setting -eq "Heartbit_Network_Sunet_Mask"}).Value

    $LiveMigrationNetAdapterVlan = ($VMEnvironment | where {$_.Setting -eq "Live_Migration_Network_VLAN"}).Value
    $LiveMigrationNetAdapterIp = CombineIPAddress ($VMEnvironment | where {$_.Setting -eq "Live_Migration_Net_Adapter_IP_Prefix"}).Value $ManagementNetAdapterIp
    $LiveMigrationNetAdapterPrefix = GetMaskPrefix(($VMEnvironment | where {$_.Setting -eq "Live_Migration_Network_Sunet_Mask"}).Value)

    $ManagementNetAdapterDnsServers = ($VMEnvironment | where {$_.Setting -eq "Domain_IP"}).Value,($VMEnvironment | where {$_.Setting -eq "SDC_Domain_IP"}).Value

    $NetAdapterNames = ($HostNetwork | where { $_.'Hostname(NetBIOS)' -eq $HostName -and $_.IsForManagement -eq 'Yes'}).TeamingNICs
	$NetAdapter1 = $NetAdapterNames.Split(',')[0].Trim()
	$NetAdapter2 = $NetAdapterNames.Split(',')[1].Trim()

    $ManagementTeamingName = ($HostNetwork | where { $_.'Hostname(NetBIOS)' -eq $HostName -and $_.IsForManagement -eq 'Yes'}).TeamingName
    $ManagementVSwitchName = ($HostNetwork | where { $_.'Hostname(NetBIOS)' -eq $HostName -and $_.IsForManagement -eq 'Yes'}).vSwitchName

    Write-Info "Hyper-V Host '$HostName' network will now be configured for Cluster environment."
    Write-Info "Configuring teaming, vSwitch and virtual network adapter on host '$HostName' for '$NetAdapter1' and '$NetAdapter2' for Load Balancing and Fail Over."
    
    Invoke-Command -Session $session -ScriptBlock {
        ### Creating Team from NIC1 & NIC2. The adapter names should be specified as 10GbE1 or whatever name is desired.
        New-NetLBFOTeam –Name $using:ManagementTeamingName –TeamMembers $using:NetAdapter1,$using:NetAdapter2 –TeamingMode SwitchIndependent –LoadBalancingAlgorithm Dynamic -Confirm:$false

        # Assuming all networks will go through this team.
        New-VMSwitch $using:ManagementVSwitchName –NetAdapterName $using:ManagementTeamingName –MinimumBandwidthMode Weight -Notes "Management, cluster, live migration and VM networks." -Confirm:$false

        #Disable VMQ
        Get-NetAdapter | where {$_.HardwareInterface -eq $True} | Disable-NetAdapterVmq -ErrorAction SilentlyContinue

        # Create network adapter and configure it
        New-NetIPAddress -InterfaceAlias "vEthernet ($using:ManagementVSwitchName)" -Confirm:$false `
                        -IPAddress $using:ManagementNetAdapterIp `
                        -PrefixLength $using:ManagementNetAdapterPrefix `
                        -DefaultGateway $using:ManagementNetAdapterGateway
    }

    Invoke-Command -Session $session -ScriptBlock {
        # Set default QoS bucket which will be used by VM traffic
        Set-VMSwitch $using:ManagementVSwitchName –DefaultFlowMinimumBandwidthWeight 5

        # Set weight for management vNIC
        Set-VMNetworkAdapter -ManagementOS -Name $using:ManagementVSwitchName -MinimumBandwidthWeight 5

        # Rename the default VNIC name to Management
        Rename-VMNetworkAdapter -ManagementOS -Name $using:ManagementVSwitchName -NewName Management

        # Set DNS addresses
        Set-DnsClientServerAddress -InterfaceAlias "vEthernet (Management)" -ServerAddresses $using:ManagementNetAdapterDnsServers

        # Set VLAN as none
        Get-VMNetworkAdapter -ManagementOS Management | Set-VMNetworkAdapterVlan -Access -VlanId 0
    }
    Write-Info "Waiting for network settings to be reflected..."
    Start-Sleep -Seconds 5 #A workaround for "No network adapter was found with the given criteria" on Hyper-V 2016
    
    Write-Info "Create and configure the Cluster network."
    Invoke-Command -Session $session -ScriptBlock {
        # Add vNIC for cluster (Heartbit) network
        Add-VMNetworkAdapter -ManagementOS -Name Cluster -SwitchName $using:ManagementVSwitchName

        # Give the new vNIC an IP address (no gateway is configure on purpose)
        New-NetIPAddress -InterfaceAlias "vEthernet (Cluster)" -IPAddress $using:ClusterNetAdapterIp -PrefixLength $using:ClusterNetAdapterPrefix

        # Configure VLAN tag for the vNIC
        Get-VMNetworkAdapter -ManagementOS Cluster | Set-VMNetworkAdapterVlan -Access -VlanId $using:ClusterNetAdapterVlan
    }

    Write-Info "Waiting for network settings to be reflected..."
    Start-Sleep -Seconds 5 #A workaround for "No network adapter was found with the given criteria" on Hyper-V 2016

    Write-Info "Create and configure the Live Migration network."
    Invoke-Command -Session $session -ScriptBlock {
        # Add vNIC for cluster (Heartbit) network
        Add-VMNetworkAdapter -ManagementOS -Name LiveMigration -SwitchName $using:ManagementVSwitchName

        # Give the new vNIC an IP address (no gateway is configure on purpose)
        New-NetIPAddress -InterfaceAlias "vEthernet (LiveMigration)" -IPAddress $using:LiveMigrationNetAdapterIp -PrefixLength $using:LiveMigrationNetAdapterPrefix

        # Configure VLAN tag for the vNIC
        Get-VMNetworkAdapter -ManagementOS LiveMigration | Set-VMNetworkAdapterVlan -Access -VlanId $using:LiveMigrationNetAdapterVlan
    }

<#
    Write-Info "Verify Bandwidth percentage for the newly created NIC's."
    $Bandwidth = Invoke-Command -Session $session -ScriptBlock {
        Get-VMNetworkAdapter -ManagementOS | Select-Object -Property Name,BandwidthPercentage
    }
#>
    return $true
}

# Clear the Hyper-V host network configuration
Function Clear-HostNetwork( [Parameter(Mandatory=$true)][Object] $session )
{
    Write-Info "Deleting existing VMNetworkAdapter, vSwitch and Teaming."

    Invoke-Command -Session $session -ErrorAction Continue -ScriptBlock {
        Get-VMNetworkAdapter -ManagementOS | Remove-VMNetworkAdapter -Confirm:$false
        Get-VMSwitch | Remove-VMSwitch -Force
        Get-NetLbfoTeam | Remove-NetLbfoTeam -Confirm:$false -ErrorAction SilentlyContinue
    }
    # A workaround for the error displayed "Another component made changes to the network driver configuration that interfered with this LBFO change".
    Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock {
        Get-NetLbfoTeam | Remove-NetLbfoTeam -Confirm:$false
    }
}

# Create partitions on the host disks
Function Create-HostPartitions (
    [Parameter(Mandatory=$true)][Object] $HostDisks, 
    [Parameter(Mandatory=$true)][String] $HostName, 
    [Parameter(Mandatory=$true)][String] $HostIP,
    [Parameter(Mandatory=$true)][Object] $credlocal)
{
	Write-Info "Creating disk partitions on host '$HostName'."

    $session = New-PSSession -ComputerName $HostIP -Credential $credlocal

    try
    {
        $SpecHostDisks = $HostDisks | ? 'Hostname(NetBIOS)' -eq $HostName

        foreach ($volume in $SpecHostDisks){
            $DiskNum = $volume.DiskNum
            $DriveLetter = $volume.DriveLetter
            $IsSystemDisk = $volume.IsSystemDisk

            $volumeExist = Invoke-Command -Session $session -ScriptBlock{
                Get-Partition | where DriveLetter -eq $using:DriveLetter 
            }

            if ($volumeExist -ne $null){
                Write-Warning "$DriveLetter already exists on host '$HostName'. skipping it."
                continue
            }

            # We only do this disk configuration actions for non system disks
            if ($volume.IsSystemDisk -eq 'No'){
                Write-Info "Disk $DiskNum on '$HostName': Make it online, Writable and Initialize it to GPT partition style."
                $ConfigureDisk = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock{
                    Set-Disk -Number $using:DiskNum -IsOffline $False
                    Set-Disk -Number $using:DiskNum -IsReadonly $False
                    Clear-Disk -Number $using:DiskNum -Confirm:$false -RemoveData -ErrorAction SilentlyContinue
                    Initialize-Disk -Number $using:DiskNum -PartitionStyle GPT
                }
                if (!$?){
                    Write-Warning "Failed to initialize disk $DiskNum on host '$HostName'."
                }
            }

            if ($volume.'Size(GB)' -eq 'Rest'){
                $partition = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock{
                    New-Partition -DiskNumber $using:DiskNum -DriveLetter $using:DriveLetter -UseMaximumSize
                }
                if ($partition -ne $null){
                    Write-Success "Created partition '$DriveLetter' on disk $DiskNum with rest of available disk space on host '$HostName' file system successfully."
                }
                else{
                    Write-Error "Failed to create partition '$DriveLetter' on host '$HostName' file system."
                    return $false
                }
            }
            else {
                $partitionSize = $volume.'Size(GB)' * 1GB
                $partition = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock{
                    New-Partition -DiskNumber $using:DiskNum -DriveLetter $using:DriveLetter -Size $using:partitionSize 
                }
                if ($partition -ne $null){
                    Write-Success "Created partition '$DriveLetter' on disk $DiskNum with size $($volume.'Size(GB)')GB on host '$HostName' file system successfully."
                }
                else{
                    Write-Error "Failed to create partition '$DriveLetter' on host '$HostName' file system."
                    return $false
                }
            }
            Write-Info "Formating volume $DriveLetter on host '$HostName'."

            $format = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock{
                Format-Volume -DriveLetter $using:DriveLetter -Confirm:$false
            }

            if ($format -ne $null){
                Write-Success "Successfully Formated volume $DriveLetter on host '$HostName'."
            } 
            else{
                Write-Error "Failed to format volume '$DriveLetter' on host '$HostName'."
                return $false
            }
            $sharePath = "$($DriveLetter):\"
            $shareName = "$DriveLetter"+'$'
            $fileShare = Invoke-Command -Session $session -ErrorAction Stop -ScriptBlock{
                New-SmbShare -Name $using:shareName -Path $using:sharePath -FullAccess Administrator -ErrorAction SilentlyContinue
            }
        }
    }
    finally
    {
        Remove-PSSession -Session $session
    }

    return $true
}

# Copy template files to an Hyper-V host
Function Copy-TemplateFiles(
		[Parameter(Mandatory=$true)][Object]$VMs,
		[Parameter(Mandatory=$true)][String]$TemplatePathOnClient, 
		[Parameter(Mandatory=$true)][String]$TemplatePathOnServer, 
		[Parameter(Mandatory=$true)][String]$HostIP,
        [Parameter(Mandatory=$true)][String]$HostName,
        [Parameter(Mandatory=$true)][Object]$credlocal)
{
	Write-Info "Copying template (VHDX) files to the host '$HostName'."

	If (!(Test-Path -Path $TemplatePathOnClient -PathType Container))
	{
		Write-Error "Template path $TemplatePathOnClient doesn't exist on client file system."
		return $false
	}

	#$fileSharePathOnServer = "\\$HostIP\" + $TemplatePathOnServer.Replace(":","$")
    $FileSharePathOnServer = "\\$HostIP\" + "$($TemplatePathOnServer[0])$"

    try
    {
        $MappedDrivePathOnServer = "$($HostName):$($TemplatePathOnServer.Substring(2))"
	    If (!(Test-Path -Path $MappedDrivePathOnServer -PathType Container))
	    {
            $currUser = whoami | Split-Path -Leaf

            if ($currUser -eq $credlocal.UserName){
                New-PSDrive –Name $HostName –PSProvider FileSystem –Root $FileSharePathOnServer
            }
            else{
                New-PSDrive -Credential $credlocal –Name $HostName –PSProvider FileSystem –Root $FileSharePathOnServer
            }

		    Write-Info "Template path $MappedDrivePathOnServer doesn't exist on server file system. Will try to create it."
		    $dirItem = New-Item -Path $MappedDrivePathOnServer -ItemType Directory -Force -ErrorAction Stop
		    if ($dirItem -eq $null)
		    {
			    Write-Error "Failed to create path $MappedDrivePathOnServer on server file system."
			    return $false
		    }
	    }

	    $templateFilesUsed = @()
        $hostRelatedVMS = $VMs | where HostIP -eq $HostIP

	    foreach ($OSProfile in ($hostRelatedVMS.OSProfile | sort-object | Get-Unique -asstring)){
		    $templateFilesUsed +=  GetTemplateFileName $OSProfile
	    }

	    Foreach ($templateFileOrDirectory in (Get-Item -Path "$TemplatePathOnClient\*"))
	    {
		    $templateFileName = Split-Path $templateFileOrDirectory -leaf
		    if (!$templateFilesUsed.Contains($templateFileName)){
			    continue
		    }

		    Write-Info "Copying template $templateFileOrDirectory to $MappedDrivePathOnServer, if needed."
		    Copy-FilesBitsTransfer -sourcePath $templateFileOrDirectory -destinationPath $MappedDrivePathOnServer

		    if (!$?){
			    Write-Error "Failed to copy template '$templateFileOrDirectory' to host '$HostName'."
			    return $false
		    }
		    Write-Success "Template '$templateFileOrDirectory' verified on the host '$HostName'."

	    }

        # Copy VHDXTool for fast creating VHDX files
        Copy-FilesBitsTransfer -sourcePath "$TemplatePathOnClient\Tools" -destinationPath $MappedDrivePathOnServer
    }
    finally
    {
        Remove-PSDrive –Name $HostName
    }

	return $?
}

# Configure Hyper-V hosts sequencialy
Function Configure-HyperVHosts($VMs, $currentExecutingPath, $Hosts, $HostNetwork, $HostDisks, $LogPath, $Domain, $VMEnvironment, $TemplatePathOnClient, 
								$TemplatePathOnServer, $HostAdminUser, $HostAdminPasswordClear)
{
	Write-Info "Configuring Hyper-V hosts..."

    $securedPassword = ConvertTo-SecureString $HostAdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential ($HostAdminUser, $securedPassword)

    $UseJobs = ($VMEnvironment | where {$_.Setting -eq "UseJobs"}).Value 

    if ($UseJobs -eq 'No')
    {
 	    foreach ($Hst in $Hosts){
 		    AddToAddRemove "HYPERV" "mc4lea" "1.0" $Hst.HostIP $Hst.'Hostname(NetBIOS)' $credlocal | Out-Null

		    $status = Create-HostNetwork $VMEnvironment $HostNetwork $Hst $HostAdminUser $HostAdminPasswordClear
		    if (!$status){
			    Write-Error "Failed to create host network for '$($Hst.'Hostname(NetBIOS)')'. Exiting..."
			    exit
		    }
		    WaitFor-HostConnection $Hst.HostIP

            $status = Create-HostPartitions $HostDisks $Hst.'Hostname(NetBIOS)' $Hst.HostIP $credlocal
		    if (!$status){
			    Write-Error "Failed to create host disk partitions for '$($Hst.'Hostname(NetBIOS)')'. Exiting..."
			    exit
		    }

		    if ($VMs -ne $null)
		    {
			    $status = Copy-TemplateFiles $VMs $TemplatePathOnClient $TemplatePathOnServer $Hst.HostIP $Hst.'Hostname(NetBIOS)' $credlocal
			    if (!$status){
				    Write-Error "Failed to copy Hyper-V templates to host '$($Hst.'Hostname(NetBIOS)')'. Exiting..."
				    exit
			    }
		    }
        }
        return
    }

    # Configure Hyper-V hosts using jobs (this make it in parallel)

  	$HostJobs = @()

 	foreach ($Hst in $Hosts){
        $hostName = $Hst.'Hostname(NetBIOS)'
        Write-Info "Creating job for configuring host '$hostName'. Log will be written in $hostName.log file."
		$HostJobs += Start-Job -Name $hostName -ErrorAction Stop -ScriptBlock {
			param($currentExecutingPath, $VMs, $Hst, $LogPath, $Domain, $VMEnvironment, $HostNetwork, $HostDisks, `
                    $TemplatePathOnClient, $TemplatePathOnServer, $HostAdminUser, $HostAdminPasswordClear, $credlocal)
            try
            {
			    . "$currentExecutingPath\Deployment\Logger.ps1"
                . "$currentExecutingPath\Deployment\GenericFuncs.ps1"
			    . "$currentExecutingPath\Deployment\VMDeploy.ps1"
                . "$currentExecutingPath\Deployment\Hosts.ps1"
			    Start-Log -LogPath "$LogPath\$($Hst.'Hostname(NetBIOS)').log"
			    Load-HyperVModule

			    AddToAddRemove "HYPERV" "mc4lea" "1.0" $Hst.HostIP $Hst.'Hostname(NetBIOS)' $credlocal | Out-Null

			    $status = Create-HostNetwork $VMEnvironment $HostNetwork $Hst.'Hostname(NetBIOS)' $Hst.HostIP $Hst.DefaultGateway `
                                            $Hst.SubnetMask $HostAdminUser $HostAdminPasswordClear
			    if (!$status){
				    Write-Error "Failed to create host network for '$($Hst.'Hostname(NetBIOS)')'. Exiting..."
				    exit
			    }
			    WaitFor-HostConnection $Hst.HostIP

                $status = Create-HostPartitions $HostDisks $Hst.'Hostname(NetBIOS)' $Hst.HostIP $credlocal
			    if (!$status){
				    Write-Error "Failed to create host disk partitions for '$($Hst.'Hostname(NetBIOS)')'. Exiting..."
				    exit
			    }

			    if ($VMs -ne $null)
			    {
				    $status = Copy-TemplateFiles $VMs $TemplatePathOnClient $TemplatePathOnServer $Hst.HostIP $Hst.'Hostname(NetBIOS)' $credlocal
				    if (!$status){
					    Write-Error "Failed to copy Hyper-V templates to host '$($Hst.'Hostname(NetBIOS)')'. Exiting..."
					    exit
				    }
			    }

			    Stop-Log
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

		} -ArgumentList $currentExecutingPath, $VMs, $Hst, $LogPath, $Domain, $VMEnvironment, $HostNetwork, $HostDisks, `
                        $TemplatePathOnClient, $TemplatePathOnServer, $HostAdminUser, $HostAdminPasswordClear, $credlocal
	}
	
	$continue = $true
    while ($continue) {
        foreach ($job in $HostJobs) {
            Receive-Job -Job $job
            if ($Job.State -eq "Completed"){
                Remove-Job -Job $Job
            }

            $NotCompletedJobs = $HostJobs | where State -ne "Completed"
            if ($NotCompletedJobs -eq $null){
                $continue = $false
                break
            }
        }

        $HostJobs = $HostJobs | where State -ne Completed

        Sleep 1        
    }

}

#Restart Hyper-V hosts
Function Restart-Computers($VMEnvironment, $HostsToRestart, $HostAdminUser, $HostAdminPasswordClear)
{
	Write-Info "Restarting Hyper-V hosts..."

    $UseJobs = ($VMEnvironment | where {$_.Setting -eq "UseJobs"}).Value 

    if ($UseJobs -eq 'No') # Restart will be done sequencially
    {
        foreach ($Hst in $HostsToRestart){
            Restart-ComputerWait $Hst.HostIP $Hst.'Hostname(NetBIOS)' $HostAdminUser $HostAdminPasswordClear | Out-Null
        }

        return
    }

    # Restarting Hyper-V hosts using jobs (this make it in parallel)

	$HostJobs = @()

    foreach ($Hst in $HostsToRestart){
        $hostName = $Hst.'Hostname(NetBIOS)'
        Write-Info "Creating job for restarting host '$hostName'. Log will be written in $hostName.log file."
		$HostJobs += Start-Job -Name $hostName -ErrorAction Stop -ScriptBlock {
		    param($currentExecutingPath, $Hst, $LogPath, $HostAdminUser, $HostAdminPasswordClear)
            try
            {
		        . "$currentExecutingPath\Deployment\Logger.ps1"
                . "$currentExecutingPath\Deployment\GenericFuncs.ps1"
		        Start-Log -LogPath "$LogPath\$($Hst.'Hostname(NetBIOS)').log"
		        Load-HyperVModule

                Restart-ComputerWait $Hst.HostIP $Hst.'Hostname(NetBIOS)' $HostAdminUser $HostAdminPasswordClear | Out-Null
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

        } -ArgumentList $currentExecutingPath, $Hst, $LogPath, $HostAdminUser, $HostAdminPasswordClear
    }
	
    # Read the output of the jobs and remove the jobs that have completed
	$continue = $true
    while ($continue) {
        foreach ($job in $HostJobs) {
            Receive-Job -Job $job
            if ($Job.State -eq "Completed"){
                Remove-Job -Job $Job
            }

            $NotCompletedJobs = $HostJobs | where State -ne "Completed"
            if ($NotCompletedJobs -eq $null){
                $continue = $false
                break
            }
        }

        $HostJobs = $HostJobs | where State -ne Completed

        Sleep 1  # Wait 1 sec for each iteration        
    }
}

#Configure the load balancing policy for the cluster
Function Configure-LoadBalancePolicy(
    [Parameter(Mandatory=$true)][Object] $hst,  # The Hyper-V host IP
    [Parameter(Mandatory=$true)][String] $HostAdminUser, 
    [Parameter(Mandatory=$true)][String] $HostAdminPasswordClear)
{
	Write-Info "Configuring Load Balancing policy for Hyper-V host '$($hst.'Hostname(NetBIOS)')'."

	$securedPassword = ConvertTo-SecureString $HostAdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential (".\$HostAdminUser", $securedPassword)

	$ret = Invoke-Command -ComputerName $hst.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
    	Set-MSDSMGlobalDefaultLoadBalancePolicy -Policy LB
	}
}

#Create shared storage pool
Function Create-StoragePool(
    [Parameter(Mandatory=$true)][Object] $Hst,
    [Parameter(Mandatory=$true)][String] $HostAdminUser, 
    [Parameter(Mandatory=$true)][String] $HostAdminPasswordClear)
{
	$securedPassword = ConvertTo-SecureString $HostAdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential (".\$HostAdminUser", $securedPassword)

    $StoragePool = Invoke-Command -Authentication Credssp -ComputerName $hst.HostIP -Credential $credlocal -ScriptBlock {
        Get-StoragePool -FriendlyName Pool -ErrorAction SilentlyContinue
    }
        
    if ($StoragePool -ne $null){
        Write-Info "Storage Pool already exists."
        return
    }

	Write-Info "Creating Storage Pool."

	$StoragePool = Invoke-Command -ComputerName $hst.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
    	$PhysicalDisks = Get-PhysicalDisk | where CanPool -eq $True | where BusType -ne USB | Sort-Object -Property FriendlyName
        if ($PhysicalDisks -eq $null){
            return $null
        }
        New-StoragePool -FriendlyName 'Pool' -StorageSubsystemFriendlyName "Clustered Windows Storage*" -PhysicalDisks $PhysicalDisks -LogicalSectorSizeDefault 4096 -ErrorAction Stop
	}
    if ($StoragePool.IsReadOnly -eq $true)
    {
        Write-Info "Wating for Storage Pool to be created..."
        while ($StoragePool.IsReadOnly -eq $true)
        {
            Start-Sleep -Seconds 1
            $StoragePool = Invoke-Command -ComputerName $hst.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
                Get-StoragePool -Name Pool
	        }
        }
    }
}

#Create the quorum volume
Function Create-QuorumVolume(
    [Parameter(Mandatory=$true)][Object] $Hst,  # The Hyper-V host
    [Parameter(Mandatory=$true)][String] $HostAdminUser, 
    [Parameter(Mandatory=$true)][String] $HostAdminPasswordClear)

{
	$securedPassword = ConvertTo-SecureString $HostAdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential (".\$HostAdminUser", $securedPassword)

    $Quorum = Invoke-Command -Authentication Credssp -ComputerName $Hst.HostIP -Credential $credlocal -ScriptBlock {
        Get-VirtualDisk -FriendlyName Quorum -ErrorAction SilentlyContinue
    }
        
    if ($Quorum -ne $null){
        Write-Info "Quorum disk already exists."
        return
    }

    Write-Info "Creating Quorum disk."

	$status = Invoke-Command -ComputerName $Hst.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{

        $VirtualDisk = New-VirtualDisk -FriendlyName 'Quorum' -ResiliencySettingName Mirror -NumberOfDataCopies 2 -Size 2GB -ProvisioningType Fixed -StoragePoolFriendlyName 'Pool'
        $disk = $VirtualDisk |  Get-Disk
        $partition = $disk | New-Partition -UseMaximumSize -DriveLetter 'W'

        $clusterResource = Get-ClusterResource | where name -like "*(Quorum)" 
        $clusterResource | Suspend-ClusterResource

        $partition | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'Quorum' -Confirm:$false

        $clusterResource | Resume-ClusterResource

        $QuorumResourceName = (Get-ClusterResource | where name -like "*(Quorum)").name
        Set-ClusterQuorum -DiskWitness $QuorumResourceName
    }
}

#Create the quorum volume on a LUN
Function Create-CentralQuorumVolume(
    [Parameter(Mandatory=$true)][Object] $Hst,  # The Hyper-V host
    [Parameter(Mandatory=$true)][String] $HostAdminUser, 
    [Parameter(Mandatory=$true)][String] $HostAdminPasswordClear,
    [Parameter(Mandatory=$true)][Object] $VMEnvironment)

{
	$securedPassword = ConvertTo-SecureString $HostAdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential (".\$HostAdminUser", $securedPassword)

    $Quorum = Invoke-Command -Authentication Credssp -ComputerName $Hst.HostIP -Credential $credlocal -ScriptBlock {
        Get-Volume -FileSystemLabel Quorum -ErrorAction SilentlyContinue
    }
        
    if ($Quorum -ne $null){
        Write-Info "Quorum disk already exists."
        return
    }

    Write-Info "Creating Quorum disk."

    $diskNumber = ($VMEnvironment | where {$_.Setting -eq "QuorumDiskNumber"}).Value

	$status = Invoke-Command -ComputerName $Hst.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{

        $disk = Get-Disk -Number $using:diskNumber
        $disk | Clear-Disk -RemoveData -Confirm:$false -ErrorAction SilentlyContinue
        $disk | Initialize-Disk -PartitionStyle MBR
        $partition = $disk | New-Partition -UseMaximumSize -DriveLetter 'W'

        $partition | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'Quorum' -Confirm:$false
    }

	$status = Invoke-Command -ComputerName $Hst.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{

        $disk = Get-Disk -Number $using:diskNumber
        $ClusterDisk = $disk | Add-ClusterDisk
        $ClusterDisk.Name = 'Quorum'
    }

    $status = Invoke-Command -ComputerName $Hst.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
           Set-ClusterQuorum -DiskWitness 'Quorum'
    }
}

#Create the CSV (Cluster Shared Volume)
Function Create-ClusterSharedVolume(
    [Parameter(Mandatory=$true)][Object] $Hst,  # The Hyper-V host IP
    [Parameter(Mandatory=$true)][String] $HostAdminUser, 
    [Parameter(Mandatory=$true)][String] $HostAdminPasswordClear)
{
	$securedPassword = ConvertTo-SecureString $HostAdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential (".\$HostAdminUser", $securedPassword)

    $CSV = Invoke-Command -Authentication Credssp -ComputerName $Hst.HostIP -Credential $credlocal -ScriptBlock {
        Get-VirtualDisk -FriendlyName Disk1 -ErrorAction SilentlyContinue
    }
        
    if ($CSV -ne $null){
        Write-Info "Cluster Shared Volume already exists."
        return
    }

    Write-Info "Creating Cluster Shared Volume."

	$status = Invoke-Command -ComputerName $Hst.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{

        $VirtualDisk = New-VirtualDisk -FriendlyName 'Disk1' -ResiliencySettingName Parity -UseMaximumSize -ProvisioningType Fixed -StoragePoolFriendlyName 'Pool' -Interleave 64KB
        $disk = $VirtualDisk |  Get-Disk
        $partition = $disk | New-Partition -UseMaximumSize
        
        $clusterResource = Get-ClusterResource | where name -like "*(Disk1)" 
        $clusterResource | Suspend-ClusterResource

        $partition | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'Volume1' -AllocationUnitSize 64KB -Confirm:$false

        $clusterResource | Resume-ClusterResource

        $clusterResource | Add-ClusterSharedVolume
    }
}

#Create the CSV (Cluster Shared Volume) on a LUN
Function Create-CentralClusterSharedVolume(
    [Parameter(Mandatory=$true)][Object] $Hst,  # The Hyper-V host IP
    [Parameter(Mandatory=$true)][String] $HostAdminUser, 
    [Parameter(Mandatory=$true)][String] $HostAdminPasswordClear,
    [Parameter(Mandatory=$true)][Object] $VMEnvironment)

{
	$securedPassword = ConvertTo-SecureString $HostAdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential (".\$HostAdminUser", $securedPassword)

    $CSV = Invoke-Command -Authentication Credssp -ComputerName $Hst.HostIP -Credential $credlocal -ScriptBlock {
        Get-Volume -FileSystemLabel Volume1 -ErrorAction SilentlyContinue
    }
        
    if ($CSV -ne $null){
        Write-Info "Cluster Shared Volume already exists."
        return
    }

    Write-Info "Creating Cluster Shared Volume."
    $diskNumber = ($VMEnvironment | where {$_.Setting -eq "CSV_DiskNumber"}).Value

	$status = Invoke-Command -ComputerName $Hst.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{

        $disk = Get-Disk -Number $using:diskNumber
        $disk | Clear-Disk -RemoveData -Confirm:$false -ErrorAction SilentlyContinue
        $disk | Initialize-Disk -PartitionStyle GPT
        $partition = $disk | New-Partition -UseMaximumSize
        $partition | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'Volume1' -AllocationUnitSize 64KB -Confirm:$false
    }

	$status = Invoke-Command -ComputerName $Hst.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{

        $disk = Get-Disk -Number $using:diskNumber
        $ClusterDisk = $disk | Add-ClusterDisk
        $ClusterDisk.Name = "Disk1"

        $ClusterDisk | Add-ClusterSharedVolume
    }
}

#Configure cluster network names
Function Configure-ClusterNetwork(
    [Parameter(Mandatory=$true)][Object] $hst,  # The Hyper-V host IP
    [Parameter(Mandatory=$true)][String] $HostAdminUser, 
    [Parameter(Mandatory=$true)][String] $HostAdminPasswordClear)
{

    Write-Info "Configuring Cluster network names and Migration Network Order."

	$securedPassword = ConvertTo-SecureString $HostAdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential (".\$HostAdminUser", $securedPassword)

	$status = Invoke-Command -ComputerName $hst.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{

        #Rename the Management network
        $NetworkName = (Get-ClusterNetworkInterface | ? name -like "*(Management)").Network[0].Name
        if ((Get-ClusterNetwork $NetworkName).name -ne "Management"){
            (Get-ClusterNetwork $NetworkName).name = "Management"
        }

        #Rename the Cluster network
        $NetworkName = (Get-ClusterNetworkInterface | ? name -like "*(Cluster)").Network[0].Name
        if ((Get-ClusterNetwork $NetworkName).name -ne "Cluster"){
            (Get-ClusterNetwork $NetworkName).name = "Cluster"
        }

        #Rename the LiveMigration network
        $NetworkName = (Get-ClusterNetworkInterface | ? name -like "*(LiveMigration)").Network[0].Name
        if ((Get-ClusterNetwork $NetworkName).name -ne "LiveMigration"){
            (Get-ClusterNetwork $NetworkName).name = "LiveMigration"
        }
    }

    $status = Invoke-Command -ComputerName $hst.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{

        (Get-ClusterNetwork "LiveMigration").metric = 39800

        # Change the order of the networks in the Live Migration sessiong
        Get-ClusterResourceType -Name “Virtual Machine” | Set-ClusterParameter -Name MigrationNetworkOrder `
        -Value ([String]::Join(“;”,(Get-ClusterNetwork -Name “LiveMigration”).ID,(Get-ClusterNetwork -Name “Cluster”).ID,(Get-ClusterNetwork -Name “Management”).ID))

        #Exclude Management network
        Get-ClusterResourceType -Name “Virtual Machine” | Set-ClusterParameter -Name MigrationExcludeNetworks -Value ([String]::Join(“;”,(Get-ClusterNetwork "Management").ID))

        #Configure cash to 1024MB to read from the CSV
        (Get-Cluster).blockcachesize = 1024
    }

}

 Function Add-NodesToCluster (
 	[Parameter(Mandatory=$true)][Object] $VMEnvironment,
    [Parameter(Mandatory=$true)][Object] $Hosts,  
    [Parameter(Mandatory=$true)][String] $HostAdminUser, 
    [Parameter(Mandatory=$true)][String] $HostAdminPasswordClear)
{
    Write-Info "Adding additional nodes to the Cluster."
    $hst = $Hosts[0]

	$securedPassword = ConvertTo-SecureString $HostAdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential (".\$HostAdminUser", $securedPassword)

	$Domain = ($VMEnvironment | where {$_.Setting -eq "Domain_Name"}).Value

	$status = Invoke-Command -ComputerName $hst.HostIP -Authentication Credssp -Credential $credlocal -ErrorAction Stop -ScriptBlock{
        $ClusterNodes = Get-ClusterNode

	    foreach ($Node in $using:Hosts."Hostname(NetBIOS)"){
            if ($Node -ne $using:hst.'Hostname(NetBIOS)') {
                if ($Node -notin $ClusterNodes.Name){
                    Add-ClusterNode -Name "$Node.$($using:Domain)" -NoStorage
                }
            }
	    }
    }
 }