# This is the main module for Hyper-V Infrastructure Management tool (HVIM).
# It reads all of its input (other than passwords) from the input Excel file.
# The input read from the command line is saved into an XML file. The passwords are encrypted.

param([String]$deployMode='All') #Option are 'All', 'Env' and 'VMs'


function ToolDescription()
{
   	Write-Host "***************************************************************************************************"
	Write-Host "Hyper-V Infrastructure Management tool (HVIM) version: $global:version"
	Write-Host "This tool creates the Hyper-V environment and deploy VMs on it."
	Write-Host "***************************************************************************************************"
}

function CheckPrerequisites()
{
    $AllowFreshCredentials = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredentialsDelegation `
                                              -Name AllowFreshCredentialsWhenNTLMOnly -ErrorAction SilentlyContinue
    
    if ($AllowFreshCredentials -eq $null)
    {
        Write-Error "You must set `"Allow Fresh Credentials with NTLM-only Server Authentication`" in the local security policy."
        return $false
    }

    return $true
}

try
{
	$currentExecutingPath = Split-Path -Path (Split-Path -Path $MyInvocation.MyCommand.Definition -Parent) -Parent

    # Load external scripts
	. "$currentExecutingPath\Deployment\Logger.ps1"
    . "$currentExecutingPath\Deployment\GenericFuncs.ps1"
    . "$currentExecutingPath\Validation\Validation.ps1"
    . "$currentExecutingPath\Deployment\VMDeploy.ps1"
    . "$currentExecutingPath\Deployment\MPSDeploy.ps1"
    . "$currentExecutingPath\Deployment\Hosts.ps1"
    . "$currentExecutingPath\Deployment\MACAddressManagement.ps1"

    ToolDescription

    # Check if user that runs this script is administrator. If not throw an exception.
    if (!(IsRunAsElevatedUser)){
       throw "User must be elevated to admin user to run this tool."
    }

    if (!(CheckPrerequisites)){
       throw "HVIM tool prerequisites not met."
    }

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

    # Install ImportExcel module if not already installed 
    if (!(Get-Module -ListAvailable -Name ImportExcel)) {
	    Write-Host "ImportExcel Module is now installing..."
	    Import-Module $currentExecutingPath\ImportExcel-master\Install.ps1
    }

    # Install Posh-SSH module if not already installed
    # Used for running commands on Linux machines using SSH session.
    if (!(Get-Module -ListAvailable -Name Posh-SSH)) {
	    Write-Host "Posh-SSH Module is now installing..."
	    Import-Module $currentExecutingPath\Posh-SSH\Install.ps1
    }

    # Read Excel file path name from user input
    $ExcelFilePathName = ReadExcelFilePathName $ExcelFilePathName

    Write-Host "Excel file path name is: $ExcelFilePathName"

    $ExcelFileName = Split-Path $ExcelFilePathName -Leaf
    $projLogDir = $ExcelFileName.Substring(0, $ExcelFileName.LastIndexOf("."))

    $LogPath = "$currentExecutingPath\Log\$projLogDir"

    New-Item -Path $currentExecutingPath -Name "Log\$projLogDir" -ItemType Directory -Force | Out-Null

    try { 
        Start-Log -LogPath "$LogPath\Deployment.log"
    } 
    catch { 
		Write-Host "Failed to create log file at: $LogPath\Deployment.log"
    } 

    Write-Info "Deployment mode is: $deployMode"
    Write-Info "Run from: $currentExecutingPath"
    Write-Host "Deployment log files location is: $LogPath"
    Write-Host "Main log file name is: Deployment.log"
    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
	Write-Host "Log started at: $Stamp."

	$HostAdminUser = "Administrator"
    $HostAdminPassword = Read-SecuredString "Local admin user [$HostAdminUser] password" $LastSessionInfo.HostAdminPassword
    $HostAdminPasswordClear = (New-Object PSCredential "User",$HostAdminPassword).GetNetworkCredential().Password

	$VMAdminUser = "Administrator"
    $VMAdminPassword = $HostAdminPassword
    $VMAdminPasswordClear = $HostAdminPasswordClear

	$DomainAdminUser = "Hercules"
    $DomainAdminPassword = Read-SecuredString "Domain admin user [$DomainAdminUser] password" $LastSessionInfo.DomainAdminPassword
    $DomainAdminPasswordClear = (New-Object PSCredential "User",$DomainAdminPassword).GetNetworkCredential().Password

	$RequiredVMAdminUser = "zeus"
    $RequiredVMAdminPassword = Read-SecuredString "Local VM admin user [$RequiredVMAdminUser] password" $LastSessionInfo.RequiredVMAdminPassword
    $RequiredVMAdminPasswordClear = (New-Object PSCredential "User",$RequiredVMAdminPassword).GetNetworkCredential().Password

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
    $HostNetwork = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname HostNetwork | where 'Hostname(NetBIOS)' -ne $null | where 'Hostname(NetBIOS)' -In $Hosts.'Hostname(NetBIOS)'
    $HostDisks = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname HostDisks | where 'Hostname(NetBIOS)' -ne $null | where 'Hostname(NetBIOS)' -In $Hosts.'Hostname(NetBIOS)'
    $VMs = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname VMs | where {$_.Enabled -eq 'Yes' -and $_.HostIP -In $Hosts.HostIP}
    $VMDisks = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname VMDisks |  where ComputerName -ne $null | where ComputerName -In $VMs.ComputerName
    $VMNetwork = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname VMNetwork |  where ComputerName -ne $null | where ComputerName -In $VMs.ComputerName

    Start-Service winrm
    Set-Item wsman:\localhost\Client\TrustedHosts * -Force
    Restart-Service winrm

    #Load-HyperVModule
    
<#
    # Validate Excel data
    if (!(Validate $ExcelFilePathName $HostAdminUser $HostAdminPasswordClear)){
        Write-Error "HVIM Excel file validation failed. Please fix errors above and try again!"
        Exit 1
    }
#>

    $TemplatePathOnServer = ($VMEnvironment | where {$_.Setting -eq "TemplatePathOnServer"}).Value
	$TemplateSourcePath = ($VMEnvironment | where {$_.Setting -eq "TemplateSourcePath"}).Value
    $MPSKitPath = ($VMEnvironment | where {$_.Setting -eq "MPSKitPath"}).Value

    $Domain = ($VMEnvironment | where {$_.Setting -eq "Domain_Name"}).Value

    # Controls whether to run the host configuration using jobs (in parallel).
    $UseJobs = ($VMEnvironment | where {$_.Setting -eq "UseJobs"}).Value 

    $MPS_VM_Name = ($VMEnvironment | where {$_.Setting -eq "MPS_VM_Name"}).Value
    $SDC_VM_Name = ($VMEnvironment | where {$_.Setting -eq "SDC_VM_Name"}).Value

    $environment = ($VMEnvironment | where {$_.Setting -eq "Environment"}).Value
    $IsClusterMode = $environment -eq "Cluster"

    if ($deployMode -eq 'All' -or $deployMode -eq 'Env')
    {
        #If the local machine is in the domain, it means no need to configured the hosts
        if ($Hosts -ne $null -and -not (IsInDomain($Domain))){
    	    Configure-HyperVHosts $VMs $currentExecutingPath $Hosts $HostNetwork $HostDisks $LogPath $Domain `
                                    $VMEnvironment $TemplateSourcePath $TemplatePathOnServer $HostAdminUser $HostAdminPasswordClear
        }
     
        # Deploy MPS VM if defined in Excel
        $MPSConfig = $VMs | where ComputerName -eq $MPS_VM_Name

        if ($MPSConfig -ne $null){
            $VMInfo = New-Object PSobject
            $VMInfo | Add-Member -MemberType NoteProperty -Name "TemplatePath" -Value $TemplatePathOnServer
            $VMInfo | Add-Member -MemberType NoteProperty -Name "DomainAdminUser" -Value $DomainAdminUser
	        $VMInfo | Add-Member -MemberType NoteProperty -Name "DomainAdminPasswordClear" -Value $DomainAdminPasswordClear
	        $VMInfo | Add-Member -MemberType NoteProperty -Name "VMAdminUser" -Value $VMAdminUser
            $VMInfo | Add-Member -MemberType NoteProperty -Name "VMAdminPasswordClear" -Value $VMAdminPasswordClear
            $VMInfo | Add-Member -MemberType NoteProperty -Name "RequiredVMAdminUser" -Value $DomainAdminUser
            $VMInfo | Add-Member -MemberType NoteProperty -Name "RequiredVMAdminPasswordClear" -Value $DomainAdminPasswordClear
            $VMInfo | Add-Member -MemberType NoteProperty -Name "HostAdminUser" -Value $HostAdminUser
            $VMInfo | Add-Member -MemberType NoteProperty -Name "HostAdminPasswordClear" -Value $HostAdminPasswordClear
            $VMInfo | Add-Member -MemberType NoteProperty -Name "AddToCluster" -Value $false

	        if (!(Deploy-MPS $MPSConfig $VMDisks $VMNetwork $VMEnvironment $MPSKitPath $VMInfo)){
			    Write-Error "Failed to deploy MPS VM. Exiting..."
		        exit
	        }
		    Write-Success "MPS VM deployed sucessfully."
        }

        # Deploy SDC VM if defined in Excel
        $SDCConfig = $VMs | where ComputerName -eq $SDC_VM_Name

        if ($SDCConfig -ne $null){
            $VMInfo = New-Object PSobject
            $VMInfo | Add-Member -MemberType NoteProperty -Name "TemplatePath" -Value $TemplatePathOnServer
            $VMInfo | Add-Member -MemberType NoteProperty -Name "DomainAdminUser" -Value $DomainAdminUser
	        $VMInfo | Add-Member -MemberType NoteProperty -Name "DomainAdminPasswordClear" -Value $DomainAdminPasswordClear
	        $VMInfo | Add-Member -MemberType NoteProperty -Name "VMAdminUser" -Value $VMAdminUser
            $VMInfo | Add-Member -MemberType NoteProperty -Name "VMAdminPasswordClear" -Value $VMAdminPasswordClear
            $VMInfo | Add-Member -MemberType NoteProperty -Name "RequiredVMAdminUser" -Value $RequiredVMAdminUser
            $VMInfo | Add-Member -MemberType NoteProperty -Name "RequiredVMAdminPasswordClear" -Value $RequiredVMAdminPasswordClear
            $VMInfo | Add-Member -MemberType NoteProperty -Name "HostAdminUser" -Value $HostAdminUser
            $VMInfo | Add-Member -MemberType NoteProperty -Name "HostAdminPasswordClear" -Value $HostAdminPasswordClear
            $VMInfo | Add-Member -MemberType NoteProperty -Name "AddToCluster" -Value $false

            if (!(Deploy-SDC $SDCConfig $VMDisks $VMNetwork $VMEnvironment $VMInfo)){
                Write-Error "Failed to deploy SDC VM. Exiting..."
		        exit
            }
    	    Write-Success "Deployment of SDC VM Finished successfully!"
        }
        $shouldRestartMPSHost = $false
        $HostsToRestart = @()
        foreach ($Hst in $Hosts){
            if ($Hst.JoinToDomain -eq "Yes"){
                $addedToDomain = Add-HostToDomain $VMEnvironment $Hst.HostIP $HostAdminUser $HostAdminPasswordClear $DomainAdminUser $DomainAdminPasswordClear
                if ($addedToDomain)
                {
                    if ($Hst.HostIP -eq $MPSConfig.HostIP){
                        $shouldRestartMPSHost = $true
                    } else {
                        $HostsToRestart += $Hst
                    }
                }
            }
        }

        # We must restart the host that hosts the MPS sequencially, otherwise it will cause issues restarting other hosts.
        if ($shouldRestartMPSHost){
            Restart-ComputerWait $MPSConfig.HostIP $MPSConfig.ComputerName $HostAdminUser $HostAdminPasswordClear | Out-Null
        }

        if ($HostsToRestart){
            # We need to restart the hosts after joining them to the domain.
            Restart-Computers $VMEnvironment $HostsToRestart $HostAdminUser $HostAdminPasswordClear
        }

        # Create a cluster if it is configured in Excel

        if ($Hosts -ne $null -and $IsClusterMode)
        {
            Create-Cluster $VMEnvironment $Hosts $DomainAdminUser $DomainAdminPasswordClear

            $mainHost = $Hosts[0]
            $StorageType = ($VMEnvironment | where {$_.Setting -eq "Storage_Type"}).Value
            if ($StorageType -eq "Storage Spaces")
            {
                foreach ($hst in $Hosts){
                    Configure-LoadBalancePolicy $hst $HostAdminUser $HostAdminPasswordClear
                }
                Create-StoragePool $mainHost $HostAdminUser $HostAdminPasswordClear
                Create-QuorumVolume $mainHost $HostAdminUser $HostAdminPasswordClear
                Create-ClusterSharedVolume $mainHost $HostAdminUser $HostAdminPasswordClear
            }
            elseif ($StorageType -eq "Central Storage"){
                Create-CentralQuorumVolume $mainHost $HostAdminUser $HostAdminPasswordClear $VMEnvironment
                Create-CentralClusterSharedVolume $mainHost $HostAdminUser $HostAdminPasswordClear $VMEnvironment
            }

            Configure-ClusterNetwork $mainHost $HostAdminUser $HostAdminPasswordClear
            Add-NodesToCluster $VMEnvironment $Hosts $HostAdminUser $HostAdminPasswordClear
        }
    }

    if ($deployMode -eq 'All' -or $deployMode -eq 'VMs')
    {
        $RegularVMs = $VMs | where ComputerName -ne $MPS_VM_Name | where ComputerName -ne $SDC_VM_Name

        # Deploy all regular VMs
        if ($RegularVMs -ne $null){
            $VMInfo = New-Object PSobject
            $VMInfo | Add-Member -MemberType NoteProperty -Name "TemplatePath" -Value $TemplatePathOnServer
            $VMInfo | Add-Member -MemberType NoteProperty -Name "DomainAdminUser" -Value $DomainAdminUser
	        $VMInfo | Add-Member -MemberType NoteProperty -Name "DomainAdminPasswordClear" -Value $DomainAdminPasswordClear
	        $VMInfo | Add-Member -MemberType NoteProperty -Name "VMAdminUser" -Value $VMAdminUser
            $VMInfo | Add-Member -MemberType NoteProperty -Name "VMAdminPasswordClear" -Value $VMAdminPasswordClear
            $VMInfo | Add-Member -MemberType NoteProperty -Name "RequiredVMAdminUser" -Value $RequiredVMAdminUser
            $VMInfo | Add-Member -MemberType NoteProperty -Name "RequiredVMAdminPasswordClear" -Value $RequiredVMAdminPasswordClear
            $VMInfo | Add-Member -MemberType NoteProperty -Name "HostAdminUser" -Value $HostAdminUser
            $VMInfo | Add-Member -MemberType NoteProperty -Name "HostAdminPasswordClear" -Value $HostAdminPasswordClear
            $VMInfo | Add-Member -MemberType NoteProperty -Name "AddToCluster" -Value $IsClusterMode

            Deploy-VMs $currentExecutingPath $LogPath $RegularVMs $VMDisks $VMNetwork $VMEnvironment $Hosts $VMInfo

            Write-Success "Deployment of Hyper-V VMs Finished successfully!"
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
    Write-Host "`nHVIM tool execution ended."
}




<#
		for ($i=1; $i -lt 255; $i++){Test-Connection -ComputerName 10.161.47.$i -Count 1 -ErrorAction SilentlyContinue | Out-Null; "Test IP 10.161.47.$i = $?"}

		for ($i=1; $i -lt 255; $i++){
		Test-Connection -ComputerName 10.161.47.$i -Count 1 -ErrorAction SilentlyContinue | Out-Null
		$retVal = $?
		"Test IP 10.161.47.$i = $retVal"
		if ($retVal) {
		"Trying to connect" 
		Connect-VIServer -Server 10.161.47.$i -Protocol https -User $user -Password $password
		}
		}
#>
