# This module contains all the functions that deals with deploying and installing the MPS appliance


# Set the SR property default value
Function Set-SRPropertyDefaultValue([Parameter(Mandatory=$true)]$plaftormXMLPathName, 
									[Parameter(Mandatory=$true)]$propertyName, 
									[Parameter(Mandatory=$true)]$propertyValue, 
									[Parameter(Mandatory=$true)]$MPSHostIP, 
									[Parameter(Mandatory=$true)]$credlocal){
	Invoke-Command -ComputerName $MPSHostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock {
		param($plaftormXMLPathName, $propertyName, $propertyValue)

		$xml = [xml](Get-Content $plaftormXMLPathName)
		$node = $xml.Component.Properties.Property | where Name -eq $propertyName
		$node.DefaultValue = $propertyValue
	
		$xml.Save($plaftormXMLPathName)
	} -ArgumentList $plaftormXMLPathName, $propertyName, $propertyValue
}

# Set the SR installer user name
Function Set-SRInstallUserName( [Parameter(Mandatory=$true)]$projectXMLPathName, 
								[Parameter(Mandatory=$true)]$userName, 
								[Parameter(Mandatory=$true)]$MPSHostIP, 
								[Parameter(Mandatory=$true)]$credlocal){
	Invoke-Command -ComputerName $MPSHostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock {
		param($projectXMLPathName, $userName)

		$xml = [xml](Get-Content $projectXMLPathName)
		$xml.Site.Machine.UserName = $userName
	
		$xml.Save($projectXMLPathName)
	} -ArgumentList $projectXMLPathName, $userName
}

# Set the SR repository location
Function Set-SRRepositoryLocation(  [Parameter(Mandatory=$true)]$projectXMLPathName, 
									[Parameter(Mandatory=$true)]$pathToMPSKit, 
									[Parameter(Mandatory=$true)]$MPSHostIP, 
									[Parameter(Mandatory=$true)]$credlocal){
	Invoke-Command -ComputerName $MPSHostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock {
		param($projectXMLPathName, $pathToMPSKit)
		$xml = [xml](Get-Content $projectXMLPathName)
		$xml.Site.RepositoryLocation = $pathToMPSKit

		$xml.Save($projectXMLPathName)
	} -ArgumentList $projectXMLPathName, $pathToMPSKit
}

# Updates the SR XML files
Function Update-SRFiles([Parameter(Mandatory=$true)]$MPSKitPath, 
						[Parameter(Mandatory=$true)]$domain, 
						[Parameter(Mandatory=$true)]$NetBios, 
						[Parameter(Mandatory=$true)]$MPSHostIP, 
						[Parameter(Mandatory=$true)]$credlocal){

    # Update MPS DC platform file with the selected domain name and NetBios
	$MPS_DC_InstallFilePathName = "$MPSKitPath\Platforms\MPS DC.xml"
	Set-SRPropertyDefaultValue $MPS_DC_InstallFilePathName 'Domain to create' $domain $MPSHostIP $credlocal
	Set-SRPropertyDefaultValue $MPS_DC_InstallFilePathName 'DomaiBiosName' $NetBios $MPSHostIP $credlocal

    # Update MPS DC project file with the repository location
	$MPS_DC_ProjectFilePathName = "$MPSKitPath\Projects\MPS_DC_project.xml"
	Set-SRRepositoryLocation $MPS_DC_ProjectFilePathName "D:\" $MPSHostIP $credlocal

    # Update MPS gereric Components project file with the relevant credentials and repository location
	$MPS_Components_ProjectFilePathName = "$MPSKitPath\Projects\MPS_Components_project.xml"
	Set-SRInstallUserName $MPS_Components_ProjectFilePathName "$NetBios\hercules" $MPSHostIP $credlocal
	Set-SRRepositoryLocation $MPS_Components_ProjectFilePathName "D:\" $MPSHostIP $credlocal

    # Update MPS Webint Components project file with the relevant credentials and repository location
	$MPS_WebintComponents_ProjectFilePathName = "$MPSKitPath\Projects\MPS_WebintComponents_project.xml"
	Set-SRInstallUserName $MPS_WebintComponents_ProjectFilePathName "$NetBios\hercules" $MPSHostIP $credlocal
	Set-SRRepositoryLocation $MPS_WebintComponents_ProjectFilePathName "D:\" $MPSHostIP $credlocal
}

# Copies the MPS components kit to the MPS VM
Function Copy-MPSKit([Parameter(Mandatory=$true)]$MPSKitPath, 
                    [Parameter(Mandatory=$true)]$MPSHostIP,
                    [Parameter(Mandatory=$true)]$credlocal){

	Write-Info "Copying MPS kit to MPS VM local D: drive..."

    try
    {
        $psdrive = "M"
        $destinationPath = "$($psdrive):\"
        $currUser = whoami | Split-Path -Leaf

        if ($currUser -eq $credlocal.UserName){
            New-PSDrive –Name $psdrive –PSProvider FileSystem –Root \\$MPSHostIP\d$ -Persist
        }
        else{
            New-PSDrive -Credential $credlocal –Name $psdrive –PSProvider FileSystem –Root \\$MPSHostIP\d$ -Persist
        }
        

        if (!(Test-Path -Path $destinationPath -PathType Container)){
            throw "Can't access drive D: on MPS VM at $MPSHostIP. Verify MPS disks were specified correctly in Excel's VMDisks tab."
        }

        Copy-Item -Path "$MPSKitPath\*" -Destination $destinationPath -Recurse -Exclude ".svn"

        #Copy-FilesBitsTransfer -sourcePath $MPSKitPath -destinationPath $destinationPath -createRootDirectory $false

	    if (!$?){
		    Write-Error "Failed to copy MPS kit."
		    return $false
	    } 
    }
    catch [Exception]
    {
        $exceptionInfo = (echo $_ | format-list -force | out-string)
        Write-Error $exceptionInfo
    }
    finally
    {
        Remove-PSDrive $psdrive
    }

	Write-Success "MPS kit copied successfully."

	return $true	
}

# Start SR setup.exe file in order to deploy SR tools on the MPS machine 
Function Start-SR([Parameter(Mandatory=$true)]$MPSHostIP, [Parameter(Mandatory=$true)]$credlocal){
	Write-Info "Executing the MPS kit setup file..."
	$PSSession = New-PSSession -ComputerName $MPSHostIP -Credential $credlocal

    try
    {
	    Invoke-Command -Session $PSSession -ErrorAction Stop -ScriptBlock {
		    Start-Process -FilePath D:\Setup.exe -Verb RunAs
	    }
	
	    if (!$?){
		    Write-Error "SR Setup failed to start."
		    return $false
	    } 

	    Write-Success "SR Setup started successfully."

	    WaitFor-ProcessToStart "Rinst" $MPSHostIP $credlocal
    }
    finally
    {
	    Remove-PSSession -Session $PSSession | Out-Null
    }

	return $true	
}

# Start DC installation
Function Start-DCInstall([Parameter(Mandatory=$true)]$MPSHostIP, [Parameter(Mandatory=$true)]$credlocal){
	Write-Info "Start installing DC..."
	$PSSession = New-PSSession -ComputerName $MPSHostIP -Credential $credlocal

    try
    {
	    Invoke-Command  -Session $PSSession -ErrorAction Stop -ScriptBlock {
		    Start-Process -FilePath D:\MPS_DC.bat -Verb RunAs
	    }
	
		if (!$?){
			Write-Error "DC installation failed to start."
			return $false
		} 

		Write-Info "DC installation started."
	
		WaitFor-ProcessToStart "CompleteMessage" $MPSHostIP $credlocal
        
        # Check log file to verify installation is sucessfull. 
		$status = Invoke-Command -ComputerName $MPSHostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock {
	        $statusText = Get-Content 'C:\Program Files (x86)\Server Readiness\Log\Installer\log-file.txt' -tail 8
	        if ($statusText -like "*Installation Completed Successfully*"){
	            return $true
	        }
	        return $false
		}
    	if (!$status){
        	throw "Failed to install DC on MPS VM at $MPSHostIP"
    	}

		Write-Info "DC installation completed."

	    Stop-ProcessByName "CompleteMessage" $MPSHostIP $credlocal
    }
    finally
    {
	    Remove-PSSession -Session $PSSession | Out-Null
    }

	return $true	
}

# Start MPS components installation
Function Start-ComponentsInstall(
    [Parameter(Mandatory=$true)]$MPSHostIP, 
    [Parameter(Mandatory=$true)]$credlocal,
    [Parameter(Mandatory=$true)]$MPSComponentType){

	Write-Info "Start installing MPS Components..."
	$PSSession = New-PSSession -ComputerName $MPSHostIP -Credential $credlocal

    try
    {	
	    if ($MPSComponentType -eq 'Webint'){
		    Invoke-Command -Session $PSSession -ErrorAction Stop -ScriptBlock {
			    Start-Process -FilePath D:\MPS_WebintComponents.bat -Verb RunAs
		    }
		}
	    else {
	        Invoke-Command -Session $PSSession -ErrorAction Stop -ScriptBlock {
			    Start-Process -FilePath D:\MPS_Components.bat -Verb RunAs
		    }
	    }
	
		if (!$?){
			Write-Error "MPS Components installation failed to start."
			return $false
		} 
	
		Write-Info "MPS Components installation started."
	
		WaitFor-ProcessToStart "CompleteMessage" $MPSHostIP $credlocal

        # Check log file to verify installation is sucessfull.
		$status = Invoke-Command -ComputerName $MPSHostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock {
	        $statusText = Get-Content 'C:\Program Files (x86)\Server Readiness\Log\Installer\log-file.txt' -tail 8
	        if ($statusText -like "*Installation Completed Successfully*"){
	            return $true
	        }
	        return $false
		}
	    if (!$status){
	        throw "Failed to install MPS components on MPS VM at $MPSHostIP"
	    }

		Write-Success "MPS Components installation completed."
	}
    finally
    {
	    Remove-PSSession -Session $PSSession | Out-Null
    }

	return $true	
}

# Install MPS VM by running SR twice. First for DC components and second for the other components
Function Install-MPSComponents( [Parameter(Mandatory=$true)]$MPSKitPath, 
								[Parameter(Mandatory=$true)]$VMEnvironment, 
								[Parameter(Mandatory=$true)]$MPSHostIP, 
								[Parameter(Mandatory=$true)]$VMName, 
								[Parameter(Mandatory=$true)]$VMAdminUser, 
								[Parameter(Mandatory=$true)]$VMAdminPasswordClear){
	$Domain = ($VMEnvironment | where {$_.Setting -eq "Domain_Name"}).Value
    $NetBios = GetNetBios $VMEnvironment

	$securedPassword = ConvertTo-SecureString $VMAdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential (".\$VMAdminUser", $securedPassword)

	Update-SRFiles "D:" $Domain $NetBios $MPSHostIP $credlocal 

	Start-SR $MPSHostIP $credlocal

    Start-DCInstall $MPSHostIP $credlocal

    $MPSComponentType = ($VMEnvironment | where {$_.Setting -eq "MPSComponentType"}).Value
    
    if ($MPSComponentType -ne "None"){
        Start-ComponentsInstall $MPSHostIP $credlocal $MPSComponentType
    }

	return $true
}

# Deploy the MPS VM
Function Deploy-MPS([Parameter(Mandatory=$true)]$VMConfig, 
					[Parameter(Mandatory=$true)]$VMDisks, 
					[Parameter(Mandatory=$false)]$VMNetwork, 
					[Parameter(Mandatory=$true)]$VMEnvironment, 
					[Parameter(Mandatory=$true)]$MPSKitPath,
                    [Parameter(Mandatory=$true)]$VMInfo)
{
	Write-Info "Deployment of MPS Virtual Machine '$($VMConfig.ComputerName)' started."

    if (!(Deploy-RegularVM $VMConfig $VMDisks $VMNetwork $VMEnvironment $VMInfo $false)){
        Write-Error "Failed to deploy MPS VM."
        return $false;
    }

    AddHyperVTools $VMConfig.PrimaryIP $VMInfo.DomainAdminUser $VMInfo.DomainAdminPasswordClear
    AddRSATVTools $VMConfig.PrimaryIP $VMInfo.DomainAdminUser $VMInfo.DomainAdminPasswordClear

    $environment = ($VMEnvironment | where {$_.Setting -eq "Environment"}).Value
    if ($environment -eq "Cluster")
    {
        AddFailoverClusterTools $VMConfig.PrimaryIP $VMInfo.DomainAdminUser $VMInfo.DomainAdminPasswordClear
    }

    $securedPassword = ConvertTo-SecureString $VMInfo.DomainAdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential ($VMInfo.DomainAdminUser, $securedPassword)

	Copy-MPSKit $MPSKitPath $VMConfig.PrimaryIP $credlocal
	Install-MPSComponents $MPSKitPath $VMEnvironment $VMConfig.PrimaryIP $VMConfig.ComputerName $VMInfo.DomainAdminUser $VMInfo.DomainAdminPasswordClear
	
	return $true
}
