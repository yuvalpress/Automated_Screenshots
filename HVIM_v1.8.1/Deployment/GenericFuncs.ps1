# This module contains generic powershell functions that are used by other modules


# Read string from the user's console
function Read-String (
    [Parameter(Mandatory=$true)]$message,       # Message to display to the user
    [Parameter(Mandatory=$false)]$defaultValue) # The default value to use if no value is specified
{
	$inputString = $null
	do
	{
		if ($defaultValue -ne $null) {
			$inputString = Read-Host "$message [$defaultValue]"
			if ($inputString.Length -eq 0)
			{
				$inputString = $defaultValue
			}
		} 
		else {
			$inputString = Read-Host "$message"
		}
	} while ($inputString -eq "")

	return $inputString
}

# Read password from the user's console
function Read-SecuredString (
    [Parameter(Mandatory=$true)]$message,       # Message to display to the user
    [Parameter(Mandatory=$false)]$defaultValue) # The default value to use if no value is specified
{
	$inputString = $null
	do
	{
		if ($defaultValue -ne $null) {
			$inputString = Read-Host -AsSecureString "$message [*********]"
			if ($inputString.Length -eq 0)
			{
				$inputString = $defaultValue
			}
		} 
		else {
			$inputString = Read-Host -AsSecureString "$message"
		}
	} while ($inputString.Length -eq 0)
	
	return $inputString
}

#Restarts the computer and waits for it to be started again
Function Restart-ComputerWait(
    [Parameter(Mandatory=$true)]$HostIP,             # The IP address of the computer
    [Parameter(Mandatory=$true)]$ComputerName,       # The VM computer name
    [Parameter(Mandatory=$true)]$AdminUser,          # The user with administrator rights
    [Parameter(Mandatory=$true)]$AdminPasswordClear) # The user password in clear text
{
	Write-Info "Restart machine '$ComputerName'."
	$securedPassword = ConvertTo-SecureString $AdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential (".\$AdminUser", $securedPassword)

	Restart-Computer -ComputerName $HostIP -Credential $credlocal -Wait -Force -ErrorAction Stop

	if (!$?){
		Write-Error "Failed to restart machine '$ComputerName'."
		return $false
	}

	Write-Success "machine '$ComputerName' was restarted successfully."
    
	return $true;
}

# Rename the administrator user
Function Rename-AdminUser {
	param([Parameter(Mandatory=$true)]$HostIP,    # The IP address of the computer
          [Parameter(Mandatory=$true)]$ComputerName,
          [Parameter(Mandatory=$true)]$AdminUser,
          [Parameter(Mandatory=$true)][Object]$credlocal) # The new admin user name
	
	Write-Info "Renaming admin user to '$AdminUser' on VM '$ComputerName'"
	
	Invoke-Command -ComputerName $HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock {
		param($AdminUser)
		$admin=[adsi]"WinNT://./Administrator,user" 
		$admin.psbase.rename($AdminUser)
	} -ArgumentList $AdminUser
	
	
	if (!$?){
		Write-Error "Failed to rename Admin user on VM '$ComputerName'."
		return $false
	}

	Write-Success "Admin user renamed to '$AdminUser' on VM '$ComputerName' successfully!"

	return $true
} 

#Change Admin user password
Function Change-AdminUserPassword {
	param([Parameter(Mandatory=$true)]$HostIP,    # The IP address of the computer
          [Parameter(Mandatory=$true)]$ComputerName,
          [Parameter(Mandatory=$true)]$VMAdminUser,
          [Parameter(Mandatory=$true)]$VMAdminPasswordClear,
          [Parameter(Mandatory=$true)]$RequiredVMAdminPasswordClear) 
	
	Write-Info "Changing admin user's password on VM '$ComputerName'"
    
    $securedPassword = ConvertTo-SecureString $VMAdminPasswordClear -AsPlainText -Force
    $credlocal = New-Object System.Management.Automation.PSCredential($VMAdminUser, $securedPassword)

	Invoke-Command -ComputerName $HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock {
		$admin=[adsi]"WinNT://./$using:VMAdminUser"
		$admin.SetPassword($using:RequiredVMAdminPasswordClear)
	}
	
	
	if (!$?){
		Write-Error "Failed to change Admin user's password on VM '$ComputerName'."
		return $false
	}

	Write-Success "Admin user's password was changed on VM '$ComputerName' successfully!"

	return $true


}
    

# Rename computer host name.
Function Rename-ComputerHostName(   [Parameter(Mandatory=$true)]$HostIP,                # The IP address of the computer
									[Parameter(Mandatory=$true)]$NewHostName,           # The new hostname
									[Parameter(Mandatory=$true)]$AdminUser,             # The user with administrator rights
									[Parameter(Mandatory=$true)]$AdminPasswordClear)    # The user password in clear text
{  
	Write-Info "Renaming VM's hostname to '$NewHostName' at VM at '$HostIP'."

	$securedPassword = ConvertTo-SecureString $AdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential ($AdminUser, $securedPassword)

	Rename-Computer -ComputerName $HostIP -LocalCredential $credlocal -NewName $NewHostName -Force -ErrorAction Stop

	if (!$?){ 
		Write-Error $error[0]
		return $false
	}

	Write-Success "Changed hostname to $NewHostName successfully."

	return $true
}

# Rename computer host name on Linux.
Function Rename-ComputerHostNameLinux(  [Parameter(Mandatory=$true)]$HostIP,                # The IP address of the computer
									    [Parameter(Mandatory=$true)]$NewHostName,           # The new hostname
									    [Parameter(Mandatory=$true)]$AdminUser,             # The user with administrator rights
									    [Parameter(Mandatory=$true)]$AdminPasswordClear)    # The user password in clear text
{  
	Write-Info "Renaming VM's hostname to '$NewHostName' at host at '$HostIP'."

	$securedPassword = ConvertTo-SecureString $AdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential ($AdminUser, $securedPassword)

    try
    {
        New-SSHSession -ComputerName $HostIP -Credential $credlocal -AcceptKey -ConnectionTimeout 20 -ErrorAction Stop | Out-Null
    }
    catch
    {
        New-SSHSession -ComputerName $HostIP -Credential $credlocal -AcceptKey -ConnectionTimeout 20 -ErrorAction Stop | Out-Null
    }

    Invoke-SSHCommand -Index 0 -Command "sudo hostname $NewHostName" -ErrorAction Stop | Out-Null

    Remove-SSHSession 0 | Out-Null

	if (!$?){ 
		Write-Error $error[0]
		return $false
	}

	Write-Success "Changed hostname to $NewHostName successfully."

	return $true
}

#
# Powershell functions for adding/removing entries to the hosts file.
#
# Known limitations:
# - does not handle entries with comments afterwards ("<ip>    <host>    # comment")
#
function AddTo-HostsFile([string]$ip, [string]$hostname) {
	Write-Info "Adding $hostname with IP $ip to management machine host file."
	$filename = "$env:windir\System32\drivers\etc\hosts"
	RemoveFrom-HostsFile $ip $hostname
	$ip + "`t" + $hostname | Out-File -encoding ASCII -append $filename
}

function RemoveFrom-HostsFile([string]$ip, [string]$hostname) {
	$filename = "$env:windir\System32\drivers\etc\hosts"
	$content = Get-Content $filename
	$newLines = @()

	foreach ($line in $content) {
		$bits = [regex]::Split($line, "\t+")
		if ($bits.count -eq 2) {
			if ($bits[0] -ne $ip -and $bits[1] -ne $hostname) {
				$newLines += $line
			}
		} else {
			$newLines += $line
		}
	}

	# Write file
	Clear-Content $filename
	foreach ($line in $newLines) {
		$line | Out-File -encoding ASCII -append $filename
	}
}

# Wait for connection to the host
Function WaitFor-HostConnection
{
	param( [Parameter(Mandatory=$true)][String]$HostIP) # The IP address of the computer

	$progressArr = '/', '-', '\', '|'
	$progressIdx = 0

	while ($true) {
		Write-Progress -Activity "$($progressArr[$progressIdx]) Waiting for Network connection to be established to host." -Status "Please wait..." -PercentComplete -1
		if ($progressIdx -eq 0) {
			if (Test-Connection -ComputerName $HostIP -Count 1 -Quiet){
				Write-Info "Network connection to $HostIP has been established."
				break
			}
		}
		Start-Sleep -Milliseconds 500
		$progressIdx = ($progressIdx + 1) % 4
	}
	
	Write-Progress -Activity "Network connection to host has been established." -Completed
}

#The next lines are in order to let windows 10 administrate Hyper-V host running Windows Server 2012 R2
Function Load-HyperVModule(){
    if ((Get-Module Hyper-V) -eq $null){
        Write-Info "Importing module Hyper-V"
        Import-Module Hyper-V -RequiredVersion 1.1
    }
    elseif ((Get-Module Hyper-V).Version -ne "1.1"){
        Write-Info "Downgrading the Hyper-V module to version 1.1"
        Remove-Module Hyper-V
        Import-Module Hyper-V -RequiredVersion 1.1
    }
}

# Adds hyper-v tools to the server
Function AddHyperVTools(
    [Parameter(Mandatory=$true)]$HostIP, 
    [Parameter(Mandatory=$true)]$AdminUser, 
    [Parameter(Mandatory=$true)]$AdminPasswordClear)
{
	Write-Info "Adding Hyper-V tools to computer at $HostIP."
	$securedPassword = ConvertTo-SecureString $AdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential ($AdminUser, $securedPassword)

    Invoke-Command -ComputerName $VMConfig.PrimaryIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
        Install-WindowsFeature hyper-v-tools
    }

	if (!$?){
		Write-Error "Failed to add Hyper-V tools to computer at $HostIP."
		return $false
	}

	Write-Success "Hyper-V tools added successfully."
    
	return $true
}

# Adds RSAT tools to the server
Function AddRSATVTools(
    [Parameter(Mandatory=$true)]$HostIP, 
    [Parameter(Mandatory=$true)]$AdminUser, 
    [Parameter(Mandatory=$true)]$AdminPasswordClear)
{
	Write-Info "Adding Hyper-V RSAT tools to computer at '$HostIP'."
	$securedPassword = ConvertTo-SecureString $AdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential ($AdminUser, $securedPassword)

    Invoke-Command -ComputerName $VMConfig.PrimaryIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
        Install-WindowsFeature RSAT-Hyper-V-Tools -IncludeAllSubFeature
    }

	if (!$?){
		Write-Error "Failed to add Hyper-V RSAT tools to VM at $HostIP."
		return $false
	}

	Write-Info "Hyper-V RSAT tools added successfully to VM at '$HostIP'."
    
	return $true
}

# Adds Failover Cluster tools to the server
Function AddFailoverClusterTools(
    [Parameter(Mandatory=$true)]$HostIP, 
    [Parameter(Mandatory=$true)]$AdminUser, 
    [Parameter(Mandatory=$true)]$AdminPasswordClear)
{
	Write-Info "Adding Hyper-V RSAT tools to computer at '$HostIP'."
	$securedPassword = ConvertTo-SecureString $AdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential ($AdminUser, $securedPassword)

    Invoke-Command -ComputerName $VMConfig.PrimaryIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
        Install-WindowsFeature RSAT-Clustering-Mgmt -IncludeAllSubFeature
    }

	if (!$?){
		Write-Error "Failed to add Failover Cluster management tools to computer at $HostIP."
		return $false
	}

	Write-Info "Failover Cluster management tools added successfully to VM at '$HostIP.'"
    
	return $true
}

# Translate from subnet mask to subnet prefix
Function GetMaskPrefix([Parameter(Mandatory=$true)][String] $SubnetMask)
{
    $ip = [System.Net.IPAddress]::Parse($SubnetMask);

    $addrBytes = $ip.GetAddressBytes();
    $count = 0;
    $bit = 1;

    for ($i = 0; $i -lt 4; $i++)
    {
        for ($j = 7; $j -ge 0; $j--)
        {
            if (($addrBytes[$i] -band ($bit -shl $j)) -ne 0){
                $count++;
            }
            else{
                return $count
            }
        }
    }

    return $count
}

#This function combines a new IP address from a pattern such as 192.168.1.x and an IP address such as 10.161.47.144
# the outcome IP address will be 192.168.1.144
Function CombineIPAddress(
    [Parameter(Mandatory=$true)][String] $IPPattern,
    [Parameter(Mandatory=$true)][String] $IPReference)
{
    $IPPrefix = $IPPattern.Remove($IPPattern.IndexOf(".x"))
    $LastOctat = $IPReference.Substring($IPReference.LastIndexOf(".") + 1)

    $NewIP = "$IPPrefix.$LastOctat"

    return $NewIP
}

#Adds a program to the add/remove registry section on local or remote host
Function AddToAddRemove(
		[Parameter(Mandatory=$true)][String]$DisplayName, 
		[Parameter(Mandatory=$true)][String]$Publisher, 
		[Parameter(Mandatory=$true)][String]$DisplayVersion,
		[Parameter(Mandatory=$false)][String]$HostIP,
        [Parameter(Mandatory=$false)][String]$HostName,
        [Parameter(Mandatory=$false)][Object]$credlocal) 
{
	$uninstallLocation = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\'

	if (!$HostIP) # Change the hosts file in the local host
	{
		if (Test-Path -Path $uninstallLocation\$DisplayName)
		{
			Write-Info "'$DisplayName' already added to Add/Remove section."
			return $true
		}

		$regItem = New-Item -Path $uninstallLocation -Name $DisplayName
		if (!$regItem)
		{
			Write-Failure "Failed to add program to Add/Remove."
			return $false
		}

		New-ItemProperty -Path $uninstallLocation\$DisplayName -Name 'DisplayName' -Value $DisplayName | Out-Null
		New-ItemProperty -Path $uninstallLocation\$DisplayName -Name 'DisplayVersion' -Value $DisplayVersion | Out-Null
		New-ItemProperty -Path $uninstallLocation\$DisplayName -Name 'Publisher' -Value $Publisher | Out-Null
		New-ItemProperty -Path $uninstallLocation\$DisplayName -Name 'UninstallString' -Value 'None' | Out-Null

		Write-Success "$DisplayName added to Add/Remove section!"
	}
	else # Change the hosts file in the remote host
	{
		$session = New-PSSession -ComputerName $HostIP -Credential $credlocal
		try
		{
			$uninstallLocationFull = "$uninstallLocation\$DisplayName"

			$pathExist = Invoke-Command -Session $session -ScriptBlock {
				Test-Path -Path $using:uninstallLocationFull
			}

			if ($pathExist)
			{
				Write-Info "'$DisplayName' already added to Add/Remove section on host '$HostName'."
				return $true
			}

			$regItem = Invoke-Command -Session $session -ScriptBlock {
				New-Item -Path $using:uninstallLocation -Name $using:DisplayName
			}

			if (!$regItem)
			{
				Write-Failure "Failed to add program to Add/Remove on host '$HostName'."
				return $false
			}

			Invoke-Command -Session $session -ScriptBlock {
				New-ItemProperty -Path $using:uninstallLocationFull -Name 'DisplayName' -Value $using:DisplayName | Out-Null
				New-ItemProperty -Path $using:uninstallLocationFull -Name 'DisplayVersion' -Value $using:DisplayVersion | Out-Null
				New-ItemProperty -Path $using:uninstallLocationFull -Name 'Publisher' -Value $using:Publisher | Out-Null
				New-ItemProperty -Path $using:uninstallLocationFull -Name 'UninstallString' -Value 'None' | Out-Null
			}

			Write-Success "'$DisplayName' program added to Add/Remove section on host at '$HostName'!"
		}
		finally
		{
			Remove-PSSession -Session $session
		}
	}
	return $true
}

#This recursive function copies files and directories recursively from source path to destination path
#If file already exists on destination path, it copies them only with newer files.
Function Copy-FilesBitsTransfer(
        [Parameter(Mandatory=$true)][String]$sourcePath, 
        [Parameter(Mandatory=$true)][String]$destinationPath, 
        [Parameter(Mandatory=$false)][bool]$createRootDirectory = $true)
{
	$item = Get-Item $sourcePath
	$itemName = Split-Path $sourcePath -leaf
	if (!$item.PSIsContainer){ #Item Is a file

	    $clientFileTime = Get-Item $sourcePath | select LastWriteTime -ExpandProperty LastWriteTime

        if (!(Test-Path -Path $destinationPath\$itemName)){
            Write-Info "Copying: $sourcePath >> $destinationPath"
            Copy-Item -Path $sourcePath -Destination $destinationPath
    		#Start-BitsTransfer -Source $sourcePath -Destination $destinationPath -Description "$sourcePath >> $destinationPath" -DisplayName "Copy file" -Confirm:$false -ErrorAction Stop
            if (!$?){
                return $false
            }
        }
        else{
	        $serverFileTime = Get-Item $destinationPath\$itemName | select LastWriteTime -ExpandProperty LastWriteTime

	        if ($serverFileTime -lt $clientFileTime)
	        {
                Write-Info "Copying: $sourcePath >> $destinationPath"
                Copy-Item -Path $sourcePath -Destination $destinationPath
    		    #Start-BitsTransfer -Source $sourcePath -Destination $destinationPath -Description "$sourcePath >> $destinationPath" -DisplayName "Copy Template file" -Confirm:$false -ErrorAction Stop
                if (!$?){
                    return $false
                }
	        }
        }
	}
	else{ #Item Is a directory
        if ($createRootDirectory){
		    $destinationPath = "$destinationPath\$itemName"
            if (!(Test-Path -Path $destinationPath -PathType Container)){
                if (Test-Path -Path $destinationPath -PathType Leaf){ #In case item is a file, delete it.
                    Remove-Item -Path $destinationPath
                }

		        New-Item -ItemType Directory $destinationPath -ErrorAction Stop | Out-Null
                if (!$?){
                    return $false
                }
            }
        }
		Foreach ($fileOrDirectory in (Get-Item -Path "$sourcePath\*"))
		{
			$status = Copy-FilesBitsTransfer $fileOrDirectory $destinationPath $true -ErrorAction Stop
            if (!$status){
                return $false
            }
		}
	}

    return $true
}

#Check if user runing this tool is elevated as admin user
Function IsRunAsElevatedUser
{
    $wid=[System.Security.Principal.WindowsIdentity]::GetCurrent()
    $prp=new-object System.Security.Principal.WindowsPrincipal($wid)
    $adm=[System.Security.Principal.WindowsBuiltInRole]::Administrator
    $IsAdmin=$prp.IsInRole($adm)

    return $IsAdmin
}

# Checks if the specified OS profile is for a Linux VM.
Function IsLinuxOS(
	[Parameter(Mandatory=$true,
				Position=1,
				ParameterSetName='OSProfile',
				ValueFromPipeline=$true)]
				[String]$OSProfile)
{
	If  ($OSProfile -match "Ubuntu" -or $OSProfile -match "RedHat"){
		return $true
	}

    return $false
}

# Get NetBios name.
Function GetNetBios($VMEnvironment)
{
	$NetBios = ($VMEnvironment | where {$_.Setting -eq "NetBios_Name"}).Value

    return $NetBios
}

# Get Excel's file path name.
Function ReadExcelFilePathName ($ExcelFilePathName)
{
      do {
        $FilePathName = Read-String 'Excel file for deployment (full path)' $ExcelFilePathName
        #Remove double quotes since it causes a problem.	
        $FilePathName = $FilePathName.Replace("`"",'')

        if (!(Test-Path -Path $FilePathName)){
            Write-Host "'$FilePathName': file doesn't exist."
            continue
        }
        elseif (!(Validate-ExcelFileVersion $FilePathName)){
            Write-Host "Input Excel file version is not compatible with current HVIM version."
            continue
        } else {
            break
        }
    }
    while ($true)

    return $FilePathName
}


Function IsInDomain($Domain)
{
	if ((gwmi win32_computersystem).partofdomain){
        if ((gwmi win32_computersystem).domain -eq $Domain){
		    return $true
    	}	
    }
	return $false
}

# Waits for process to start running. 
# This function pols the processes every 2 secs in order to see if the specified process has started.
Function WaitFor-ProcessToStart([Parameter(Mandatory=$true)]$ProcessName, [Parameter(Mandatory=$true)]$HostIP, [Parameter(Mandatory=$true)]$credlocal){

	$progressArr = '/', '-', '\', '|'
	$progressIdx = 0
    
	while($true)
	{
		Write-Progress -Activity "$($progressArr[$progressIdx]) Waiting for process $ProcessName to start." -Status "Please wait..."
		if ($progressIdx -eq 0) {
			$process = Invoke-Command -ComputerName $HostIP -Credential $credlocal -ErrorAction SilentlyContinue -ScriptBlock {
				param($ProcessName)
				Get-Process $ProcessName -ErrorAction SilentlyContinue
			} -ArgumentList $ProcessName
			If ($process.ProcessName -eq $ProcessName) { 
				Write-Info "Process $ProcessName has started."
				break;
			}
		}
		Start-Sleep -Milliseconds 500
		$progressIdx = ($progressIdx + 1) % 4
	}

	Write-Progress -Activity "Process $ProcessName has started." -Completed
}

# Terminate a process by its name
Function Stop-ProcessByName([Parameter(Mandatory=$true)]$ProcessName, [Parameter(Mandatory=$true)]$HostIP, [Parameter(Mandatory=$true)]$credlocal){
	Invoke-Command -ComputerName $HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock {
		param($ProcessName)

		Stop-Process -Name $ProcessName
	}  -ArgumentList $ProcessName

	If (!($?)) { 
		Write-Failure "Failed to stop process $ProcessName."
		return $false
	}

	Write-Info "Process $ProcessName has been stopped."
	return $true;
}

# Wait for the integration tools on the VM to be initialized
Function WaitFor-IntegrationTool{ 
	param( [Parameter(Mandatory=$true)][String]$VMName, 
            [Parameter(Mandatory=$true)][String]$HostIP,
            [Parameter(Mandatory=$true)][Object]$credlocal)

	Write-Info "Wait for VM '$VMName' Integration Tools to be ready."

	#Wait for VM to complete initialization
	$progressArr = '/', '-', '\', '|'
	$progressIdx = 0
	while($true)
	{
		Write-Progress -Activity "$($progressArr[$progressIdx]) Waiting for Integration Tools to be ready on $VMName." -Status "Please wait..."
		if ($progressIdx -eq 0) {
			$VMIntegrationService = Invoke-Command -ComputerName $HostIP -Credential $credlocal -ScriptBlock{
				Get-VMIntegrationService -VMName $using:VMName -Name Heartbeat
			}
<#
			if (-not $?)
			{
				Write-Error $Error[0].Exception.Message
				break
			}
#>
			if($VMIntegrationService.PrimaryStatusDescription -eq 'OK') #-And $VMIntegrationService.SecondaryStatusDescription -eq 'OK')
			{
				Write-Info "Integration Tools are now ready on $VMName."
				break
			}
		}
		Start-Sleep -Milliseconds 500
		$progressIdx = ($progressIdx + 1) % 4
	}
}

# Wait for VM network interface to be reachable
Function WaitFor-NetworkInterface
{
	param( [Parameter(Mandatory=$true)][String]$VMName, 
            [Parameter(Mandatory=$true)][String]$HostIP,
            [Parameter(Mandatory=$true)][Object]$credlocal)

	$progressArr = '/', '-', '\', '|'
	$progressIdx = 0

    Write-Info "Waiting for network interface to be available."

	while ($true) {
		Write-Progress -Activity "$($progressArr[$progressIdx]) Waiting for Network interface to be ready on $VMName." -Status "Please wait..." -PercentComplete -1
		if ($progressIdx -eq 0) {
			$VM_IPAddress = Invoke-Command -ComputerName $HostIP -Credential $credlocal -ScriptBlock{
				Get-VMNetworkAdapter -VMName $using:VMName | ? name -eq "Network Adapter" | select -ExpandProperty IPAddresses
			}
<#
			if (-not $?)
			{
				Write-Error $Error[0].Exception.Message
				break
			}
#>
			if ($VM_IPAddress -ne $null){
				Write-Info "Network interface in VM '$VMName' is now ready."
				break
			}
		}
		Start-Sleep -Milliseconds 500
		$progressIdx = ($progressIdx + 1) % 4
	}
}
