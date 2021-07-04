# This is the module is used in order to verify/validate the Hyper-V environment that was created by the Hyper-V Infrastructure Management tool (HVIM).
# This tool should be used after all manual configuration was done as well.

# Displays the tool description
function ToolDescription()
{
   	Write-Host "***************************************************************************************************"
	Write-Host "Hyper-V Infrastructure Verification tool (HVIM) version: $global:version"
	Write-Host "This tool verifies the Hyper-V environment and VMs deployments on it."
	Write-Host "***************************************************************************************************"
}

#Returns the HTML head element content. It includes the syle and javascript code.
Function Get-HTMLHead
{
    $Head = @"
    <style>
	    BODY{background-color:White;}
	    TABLE{width: 1200px;border-width: 1px;border-style: solid;border-color: white;border-collapse: collapse;}
	    TH{text-align: left;border-width: 1px;padding: 0px;border-style: solid;border-color: white;background-color:#a5aCc7;font-family:tahoma; font-size=12}
	    TD{border-width: 1px;padding: 0px;border-style: solid;border-color: white;font-family:tahoma; font-size=12}
    </style>

    <script src='https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js'></script>
    <script>
    `$(document).ready(function(){
	    `$('tr').each(function(){
		    if (`$(this).children().length > 3){
			    if(`$(this).children().last().text() == 'Not OK'){
				    `$(this).css('background-color','#E4CEC8'); //Red
			    }
			    else{
				    `$(this).css('background-color','#C8E6C8'); //Green
			    }
		    }
	    });
    });
    </script>
"@
    return $Head
}

#This is the main function that is used to verify the Hyper-V environment after deployment finishes.
Function Verify($ExcelFilePathName, $HostAdminUser, $HostAdminPasswordClear, $DomainAdminUser, $DomainAdminPasswordClear, $VMAdminUser, $VMAdminPasswordClear, $ValidatorUserName)
{
    Write-Info "Performing post-installation verification on Excel file: $ExcelFilePathName"

    $securedPassword = ConvertTo-SecureString $HostAdminPasswordClear -AsPlainText -Force
	$credlocal = New-Object System.Management.Automation.PSCredential (".\$HostAdminUser", $securedPassword)

    ### Import from Excel configuration file ###
    $VMEnvironment = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname Environment
    $Hosts = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname Hosts | where Enabled -eq Yes
    $HostNetwork = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname HostNetwork | where 'Hostname(NetBIOS)' -ne $null | where 'Hostname(NetBIOS)' -In $Hosts.'Hostname(NetBIOS)'
    $HostDisks = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname HostDisks | where 'Hostname(NetBIOS)' -ne $null | where 'Hostname(NetBIOS)' -In $Hosts.'Hostname(NetBIOS)'
    $VMs = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname VMs | where {$_.Enabled -eq 'Yes' -and $_.HostIP -In $Hosts.HostIP}
    $VMDisks = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname VMDisks |  where ComputerName -ne $null | where ComputerName -In $VMs.ComputerName
    $VMNetwork = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname VMNetwork |  where ComputerName -ne $null | where ComputerName -In $VMs.ComputerName

    $frag1 = Verify-Environment $VMEnvironment $VMs $Hosts $credlocal
    $frag2 = Verify-Hosts $VMEnvironment $Hosts $HostDisks $credlocal

    #Verify MPS
    $NetBios = GetNetBios $VMEnvironment

    $MPS_VM_Name = ($VMEnvironment | where {$_.Setting -eq "MPS_VM_Name"}).Value
    $MPSConfig = $VMs | where ComputerName -eq $MPS_VM_Name

    $MPSsecuredPassword = ConvertTo-SecureString $DomainAdminPasswordClear -AsPlainText -Force
	$MPScredlocal = New-Object System.Management.Automation.PSCredential ("$NetBios\$DomainAdminUser", $MPSsecuredPassword)

    $frag3 = Verify-VMs $VMEnvironment $MPSConfig $Hosts $VMNetwork $VMDisks $MPScredlocal

    #Verify SDC VM
    $SDC_VM_Name = ($VMEnvironment | where {$_.Setting -eq "SDC_VM_Name"}).Value
    $SDCConfig = $VMs | where ComputerName -eq $SDC_VM_Name

    $frag4 = Verify-VMs $VMEnvironment $SDCConfig $Hosts $VMNetwork $VMDisks $MPScredlocal

    #Verify regular VMs
    $RegularVMs = $VMs | where ComputerName -ne $MPS_VM_Name | where ComputerName -ne $SDC_VM_Name

    $VMsecuredPassword = ConvertTo-SecureString $VMAdminPasswordClear -AsPlainText -Force
	$VMcredlocal = New-Object System.Management.Automation.PSCredential ($VMAdminUser, $VMsecuredPassword)

    $frag5 = Verify-VMs $VMEnvironment $RegularVMs $Hosts $VMNetwork $VMDisks $VMcredlocal

    $Head = Get-HTMLHead

    $Stamp = (Get-Date).toString("d/M/yyyy HH:mm:ss")
    $title = "<Table><tr><th align=`"left`"> HVIM Hardware Report </th><th> Time: $Stamp </th><th> Report Tool Version: $($global:version)</th><th>Run by: $ValidatorUserName</th></tr></Table>"
    $fragments = $frag1,$frag2
    if ($frag3)
    {
        $fragments += $frag3
    }
    if ($frag4)
    {
        $fragments += $frag4
    }
    if ($frag5)
    {
        $fragments += $frag5
    }

    ConvertTo-HTML -Head $Head -PreContent $title -PostContent $fragments | Out-File $LogPath\HVIMValidationReport.htm
}

try
{
	$currentExecutingPath = Split-Path -Path (Split-Path -Path $MyInvocation.MyCommand.Definition -Parent) -Parent

    # Load external scripts
	. "$currentExecutingPath\Deployment\Logger.ps1"
    . "$currentExecutingPath\Deployment\GenericFuncs.ps1"
    . "$currentExecutingPath\Validation\Validation.ps1"
    . "$currentExecutingPath\Verification\GenVerificationFuncs.ps1"
    . "$currentExecutingPath\Verification\VerifyEnvironment.ps1"
    . "$currentExecutingPath\Verification\VerifyHosts.ps1"
    . "$currentExecutingPath\Verification\VerifyVMs.ps1"

    ToolDescription

    if (!(IsRunAsElevatedUser)){
       throw "User must be elevated to admin user to run this tool."
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

    # Read Excel file path name from user input
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
        InitialDirectory = [Environment]::GetFolderPath('Desktop') 
        Filter = 'SpreadSheet (*.xlsm)|*.xlsm'
    }

    $FileBrowser.ShowDialog()

    $ExcelFilePathName = $FileBrowser.FileName

    Write-Host "Excel file path name is: $ExcelFilePathName"

    $ExcelFileName = Split-Path $ExcelFilePathName -Leaf
    $projLogDir = $ExcelFileName.Substring(0, $ExcelFileName.LastIndexOf("."))

    $LogPath = "$currentExecutingPath\Log\$projLogDir"

    New-Item -Path $currentExecutingPath -Name "Log\$projLogDir" -ItemType Directory -Force | Out-Null

    try { 
        Start-Log -LogPath "$LogPath\ValidationReport.log"
    } 
    catch { 
		Write-Host "Failed to create log file at: $LogPath\ValidationReport.log"
    } 

    Write-Info "Run from: $currentExecutingPath"
    Write-Host "Deployment log files location is: $LogPath"
    Write-Host "Main log file name is: Deployment.log"
    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
	Write-Host "Log started at: $Stamp."

    $ValidatorUserName = Read-String "Enter your name" $LastSessionInfo.ValidatorUserName

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
    $LastSessionInfo | Add-Member -MemberType NoteProperty -Name "ValidatorUserName" -Value $ValidatorUserName
	$LastSessionInfo | Add-Member -MemberType NoteProperty -Name "HostAdminPassword" -Value $HostAdminPassword
    $LastSessionInfo | Add-Member -MemberType NoteProperty -Name "DomainAdminPassword" -Value $DomainAdminPassword
    $LastSessionInfo | Add-Member -MemberType NoteProperty -Name "RequiredVMAdminPassword" -Value $RequiredVMAdminPassword

    $LastSessionInfo | Export-Clixml $LastSessionFile

    ### Import from Excel configuration file ###
    $VMs = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname VMs | Where-Object Enabled -eq Yes
    $VMEnvironment = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname Environment
    $VMDisks = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname VMDisks
    $VMNetwork = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname VMNetwork
    $Hosts = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname Hosts | where Enabled -eq Yes
    $HostNetwork = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname HostNetwork
    $HostDisks = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname HostDisks

    Set-Item wsman:\localhost\Client\TrustedHosts * -Force
    restart-service winrm

    Load-HyperVModule
    
    Verify $ExcelFilePathName $HostAdminUser $HostAdminPasswordClear $DomainAdminUser $DomainAdminPasswordClear `
           $RequiredVMAdminUser $RequiredVMAdminPasswordClear $ValidatorUserName
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
    Write-Host "`nHVIM verification tool execution ended."
}
