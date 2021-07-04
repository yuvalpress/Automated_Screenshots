# This module validates the input in the HVIM Excel file. It prints out the number of errors and warinings found.

$global:validationErrors = 0
$global:validationWarnings = 0

. "$currentExecutingPath\Validation\GenValidationFuncs.ps1"
. "$currentExecutingPath\Validation\ValidateEnvironment.ps1"
. "$currentExecutingPath\Validation\ValidateHosts.ps1"
. "$currentExecutingPath\Validation\ValidateVMs.ps1"
. "$currentExecutingPath\Validation\ValidateHostNetwork.ps1"
. "$currentExecutingPath\Validation\ValidateVMNetwork.ps1"
. "$currentExecutingPath\Validation\ValidateHostDisks.ps1"
. "$currentExecutingPath\Validation\ValidateVMDisks.ps1"

# In case there are VM's that their host is disabled or not exist this will display a warning
# inclusing the list of VM's that will be implicitly disabled.
Function ValidateDisabledVMs ($VMs)
{
    $vmNames = ""
    if ($VMs -ne $null)
    {
        foreach ($vm in $VMs)
        {
            $vmNames = $vmNames + $vm.ComputerName + ","
        }
        $vmNames = $vmNames.Trim(",")

        Write-Warning "The following VMs won't be deployed, since their host is disabled: $vmNames"

        $global:validationWarnings += 1
    }
}

# This is the main function that validates the HVIM excel file before starting the deployment.
# In case errors are found, the HVIM tool will not continue with the deployment.
# This function displays the number of errors and warnings that are found during the validation process.
Function Validate($ExcelFilePathName, $HostAdminUser, $HostAdminPasswordClear)
{
    Write-Info "Performing pre-installation validation of HVIM Excel file: $ExcelFilePathName"

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
    
    $ImplicitlyDisabledVMs = Import-Excel -Path "$ExcelFilePathName" -WorkSheetname VMs | where {$_.Enabled -eq 'Yes' -and $_.HostIP -NotIn $Hosts.HostIP}
    ValidateDisabledVMs $ImplicitlyDisabledVMs

    Validate-Environment $VMEnvironment
    Validate-Hosts $Hosts
    Validate-VMs $VMs $Hosts $HostNetwork $HostDisks 
    Validate-HostNetwork $Hosts $HostNetwork $credlocal
    Validate-VMNetwork $VMNetwork $VMs $Hosts $HostNetwork $credlocal
    Validate-HostDisks $HostDisks $Hosts $credlocal
    Validate-VMDisks $VMDisks

    Write-Info "Validation errors: $global:validationErrors"
    Write-Info "Validation warnings: $global:validationWarnings"

    if ($global:validationErrors -gt 0){
        return $false
    }

    return $true
}