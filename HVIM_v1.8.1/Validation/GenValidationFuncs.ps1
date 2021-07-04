# This module contain generic validation functions

#Validates the input IP address format
Function Validate-IPAddress($IPAddress)
{
    try
    {
        [ipaddress]$IPAddress | Out-Null
    }
    catch [Exception]
    {
        return $false
    }

    return $true
}

#Validates VM IP address
Function Validate-VMIP($VMIP, $VMName)
{
    if ($VMIP -eq $null){
        Write-Error "VM IP address must be defined for VM '$VMName'"
        $global:validationErrors += 1
    } elseif (!(Validate-IPAddress $VMIP)){
        Write-Error "Invalid IP address value '$VMIP' defined for VM '$VMName'"
        $global:validationErrors += 1
    } elseif (!(Validate-IPAddressFree $VMIP)){
        Write-Error "IP address '$VMIP' for VM '$VMName' is already in use!"
        $global:validationErrors += 1
    }
}

# Validates the input IP is free by pinginf it.
Function Validate-IPAddressFree([Parameter(Mandatory=$true)] $VMIP){
	if (Test-Connection -ComputerName $VMIP -Count 1 -Quiet){
        return $false
	}   

    return $true;
}

#Validates VM subnet mask
Function Validate-VMSubnet($Subnet, $VMName)
{
    if ($Subnet -eq $null){
        Write-Error "A subnet must be defined for VM '$VMName'"
        $global:validationErrors += 1
    } elseif (!(Validate-IPAddress $Subnet)){
        Write-Error "Invalid subnet value '$Subnet' defined for VM '$VMName'"
        $global:validationErrors += 1
    }
}

#Validates tool version number against Excel file version
Function Validate-ExcelFileVersion($ExcelFilePathName)
{
    $ExcelFileComment = Get-ExcelWorkbookInfo -Path $ExcelFilePathName | select -ExpandProperty Comments
	$ExcelFileVersion = $ExcelFileComment.Split(' ')[1]
	
    $SupportedExcelVersion = "Version $global:excelVersion"
    if ($global:excelVersion -eq $ExcelFileVersion){
        return $true
    }
	else
	{
		Write-Host "HVIM Excel file version: $ExcelFileVersion" 
		Write-Host "HVIM Excel supported version: $global:excelVersion" 
	}
	
    return $false
}
