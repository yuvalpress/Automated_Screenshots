# This module validates the Excel hostDisks tab details

# Validates specified disk number exists.
Function Validate-DiskExist ($HostDisk, $Hosts, $credlocal)
{
    $hst = $Hosts | where 'Hostname(NetBIOS)' -eq $HostDisk.'Hostname(NetBIOS)'

    $Disk = Invoke-Command -ComputerName $hst.HostIP -Credential $credlocal -ErrorAction Stop -ScriptBlock{
        Get-Disk -Number $using:HostDisk.DiskNum -ErrorAction SilentlyContinue
    }
    if ($Disk -eq $null)
    {
        Write-Error "Disk number $($HostDisk.DiskNum) doesn't exist on host '$($HostDisk.'Hostname(NetBIOS)')'"
        $global:validationErrors += 1
    }
}

#Validates the Excel hostDisks tab details
Function Validate-HostDisks($HostDisks, $Hosts, $HostAdminUser,$HostAdminPasswordClear)
{
    Write-Info "Validating HostDisks Excel sheet."

    foreach ($HostDisk in $HostDisks){
        Validate-DiskExist $HostDisk $Hosts $HostAdminUser $HostAdminPasswordClear
    }
}

