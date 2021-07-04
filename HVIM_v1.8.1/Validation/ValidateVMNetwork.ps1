# This module validates the Excel VMNetwork tab details


#Validate VM vSwitch name
Function Validate-VMNetworkSwitchName($VMNet, $VMs, $Hosts, $HostNetwork)
{
    $VM = $VMs | where ComputerName -eq $VMNet.ComputerName
    if ($VM -eq $null){
        Write-Warning "'$($VMNet.ComputerName)' doesn't exist in VMs sheet"
        $global:validationWarnings += 1
        return
    }
    $VMHost = $Hosts | where HostIP -eq $VM.HostIP
    $HostNet = $HostNetwork | where 'Hostname(NetBIOS)' -eq $VMHost.'Hostname(NetBIOS)'
        
    if ($HostNet.vSwitchName -notcontains $VMNet.vSwitchName){
        Write-Error "vSwitch name '$($VMNet.vSwitchName)' used by VM '$($VM.ComputerName)' isn't defined on its Hyper-V host '$($VMHost.'Hostname(NetBIOS)')'"
        $global:validationErrors += 1
    }
}

#Validates the Excel VMNetwork tab details
Function Validate-VMNetwork($VMNetwork, $VMs, $Hosts, $HostNetwork)
{
    Write-Info "Validating VMNetwork Excel sheet."

    foreach ($VMNet in $VMNetwork){
        Validate-VMIP $VMNet.IP $VMNet.ComputerName
        Validate-VMSubnet $VMNet.Subnet $VMNet.ComputerName
        Validate-VMNetworkSwitchName $VMNet $VMs $Hosts $HostNetwork
    }
}

