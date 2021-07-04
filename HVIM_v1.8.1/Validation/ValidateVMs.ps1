# This module validated the Excel VMs tab details

#Validate VM default gateway
Function Validate-VMDefaultGateway($DefaultGateway, $VMName)
{
    if ($VM.DefaultGateway -eq $null){
        Write-Error "A Default Gateway must be defined for VM '$VMName'"
        $global:validationErrors += 1
    } elseif (!(Validate-IPAddress $VM.DefaultGateway)){
        Write-Error "Invalid Default Gateway value '$($VM.DefaultGateway)' defined for VM '$VMName'"
        $global:validationErrors += 1
    }
}

#Validate VM secondary DNS
Function Validate-VMSecondaryDNS($SecondaryDNS, $VMName)
{
    if ($VM.SecondaryDNS -ne $null){
        if (!(Validate-IPAddress $VM.SecondaryDNS)){
            Write-Error "Invalid DNS server address value '$($VM.SecondaryDNS)' defined for VM '$VMName'"
            $global:validationErrors += 1
        }
    }
}

#Validate VM vSwitch name
Function Validate-VMSwitchName($VM, $Hosts, $HostNetwork)
{
    $VMHost = $Hosts | where HostIP -eq $VM.HostIP
    $HostNet = $HostNetwork | where 'Hostname(NetBIOS)' -eq $VMHost.'Hostname(NetBIOS)'
        
    if ($HostNet.vSwitchName -notcontains $VM.vSwitchName){
        Write-Error "vSwitch name '$($VM.vSwitchName)' used by VM '$($VM.ComputerName)' isn't defined on its Hyper-V host '$($VMHost.'Hostname(NetBIOS)')'"
        $global:validationErrors += 1
    }
}

#Validate VM volume path
Function Validate-VMVolumePath($VM, $Hosts, $HostDisks)
{
    $VMHost = $Hosts | where HostIP -eq $VM.HostIP
    $HostDsk = $HostDisks | where 'Hostname(NetBIOS)' -eq $VMHost.'Hostname(NetBIOS)'

    $driveLetter = $($VM.Volume).Substring(0, 1)

    if ($HostDsk.DriveLetter -notcontains $driveLetter -and $driveLetter -ne 'C'){
        Write-Error "VM '$($VM.ComputerName)' volume path '$($VM.Volume)' isn't valid, since drive $($driveLetter): isn't supposed to exist on its Hyper-V host '$($VMHost.'Hostname(NetBIOS)')'"
        $global:validationErrors += 1
    }
}

#Validates Excel VMs tab details
Function Validate-VMs ($VMs, $Hosts, $HostNetwork, $HostDisks)
{
    Write-Info "Validating VMs Excel sheet."

    foreach ($VM in $VMs){
        Validate-VMIP $VM.PrimaryIP $VM.ComputerName
        Validate-VMSubnet $VM.Subnet $VM.ComputerName
        Validate-VMDefaultGateway $VM.DefaultGateway $VM.ComputerName
        Validate-VMSecondaryDNS $VM.SecondaryDNS $VM.ComputerName
        Validate-VMSwitchName $VM $Hosts $HostNetwork
        Validate-VMVolumePath $VM $Hosts $HostDisks
    }

}

