# This module validates the Excel hosts tab details

#Validate Hyper-V Host's IP address 
Function Validate-HostIP($HostIP, $HostName)
{
    if (!(Validate-IPAddress $HostIP)){
        Write-Error "Invalid host IP address value '$HostIP' defined for host '$HostName'"
        $global:validationErrors += 1
    } elseif (!(Test-Connection $HostIP -Count 1 -Quiet)){
        Write-Error "$HostName at IP $HostIP can't be reached!"
        $global:validationErrors += 1
    }
}

#Validate Hyper-V Host's subnet mask
Function Validate-HostSubnet($SubnetMask, $HostName)
{
    if ($SubnetMask -eq $null){
        Write-Error "A subnet must be defined for host '$HostName'"
        $global:validationErrors += 1
    } elseif (!(Validate-IPAddress $Hst.SubnetMask)){
        Write-Error "Invalid subnet value '$($Hst.SubnetMask)' defined for host '$HostName'"
        $global:validationErrors += 1
    }
}

#Validate Hyper-V Host's default gateway
Function Validate-HostDefaultGateway($DefaultGateway, $HostName)
{
    if ($DefaultGateway -eq $null){
        Write-Error "A Default Gateway must be defined for host '$HostName'"
        $global:validationErrors += 1
    } elseif (!(Validate-IPAddress $Hst.DefaultGateway)){
        Write-Error "Invalid Default Gateway value '$($Hst.DefaultGateway)' defined for host '$HostName'"
        $global:validationErrors += 1
    }
}

#Validate Hyper-V Host's secondary DNS
Function Validate-HostSecondaryDNS($SecondaryDNS, $HostName)
{
    if ($SecondaryDNS -ne $null){
        if (!(Validate-IPAddress $Hst.SecondaryDNS)){
            Write-Error "Invalid DNS server address value '$($Hst.SecondaryDNS)' defined for host '$HostName'"
            $global:validationErrors += 1
        }
    }
}

#Validates the Excel hosts tab details
Function Validate-Hosts($Hosts)
{
    Write-Info "Validating Hosts Excel sheet."

    foreach ($Hst in $Hosts){
        Validate-HostIP $Hst.HostIP $Hst.'Hostname(NetBIOS)'
        Validate-HostSubnet $Hst.SubnetMask $Hst.'Hostname(NetBIOS)'
        Validate-HostDefaultGateway $Hst.DefaultGateway $Hst.'Hostname(NetBIOS)'
        Validate-HostSecondaryDNS $Hst.SecondaryDNS $Hst.'Hostname(NetBIOS)'
    }
}

