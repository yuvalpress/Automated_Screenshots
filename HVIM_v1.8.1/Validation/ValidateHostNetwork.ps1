# This module validates the Excel HostNetwork tab details

#Validate Hyper-V Host's teaming settings 
Function Validate-ManagmentTeamingNICs($HostNet, $Hosts, $HostNetwork, $credlocal)
{
    $hostsname = $HostNet.'Hostname(NetBIOS)'
    $NetAdapterNames = $HostNet.TeamingNICs.Split(',')
    if ($NetAdapterNames.Length -lt 2)
    {
        Write-Error "Value for Teaming NICs on host $hostsname isn't valid '$($HostNet.TeamingNICs)'"
        $global:validationErrors += 1
    } else {
	    $NetAdapter1 = $NetAdapterNames[0].Trim()
	    $NetAdapter2 = $NetAdapterNames[1].Trim()

        $ManagementTeamingName = ($HostNetwork | where { $_.'Hostname(NetBIOS)' -eq $hostsname -and $_.IsForManagement -eq 'Yes'}).TeamingName

        $hst = $Hosts | where 'Hostname(NetBIOS)' -eq $hostsname

        $NetTeaming = Invoke-Command -ComputerName $hst.HostIP -Credential $credlocal -ScriptBlock {
            Get-NetLBFOTeam –Name $using:ManagementTeamingName -ErrorAction SilentlyContinue
        }
        #Only if network is not configured on host we will check the following
        if ($NetTeaming -eq $null){
            $status = Invoke-Command -ComputerName $hst.HostIP -Credential $credlocal -ScriptBlock {
                $NetIPAddress1 = Get-NetIPAddress -InterfaceAlias $using:NetAdapter1 | where AddressFamily -eq 'IPv4'
                $NetIPAddress2 = Get-NetIPAddress -InterfaceAlias $using:NetAdapter2 | where AddressFamily -eq 'IPv4'
                if (!($NetIPAddress1.IPAddress.Contains($using:hst.HostIP)) -and 
                    !($NetIPAddress2.IPAddress.Contains($using:hst.HostIP))){
                    return $false
                }
                return $true
            }
            if (!$status){
                Write-Error "Host '$hostsname' management IP address $($hst.HostIP) should be configured on '$NetAdapter1' or '$NetAdapter2' network adapters only!"
                $global:validationErrors += 1
            }
        }
    }
}

# Validates extra teaming NICs is composed of two NICs, comma seperated.
Function Validate-ExtraTeamingNICs($HostNet)
{
    $NetAdapterNames = $HostNet.TeamingNICs.Split(',')
    if ($NetAdapterNames.Length -lt 2)
    {
        Write-Error "Value for Teaming NICs on host $hostsname isn't valid '$($HostNet.TeamingNICs)'"
        $global:validationErrors += 1
    }
}

#Validates the Excel HostNetwork tab details
Function Validate-HostNetwork($Hosts, $HostNetwork, $credlocal)
{
    Write-Info "Validating HostNetwork Excel sheet."

    foreach ($HostNet in $HostNetwork){
        if ($HostNet -eq $null){
            break
        }
        if ($HostNet.IsForManagement -eq 'Yes'){
            Validate-ManagmentTeamingNICs $HostNet $Hosts $HostNetwork $credlocal
        }
        else {
            Validate-ExtraTeamingNICs $HostNet
        }
    }
}

