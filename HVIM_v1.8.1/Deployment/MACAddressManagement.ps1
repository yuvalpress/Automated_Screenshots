Function Get-FreeMACAddressRange($session)
{
    $StartMACAddress = "00155D001000"

    $MACAddressInfoFile = "$global:currentExecutingPath\MACAddressInfo.xml"
    $LastMACAddressName = $global:projLogDir + "_LastMACAddress"

    if (Test-Path $MACAddressInfoFile)
    {
	    $MACAddressInfo = Import-Clixml $MACAddressInfoFile
		$LastMACAddress = $MACAddressInfo.$LastMACAddressName
    }
    else
    {
        $MACAddressInfo = New-Object PSobject
        $LastMACAddress = $null
    }

    if ($LastMACAddress -eq $null)
    {
        $LastMACAddress = $StartMACAddress # Start of the Hyper-V MAC address range
    }
    else
    {
        $LastMACAddressNum = [convert]::ToInt64($LastMACAddress, 16)
        $LastMACAddressNum += 0x1000
        $LastMACAddress = '{0:X12}' -f $LastMACAddressNum
    }

    if ($MACAddressInfo.$LastMACAddressName -ne $null)
    {
        $MACAddressInfo.$LastMACAddressName = $LastMACAddress
    }
    else
    {
        $MACAddressInfo | Add-Member -MemberType NoteProperty -Name $LastMACAddressName -Value $LastMACAddress
    }

    $MACAddressInfo | Export-Clixml $MACAddressInfoFile
        
    $MacAddressMinimum = '{0:X12}' -f $LastMACAddress
    $LastMACAddressNum = [convert]::ToInt64($LastMACAddress, 16)
    $MacAddressMaximum = '{0:X12}' -f ($LastMACAddressNum + 0xFFF)

    $MACAddressRangeInfo = New-Object PSobject
    $MACAddressRangeInfo | Add-Member -MemberType NoteProperty -Name MacAddressMinimum -Value $MacAddressMinimum
    $MACAddressRangeInfo | Add-Member -MemberType NoteProperty -Name MacAddressMaximum -Value $MacAddressMaximum


    return $MACAddressRangeInfo
}

<#
$currentExecutingPath = Split-Path -Path (Split-Path -Path $MyInvocation.MyCommand.Definition -Parent) -Parent

$HostAdminPasswordClear = "Rel7.xPass!"
$HostAdminUser = "Administrator"
$securedPassword = ConvertTo-SecureString $HostAdminPasswordClear -AsPlainText -Force
$credlocal = New-Object System.Management.Automation.PSCredential (".\$HostAdminUser", $securedPassword)

$Hosts = Import-Excel -Path "$currentExecutingPath\Config\NPILAB-VIM - Cluster.xlsm" -WorkSheetname Hosts | where Enabled -eq Yes

$Hst = $Hosts[0]

$session = New-PSSession -ComputerName $Hst.HostIP -Credential $credlocal

$projLogDir = "NPILAB-VIM"

Get-FreeMACAddressRange($session)


for ($i=0; $i -lt 10; $i++)
{
    Get-FreeMACAddressRange($session)
}
Remove-PSSession -Session $session

#>