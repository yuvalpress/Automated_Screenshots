# Verifies if a domain controller exists by pinging it's IP address
Function Verify-DomainExists($VMEnvironment, $session)
{
    $Domain = ($VMEnvironment | where {$_.Setting -eq "Domain_Name"}).Value
    $Domain_IP = ($VMEnvironment | where {$_.Setting -eq "Domain_IP"}).Value

    Write-Info "Checking if domain '$Domain' exists."

    $testResult = Invoke-Command $session -ErrorAction SilentlyContinue -ScriptBlock {
        Test-Connection -ComputerName $using:Domain_IP -Count 1
    }

    $obj = NewReportObject
    $obj.'Check Name' = "Domain IP"
    $obj.'Required Value' = $Domain_IP

    if ($testResult)
    {
        $obj.'Current Value' = $testResult[0].IPV4Address.IPAddressToString
    }

    UpdateStatus $obj

    return $obj
}

# Verifies if an MPS VM exists by 
Function Verify-MPS($VMEnvironment, $session)
{
    $MPS_VM_Name = ($VMEnvironment | where {$_.Setting -eq "MPS_VM_Name"}).Value

    Write-Info "Checking if '$MPS_VM_Name' VM exists."

    $testResult = Invoke-Command $session -ScriptBlock {
        Get-VM -Name $using:MPS_VM_Name -ErrorAction SilentlyContinue
    }
    
    $obj = NewReportObject
    $obj.'Check Name' = "MPS VM Name"
    $obj.'Required Value' = $MPS_VM_Name

    if ($testResult)
    {
        $obj.'Current Value' = $MPS_VM_Name
    }    

    UpdateStatus $obj

    return $obj
}

# Verifies cluster name and IP address is as configured.
Function Verify-Cluster($VMEnvironment, $session)
{
    $Cluster_Name = ($VMEnvironment | where {$_.Setting -eq "Cluster_Name"}).Value
    $Cluster_IP_Adress = ($VMEnvironment | where {$_.Setting -eq "Cluster_IP_Adress"}).Value

    Write-Info "Checking if Cluster '$Cluster_Name' exists."

    $testResult = Invoke-Command $session -ScriptBlock {
        Test-Connection -ComputerName $using:Cluster_Name -Count 1
    }

    $objList = @()

    $obj = NewReportObject
    $obj.'Check Name' = "Cluster Name"
    $obj.'Required Value' = $Cluster_Name

    if ($testResult)
    {
        $obj.'Current Value' = $Cluster_Name
    }    

    UpdateStatus $obj
    $objList += $obj

    $obj = NewReportObject
    $obj.'Check Name' = "Cluster IP Address"
    $obj.'Required Value' = $Cluster_IP_Adress

    if ($testResult)
    {
        $obj.'Current Value' = $testResult[0].IPV4Address.IPAddressToString
    }    

    UpdateStatus $obj

    $objList += $obj


    return $objList
}

# Verifies the environment is configurted correctly
Function Verify-Environment($VMEnvironment, $VMs, $Hosts, $credlocal)
{
    Write-Info "Verifying Environment."

    $MPS_VM_Name = ($VMEnvironment | where {$_.Setting -eq "MPS_VM_Name"}).Value
    $MPSConfig = $VMs | where ComputerName -eq $MPS_VM_Name

    $EnvironmentVars = @()

    if ($MPSConfig -eq $null)
    {
        Write-Warning "Can't verify environment, since MPS configuration is missing or disabled in Excel VMs tab."

        $title = "<BR><Table><tr><th><B> Environment Info - Missing</B></th><tr><Table>"

        $frag = $EnvironmentVars | ConvertTo-HTML -Fragment -PreContent $title | Out-String

        return $frag
    }

    $session = New-PSSession -Credential $credlocal -ComputerName $MPSConfig.HostIP

    try
    {
        $EnvironmentVars += Verify-DomainExists $VMEnvironment $session
        $EnvironmentVars += Verify-MPS $VMEnvironment $session

        $EnvironmentType = ($VMEnvironment | where Setting -eq "Environment").Value

        if ($EnvironmentType -eq 'Cluster')
        {
            $EnvironmentVars += Verify-Cluster $VMEnvironment $session
        }

        $title = "<BR><Table><tr><th><B> Environment Info </B></th><tr><Table>"

        $frag = $EnvironmentVars | ConvertTo-HTML -Fragment -PreContent $title | Out-String
    }
    finally
    {        
        Remove-PSSession -Session $session
    }


    return $frag
}