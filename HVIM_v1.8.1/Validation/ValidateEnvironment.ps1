# Validates the specified domain name is in the correct format.
Function Validate-DomainName($VMEnvironment)
{
    $Domain = ($VMEnvironment | where {$_.Setting -eq "Domain_Name"}).Value

    if ($Domain -eq $null)
    {
        Write-Error "Domain_Name: Domain name field can't be empty!"
        $global:validationErrors += 1
    }

    $NetBios = GetNetBios $VMEnvironment
    if ($NetBios.Length -gt 15)
    {
        Write-Error "NetBios name can't exceed 15 chars [$NetBios]."
        $global:validationErrors += 1
    }

    if (Test-Connection -ComputerName $Domain -Count 1 -Quiet)
    {
        Write-Warning "Domain_Name: Domain name '$Domain' already exists!"
        $global:validationWarnings += 1
    }
}

# Validates domain IP address is in the correct format and that it is available.
Function Validate-DomainIP($VMEnvironment)
{
    $Domain_IP = ($VMEnvironment | where {$_.Setting -eq "Domain_IP"}).Value

    try
    {
        [ipaddress]$Domain_IP | Out-Null
    }
    catch [Exception]
    {
        Write-Error "Domain_IP: Invalid IP address [$Domain_IP]."
        $global:validationErrors += 1
    }
}

# Validates MPS VM name doesn't contain spaces
Function Validate-MPS_VM_Name($VMEnvironment)
{
    $MPS_VM_Name = ($VMEnvironment | where {$_.Setting -eq "MPS_VM_Name"}).Value
    if (!($MPS_VM_Name -imatch '\w+'))
    {
        Write-Error "MPS_VM_Name: Invalid MPS name '$MPS_VM_Name'."
        $global:validationErrors += 1
    }
}

# Validates Template Source Path is accessible.
Function Validate-TemplateSourcePath ($VMEnvironment)
{
    $Domain = ($VMEnvironment | where {$_.Setting -eq "Domain_Name"}).Value
    if (IsInDomain($Domain)){
        return
    }

	$TemplateSourcePath = ($VMEnvironment | where {$_.Setting -eq "TemplateSourcePath"}).Value
    if (!(Test-Path -Path $TemplateSourcePath))
    {
        Write-Error "TemplateSourcePath: Failed to access path '$TemplateSourcePath'"
        $global:validationErrors += 1
    }
}

# Validates Template Path on server is not empty.
Function Validate-TemplatePathOnServer ($VMEnvironment)
{
    $TemplatePathOnServer = ($VMEnvironment | where {$_.Setting -eq "TemplatePathOnServer"}).Value
    if ($TemplatePathOnServer -eq $null)
    {
        Write-Error "TemplatePathOnServer: Template path on server can't be empty "
        $global:validationErrors += 1
    }
}

# Validates MPS kit path is accessible.
Function Validate-MPSKitPath ($VMEnvironment)
{
    $Domain = ($VMEnvironment | where {$_.Setting -eq "Domain_Name"}).Value
    if (IsInDomain($Domain)){
        return
    }

    $MPSKitPath = ($VMEnvironment | where {$_.Setting -eq "MPSKitPath"}).Value
    if (!(Test-Path -Path $MPSKitPath))
    {
        Write-Error "MPSKitPath: Failed to access path '$MPSKitPath'"
        $global:validationErrors += 1
    }
}

# Validates environment is Standalone or Cluster only.
Function Validate-EnvironmentType ($VMEnvironment)
{
    $EnvironmentType = ($VMEnvironment | where Setting -eq "Environment").Value

    if ($EnvironmentType -ne 'Standalone' -and $EnvironmentType -ne 'Cluster')
    {
        Write-Error "Environment: can be 'Standalone' or 'Cluster' only!"
        $global:validationErrors += 1
    }
}

# Validates environment Excel sheet.
Function Validate-Environment($VMEnvironment)
{
    Write-Info "Validating Environment Excel sheet."

    Validate-DomainName $VMEnvironment
    Validate-DomainIP $VMEnvironment
    Validate-MPS_VM_Name $VMEnvironment
    Validate-TemplateSourcePath $VMEnvironment
    Validate-TemplatePathOnServer $VMEnvironment
    Validate-MPSKitPath $VMEnvironment
    Validate-EnvironmentType $VMEnvironment
}
