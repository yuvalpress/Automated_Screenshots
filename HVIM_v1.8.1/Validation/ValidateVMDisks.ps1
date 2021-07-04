# This module validates the Excel VMDisks tab details

# Validates drive letter is in the correct format.
Function Validate-DriveLetter ($VMDisk)
{
    if ($VMDisk.DriveLetter -ne $null)
    {
        $pat = "^[a-zA-Z]+$"
        if ($VMDisk.DriveLetter -notmatch $pat)
        {
            Write-Error "'$($VMDisk.ComputerName)' has invalid drive letter '$($VMDisk.DriveLetter)'. It can only contain letters."
            $global:validationErrors += 1
        } 
        elseif ($VMDisk.DriveLetter.Length -gt 1)
        {
            Write-Error "'$($VMDisk.ComputerName)' has invalid drive letter '$($VMDisk.DriveLetter)'. It can only contain a single letter."
            $global:validationErrors += 1
        }
    }
}

#Validates the Excel VMDisks tab details
Function Validate-VMDisks($VMDisks)
{
    Write-Info "Validating VMDisks Excel sheet."

    foreach ($VMDisk in $VMDisks){
        Validate-DriveLetter $VMDisk
    }
}

