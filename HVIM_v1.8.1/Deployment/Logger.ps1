# This module implements a logger that is used by other functions and code in the tool
$global:version = "1.8.1"
$global:excelVersion = "1.6"

# This is called in order to start the logger
function Start-Log([Parameter(Mandatory=$true)][String] $LogPathName)
{
	$global:LogPathName = $LogPathName
	$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")

	Add-Content -Path $global:LogPathName -Value "***************************************************************************************************"
	Add-Content -Path $global:LogPathName -Value "Hyper-V deployment tool version: $global:version"
    Add-Content -Path $global:LogPathName -Value "Deployment log file location is: $global:LogPathName"
	Add-Content -Path $global:LogPathName -Value "Log started at: $Stamp."
	Add-Content -Path $global:LogPathName -Value "***************************************************************************************************"
}

# This is called in order to stop the logger
function Stop-Log()
{
	$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")

	Add-Content -Path $global:LogPathName -Value  "***************************************************************************************************"
	Add-Content -Path $global:LogPathName -Value  "Log ended at: $Stamp."
	Add-Content -Path $global:LogPathName -Value  "***************************************************************************************************"
	Add-Content -Path $global:LogPathName -Value  ""

	$global:LogPathName = $null
}

# Write the the log file and to the screen console
function Write-Log([Parameter(Mandatory=$true)]$message, 
                    $color, 
                    $Level,
                    $scriptName,
                    $scriptLineNumber) {
	$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")

    If ($global:LogPathName -ne $null){
	    Add-Content -Path $global:LogPathName -Value "$Stamp $Level`t$($scriptName):($scriptLineNumber) $message"
    }

	$Time = (Get-Date).toString("HH:mm:ss")

	if ($Level -ne 'INFO')
	{
		$message = "$($Level): $message"
	}
    $message = "$Time $message"

	Write-Host -ForegroundColor $color $message
}

# Write log message as information
function Write-Info([Parameter(Mandatory=$true)]$message) {
    if ($MyInvocation.ScriptName)
    {
        $scriptName = Split-Path -Leaf $MyInvocation.ScriptName 
        $scriptLineNumber = $MyInvocation.ScriptLineNumber
    }

	Write-Log $message 'white' 'INFO' $scriptName $scriptLineNumber
}

# Write log message as warning
function Write-Warning([Parameter(Mandatory=$true)]$message) {
    if ($MyInvocation.ScriptName)
    {
        $scriptName = Split-Path -Leaf $MyInvocation.ScriptName 
        $scriptLineNumber = $MyInvocation.ScriptLineNumber
    }

	Write-Log $message 'yellow' 'WARNING' $scriptName $scriptLineNumber
}

# Write log message as error
function Write-Error([Parameter(Mandatory=$true)]$message) {
    if ($MyInvocation.ScriptName)
    {
    	$scriptName = Split-Path -Leaf $MyInvocation.ScriptName 
    	$scriptLineNumber = $MyInvocation.ScriptLineNumber
    }

	Write-Log $message 'red' 'ERROR' $scriptName $scriptLineNumber
}

# Write log message as success
function Write-Success([Parameter(Mandatory=$true)]$message) {
    if ($MyInvocation.ScriptName)
    {
    	$scriptName = Split-Path -Leaf $MyInvocation.ScriptName 
    	$scriptLineNumber = $MyInvocation.ScriptLineNumber
    }

	Write-Log $message 'green' 'SUCCESS' $scriptName $scriptLineNumber
}

# Write log message as failure
function Write-Failure([Parameter(Mandatory=$true)]$message) {
    if ($MyInvocation.ScriptName)
    {
    	$scriptName = Split-Path -Leaf $MyInvocation.ScriptName 
    	$scriptLineNumber = $MyInvocation.ScriptLineNumber
    }

	Write-Log $message 'red' 'FAILURE' $scriptName $scriptLineNumber
}


#Start-Log -LogPath "D:\Work\Automation\Log\Deployment2.log"

#Write-Info "Testing Info"
#Write-Warning "Testing Warning"
#Write-Error "Testing Error"
#Write-Success "Testing Sucess"
#Write-Failure "Testing Failure"

#Stop-Log
