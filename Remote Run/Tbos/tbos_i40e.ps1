#Fetch arguments
$user = 'root'
$password = 'password'
$ip = $args[0]
$logFile = $args[1]
$screenshot = $args[2]

Write-Host "Starting validation.."

#Apply commands to server
echo y | plink -v $user@$ip -pw $password -m "$($PSScriptRoot)\i40e.txt" > $logFile

#Take a screenshot of file
Invoke-Item $logFile
Start-Sleep(1)

Invoke-Expression "& `"$PSScriptRoot\screenshot_func.ps1`" '$screenshot\i40e.jpg'"
Start-Sleep(1)
Remove-Item $logFile

Write-Host "Validation has been finished" -ForegroundColor Green
1