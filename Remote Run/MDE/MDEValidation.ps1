#Fetch arguments
$user = 'root'
$password = 'password'
$ip = $args[0]
$logFile = $args[1]

Write-Host "Starting validation.."

#Apply commands to server
Write-Output y | plink -v $user@$ip -pw $password -m "$($PSScriptRoot)\commands.txt" > $logFile
Write-Host "Validation has been finished" -ForegroundColor Green
