mode 300 #Make window bigger

Import-Module UpdateServices #Import UpdateServices module for wsus manipulation
Import-Module FailoverClusters #Module for cluster validation

[void][reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")            
$wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::getUpdateServer("MPS1",$False, 8530) #Create WSUS object

#Create updates and computers scopes variables
$computerscope = New-Object Microsoft.UpdateServices.Administration.ComputerTargetScope
$updatescope = New-Object Microsoft.UpdateServices.Administration.UpdateScope

#Get updates summries from Wsus
$wsus.GetSummariesPerComputerTarget($updatescope,$computerscope) |

    Format-Table @{L=’ComputerTarget’;E={($wsus.GetComputerTarget([guid]$_.ComputerTargetId)).FullDomainName}},

        @{L=’NeededCount’;E={($_.DownloadedCount + $_.NotInstalledCount)}},DownloadedCount,NotApplicableCount,NotInstalledCount,InstalledCount,FailedCount

#Take a screenshot
Start-Sleep(2)
Invoke-Expression "& `"c:\users\administrator\documents\screenshot_func.ps1`" '$env:USERPROFILE\Documents\' wsus100.jpg"

#Generate cluster report htm file
Test-Cluster -ReportName 'C:\Users\hercules\Documents\cluster_validation.htm' -Force