mode 300 #Make window bigger

Import-Module UpdateServices #Import UpdateServices module for wsus manipulation

[void][reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")            
$wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::getUpdateServer("127.0.0.1",$False, 8530) #Create WSUS object

#Create updates and computers scopes variables
$computerscope = New-Object Microsoft.UpdateServices.Administration.ComputerTargetScope
$updatescope = New-Object Microsoft.UpdateServices.Administration.UpdateScope

#Get updates summries from Wsus
$wsus.GetSummariesPerComputerTarget($updatescope,$computerscope) |

    Format-Table @{L=’ComputerTarget’;E={($wsus.GetComputerTarget([guid]$_.ComputerTargetId)).FullDomainName}},

        @{L=’NeededCount’;E={($_.DownloadedCount + $_.NotInstalledCount)}},DownloadedCount,NotApplicableCount,NotInstalledCount,InstalledCount,FailedCount

#Take a screenshot
Invoke-Expression "& `"c:\users\administrator\documents\screenshot_func.ps1`" 'c:\Users\Administrator\Documents\' wsus100.jpg"