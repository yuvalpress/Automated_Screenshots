#Take a picture of diskmgmt.msc window
$pid1 = Start-Process diskmgmt.msc -PassThru
Start-Sleep(1)
Invoke-Expression "& `"C:\Users\Administrator\Documents\screenshot_func.ps1`" '$env:USERPROFILE\Documents\' diskpart.jpg"
Stop-Process $pid1


#Take a picture of control pannel system window
Show-ControlPanelItem *system*
Start-Sleep(2)
Invoke-Expression "& `"C:\Users\Administrator\Documents\screenshot_func.ps1`" '$env:USERPROFILE\Documents\' system.jpg"
#Close the system window
(New-Object -comObject Shell.Application).Windows() | foreach-object {$_.quit()}

#Take a screenshot of network ipconfig/all
Start-Process cmd.exe '/k ipconfig' -WindowStyle Maximized
Start-Sleep(1)
Invoke-Expression "& `"C:\Users\Administrator\Documents\screenshot_func.ps1`" '$env:USERPROFILE\Documents\' network.jpg"