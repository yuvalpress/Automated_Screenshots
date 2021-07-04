#Check what servers to connect to

if($args[0] -eq "Sau") {
    $source = ".\Remote Run\Sau\sau.ps1"
    $screenshot = ".\Remote Run\Sau\screenshot_func.ps1"
    $ip = $args[1]
    $validationURL = $args[2]

    Write-Host("Execution will be performed on server: $ip")

    #Create encrypted password file
    read-host -prompt "Password" -assecurestring | convertfrom-securestring | out-file "Files\rel_pass.txt"

    #Create the credentials object
    $username = "administrator"
    $password = Get-Content 'Files\rel_pass.txt' | ConvertTo-SecureString
    $cred = new-object -typename System.Management.Automation.PSCredential `
        -argumentlist $username, $password

    #check if the server is connectable
	if (test-Connection -Cn $args[1] -quiet)
	{
        #Create a temporary virtual drive to store the files to be moved
        Write-Host("\\$($ip)\c$\users\administrator\documents")
        New-PSDrive -Name Y -PSProvider filesystem -Root "\\$($ip)\c$\users\administrator\documents" -Credential $cred

        #Pass the requested script files to remote Sau server
        Copy-Item $source -Destination Y:\ -Recurse -ErrorAction SilentlyContinue -ErrorVariable A
        Copy-Item $screenshot -Destination Y:\ -Recurse -ErrorAction SilentlyContinue -ErrorVariable A
        if($A) { write-Output "$ip - File copy Failed"}
        
	}
	else {
        Write-Output "$($ip) is offline"
    }
    
    #Allow sau server credentials for passwordless logging
    Invoke-Command -ScriptBlock { cmdkey /generic:$ip /user:administrator /pass:Rel7.xPass! }
    # Start-Sleep(2)
    
    #Connect by RDP to Sau server
    mstsc -v $ip

    #Execute Sau.ps1 script on remote Sau server
    Files\PsExec.exe \\$($ip) -s -accepteula -i 2 -u administrator -p Rel7.xPass! cmd /c "powershell.exe C:\Users\Administrator\Documents\sau.ps1" #the command was "echo . | powershell.exe C:\Users\Administrator\Documents\sau.ps1"

    #Copy screenshots from Sau server to local computer
    $picArray = "Y:\diskpart.jpg", "Y:\system.jpg", "Y:\network.jpg" #Array with names of pictures files

    #Iterate through array
    foreach ($pic in $picArray) {
        
        #Copy screenshot from Sau server
        Copy-Item $pic -Destination  $validationURL -Recurse -ErrorAction SilentlyContinue -ErrorVariable A
        if($A) { write-Output "$ip - File copy Failed"}

        #Remove screenshot from Sau server
        Remove-Item $pic -ErrorAction SilentlyContinue -ErrorVariable A
        if($A) { write-Output "$ip - Screenshot deletion Failed"}
    }


    #Removing scripts from Remote Sau server
    Remove-Item Y:\sau.ps1 -ErrorAction SilentlyContinue -ErrorVariable A
    Remove-Item Y:\screenshot_func.ps1 -ErrorAction SilentlyContinue -ErrorVariable A
    if($A) { write-Output "$ip - Script removal Failed"}

    #Removing the temporary virtual drive
    Remove-PSDrive Y
    
    Write-Host("Validation was successful")
    
}

if ($args[0] -eq "3GI") {
    #Fetch arguments
    $ip = $args[1]
    $URL = $args[2]
    $name = $args[3]
    $source = ".\Remote Run\3GI\3GI.ps1"
    $screenshot = ".\Remote Run\3GI\screenshot_func.ps1"

    Write-Host("Execution will be performed on server: $ip")

    #Create encrypted password file
    read-host -prompt "Password" -assecurestring | convertfrom-securestring | out-file "Files\rel_pass.txt"

    #Create the credentials object
    $username = "hercules"
    $password = Get-Content 'Files\rel_pass.txt' | ConvertTo-SecureString
    $cred = new-object -typename System.Management.Automation.PSCredential `
        -argumentlist $username, $password

    #check if the server is connectable
	if (test-Connection -Cn $args[1] -quiet)
	{
        #Create a temporary virtual drive to store the files to be moved
        Write-Host("\\$($ip)\c$\users\administrator\documents")
        New-PSDrive -Name Y -PSProvider filesystem -Root "\\$($ip)\c$\users\administrator\documents" -Credential $cred

        #Pass the requested script files to remote Sau server
        Copy-Item $source -Destination Y:\ -Recurse -ErrorAction SilentlyContinue -ErrorVariable A
        Copy-Item $screenshot -Destination Y:\ -Recurse -ErrorAction SilentlyContinue -ErrorVariable A
        if($A) { write-Output "$ip - File copy Failed"}
        
	}
	else {
        Write-Output "$($ip) is offline"
    }
    
    #Allow sau server credentials for passwordless logging
    Invoke-Command -ScriptBlock { cmdkey /generic:$ip /user:hercules /pass:Rel7.xPass! }
    # Start-Sleep(2)
    
    #Connect by RDP to Sau server
    mstsc -v $ip
    
    #Execute Sau.ps1 script on remote Sau server
    Files\PsExec.exe \\$($ip) -s -accepteula -i 2 cmd /c "powershell.exe C:\Users\Administrator\Documents\3GI.ps1" #the command was "echo . | powershell.exe C:\Users\Administrator\Documents\sau.ps1"

    # Invoke-Expression "start '$ENV:USERPROFILE\Desktop\Scripts\Automated Validations\Remote Run\3GI\psexecExecute.cmd' '$($ip)'"

    #Copy screenshots from MPS1 server to local computer
    $pic = "Y:\wsus100.jpg"
        
    #Copy screenshot from MPS1 server
    Copy-Item $pic -Destination  $URL -Recurse -ErrorAction SilentlyContinue -ErrorVariable A
    if($A) { write-Output "$ip - File copy Failed"}

    #Remove screenshot from Sau server
    Remove-Item $pic -ErrorAction SilentlyContinue -ErrorVariable A
    if($A) { write-Output "$ip - Screenshot deletion Failed"}


    #Removing scripts from Remote Sau server
    Remove-Item Y:\3GI.ps1 -ErrorAction SilentlyContinue -ErrorVariable A
    Remove-Item Y:\screenshot_func.ps1 -ErrorAction SilentlyContinue -ErrorVariable A
    if($A) { write-Output "$ip - Script removal Failed"}

    #Removing the temporary virtual drive
    Remove-PSDrive Y
    
    Write-Host("Validation was successful")
}

if ($args[0] -eq "Stargate") {
    #Fetch arguments
    $ip = $args[1]
    $URL = $args[2]
    $name = $args[3]
    $source = ".\Remote Run\Stargate\StargateNoCluster.ps1"
    $screenshot = ".\Remote Run\Stargate\screenshot_func.ps1"
    $projectName = $args[4]

    Write-Host("Execution will be performed on server: $ip")

    #Create encrypted password file
    read-host -prompt "Password" -assecurestring | convertfrom-securestring | out-file "Files\rel_pass.txt"

    #Create the credentials object
    $username = "Hercules"
    $password = Get-Content 'Files\rel_pass.txt' | ConvertTo-SecureString
    $cred = new-object -typename System.Management.Automation.PSCredential `
        -argumentlist $username, $password

    #check if the server is connectable
	if (test-Connection -Cn $args[1] -quiet)
	{
        #Create a temporary virtual drive to store the files to be moved
        Write-Host("\\$($ip)\c$\users\administrator\documents")
        New-PSDrive -Name Y -PSProvider filesystem -Root "\\$($ip)\c$\users\administrator\documents" -Credential $cred

        #Pass the requested script files to remote Sau server
        Copy-Item $source -Destination Y:\ -Recurse -ErrorAction SilentlyContinue -ErrorVariable A
        Copy-Item $screenshot -Destination Y:\ -Recurse -ErrorAction SilentlyContinue -ErrorVariable A
        if($A) { write-Output "$ip - File copy Failed"}
        
	}
	else {
        Write-Output "$($ip) is offline"
    }
    
    #Allow sau server credentials for passwordless logging
    #Invoke-Command -ScriptBlock { cmdkey /delete:$ip }
    #Start-Sleep(1)
    Invoke-Command -ScriptBlock { cmdkey /generic:$ip /user:hercules /pass:Rel7.xPass! }
    # Start-Sleep(2)
    
    #Connect by RDP to MPS1 server
    mstsc -v $ip

    #Execute Stargate.ps1 script on remote Sau server
    Files\PsExec.exe \\$($ip) -s -accepteula -i 2 cmd /c "powershell.exe C:\Users\administrator\Documents\StargateNoCluster.ps1" #the command was "echo . | powershell.exe C:\Users\Administrator\Documents\sau.ps1"

    #Copy screenshots from MPS1 server to local computer
    $copyArray = "Y:\wsus100.jpg"#, "cluster_validation.htm"
        
    foreach($file in $copyArray) {

        #Copy files to destination
        Copy-Item $file -Destination $URL -Recurse -ErrorAction SilentlyContinue -ErrorVariable A
        if($A) { write-Output "$ip - File copy Failed"}

        #Remove screenshot from MPS1 server
        Remove-Item $file -ErrorAction SilentlyContinue -ErrorVariable A
        if($A) { write-Output "$ip - Screenshot deletion Failed"}

    }

    #Removing scripts from Remote MPS1 server
    Remove-Item Y:\StargateNoCluster.ps1 -ErrorAction SilentlyContinue -ErrorVariable A
    Remove-Item Y:\screenshot_func.ps1 -ErrorAction SilentlyContinue -ErrorVariable A
    if($A) { write-Output "$ip - Script removal Failed"}

    #Removing the temporary virtual drive
    Remove-PSDrive Y

    #Generate HVIM report
    .\Files\PsExec.exe \\127.0.0.1 -h "$env:USERPROFILE\Desktop\Scripts\Automated Validations\HVIM_v1.8.1\ValidationReport.bat"

    if (Test-Path 'HVIM_v1.8.1\Log\$($projectName)_HVIM\HVIMValidationReport.htm') {
        Copy-Item 'HVIM_v1.8.1\Log\$($projectName)_HVIM\HVIMValidationReport.htm' -Destination $URL -Recurse -ErrorAction SilentlyContinue -ErrorVariable A
        if($A) { write-Output "$ip - HVIM report copy Failed"}

        Remove-Item 'HVIM_v1.8.1\Log\$($projectName)_HVIM\HVIMValidationReport.htm' -ErrorAction SilentlyContinue -ErrorVariable A
        if($A) { write-Output "$ip - HVIM report deletion Failed"}
    }
    
    Write-Host("Validation was successful")
}

if ($args[0] -eq "Tbos") {
    #Fetch arguments
    $ip = $args[1]
    $URL = $args[2]
    $name = $args[3]

    Invoke-Expression "& `"$PSScriptRoot\Tbos\TBosValidation.ps1`" $ip '$URL\$name.txt'"
    Invoke-Expression "& `"$PSScriptRoot\Tbos\tbos_i40e.ps1`" $ip '$URL\$($name)_i40e.txt' '$URL\'"
}

if ($args[0] -eq "Workers") {
    #Fetch arguments
    $ip = $args[1]
    $URL = $args[2]
    $name = $args[3]

    Invoke-Expression "& `"$PSScriptRoot\Workers\WorkersValidation.ps1`" $ip '$URL\$name.txt'"
}

if ($args[0] -eq "MDE") {
    #Fetch arguments
    $ip = $args[1]
    $URL = $args[2]
    $name = $args[3]

    Invoke-Expression "& `"$PSScriptRoot\MDE\MDEValidation.ps1`" $ip '$URL\$name.txt'"
}

if ($args[0] -eq "Kafka") {
    #Fetch arguments
    $ip = $args[1]
    $URL = $args[2]
    $name = $args[3]

    Invoke-Expression "& `"$PSScriptRoot\Kafka\KafkaValidation.ps1`" $ip '$URL\$name.txt'"
}

if ($args[0] -eq "Presto") {
    #Fetch arguments
    $ip = $args[1]
    $URL = $args[2]
    $name = $args[3]

    Invoke-Expression "& `"$PSScriptRoot\Presto\PrestoValidation.ps1`" $ip '$URL\$name.txt'"
}