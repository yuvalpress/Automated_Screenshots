$personalModules = Join-Path -Path ([Environment]::GetFolderPath('MyDocuments')) -ChildPath WindowsPowerShell\Modules

if (($env:PSModulePath -split ';') -notcontains $personalModules) {
	Write-Warning "$personalModules is not in `$env:PSModulePath"
}

$InstallDirectory = Join-Path -Path $personalModules -ChildPath Posh-SSH
if (!(Test-Path $InstallDirectory)) {
    $null = mkdir $InstallDirectory
}

Copy-Item -Recurse -Path $currentExecutingPath\Posh-SSH\* -Destination $installDirectory

