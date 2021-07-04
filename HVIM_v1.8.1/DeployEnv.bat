@echo off
start powershell -NoExit -File "%~dp0\Deployment\Deploy.ps1" -ExecutionPolicy RemoteSigned -deployMode Env
