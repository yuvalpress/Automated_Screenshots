@echo off
start powershell -NoExit -File "%~dp0\Deployment\ClearEnvironment.ps1" -ExecutionPolicy RemoteSigned

