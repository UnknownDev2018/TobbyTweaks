@echo off
Echo Installing Timer Resolution Service
echo.
powershell Invoke-WebRequest "https://raw.githubusercontent.com/UnknownDev2018/TobbyTweaks/main/v2/SetTimerResolutionService.exe" -OutFile "C:\Windows\SetTimerResolutionService.exe"
"C:\Windows\SetTimerResolutionService.exe" -install
sc start STR
exit
