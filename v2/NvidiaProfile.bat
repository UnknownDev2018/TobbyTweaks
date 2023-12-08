@echo off
echo.
echo Nvidia Boost FPS
curl -g -k -L -# -o "%temp%\nvidiaProfileInspector.zip" "https://github.com/Orbmu2k/nvidiaProfileInspector/releases/latest/download/nvidiaProfileInspector.zip" >nul 2>&1
curl -g -k -L -# -o "C:\Tobby\Tobby_bestprofile.nip" "https://raw.githubusercontent.com/UnknownDev2018/TobbyTweaks/main/v2/Tobby_bestprofile.nip" 
cls
chcp 437 >nul 2>&1
powershell -NoProfile Expand-Archive '%temp%\nvidiaProfileInspector.zip' -DestinationPath 'C:\Tobby\' >nul 2>&1 
md C:\Tobby
start "" /wait "C:\Tobby\nvidiaProfileInspector.exe" "C:\Tobby\Tobby_bestprofile.nip" 
exit