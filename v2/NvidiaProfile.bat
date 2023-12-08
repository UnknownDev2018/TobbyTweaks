@echo off
echo.
echo Nvidia Boost FPS v3

:: Create directory if it doesn't exist
md C:\Tobby

:: Download nvidiaProfileInspector.zip
powershell -command "& {Invoke-WebRequest -Uri 'https://github.com/Orbmu2k/nvidiaProfileInspector/releases/latest/download/nvidiaProfileInspector.zip' -OutFile '%temp%\nvidiaProfileInspector.zip'}" >nul 2>&1

:: Download Tobby_bestprofile.nip
powershell -command "& {Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/UnknownDev2018/TobbyTweaks/main/v2/Tobby_bestprofile.nip' -OutFile 'C:\Tobby\Tobby_bestprofile.nip'}"

cls
chcp 437 >nul 2>&1

:: Extract nvidiaProfileInspector.zip
powershell -NoProfile Expand-Archive -Path '%temp%\nvidiaProfileInspector.zip' -DestinationPath 'C:\Tobby\' >nul 2>&1

:: Run nvidiaProfileInspector without prompts
start "" /wait "C:\Tobby\nvidiaProfileInspector.exe" "C:\Tobby\Tobby_bestprofile.nip" /silent

exit
