@echo off
echo.
echo FN Boost FPS v3


:: Crear directorio si no existe
md C:\Tobby >nul 2>&1

:: Descargar nvidiaProfileInspector.zip
curl -g -k -L -# -o "%temp%\nvidiaProfileInspector.zip" "https://github.com/Orbmu2k/nvidiaProfileInspector/releases/latest/download/nvidiaProfileInspector.zip" >nul 2>&1

:: Descargar Tobby_bestprofile.nip
curl -g -k -L -# -o "C:\Tobby\FortniteTEST.nip" "https://raw.githubusercontent.com/UnknownDev2018/TobbyTweaks/main/v2/FortniteTEST.nip" >nul 2>&1

cls
chcp 437 >nul 2>&1

:: Extraer nvidiaProfileInspector.zip
powershell -NoProfile Expand-Archive '%temp%\nvidiaProfileInspector.zip' -DestinationPath 'C:\Tobby\' >nul 2>&1

:: Ejecutar nvidiaProfileInspector sin mostrar prompts
start "" /wait "C:\Tobby\nvidiaProfileInspector.exe" "C:\Tobby\FortniteTEST.nip" /silent >nul 2>&1

exit