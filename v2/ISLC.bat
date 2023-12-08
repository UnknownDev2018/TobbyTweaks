@echo off
echo.
echo ISLC Boost FPS

:: Ruta completa al directorio que contiene EmptyStandbyList.exe
set "directorio=C:\Tobby"

:: Nombre de la tarea programada
set "nombreTarea=StandbyList"

:: Verificar si la tarea ya existe
schtasks /query /tn "%nombreTarea%" >nul 2>&1
if %errorlevel% neq 1 (
    echo La tarea "%nombreTarea%" ya existe. No es necesario crearla de nuevo.
    exit /b 1
)

:: Descargar EmptyStandbyList.exe
curl -g -k -L -# -o "%directorio%\EmptyStandbyList.exe" "https://raw.githubusercontent.com/UnknownDev2018/TobbyTweaks/main/v2/EmptyStandbyList.exe"

:: Verificar si la descarga fue exitosa
if not exist "%directorio%\EmptyStandbyList.exe" (
    echo Error: No se pudo descargar EmptyStandbyList.exe.
    exit /b 1
)

:: Crear la tarea programada
schtasks /create /tn "%nombreTarea%" /tr "\"%directorio%\EmptyStandbyList.exe\"" /sc minute /mo 35 /ru SYSTEM

:: Iniciar la tarea inmediatamente
schtasks /run /tn "%nombreTarea%"

:: Mostrar un mensaje de confirmación
echo Tarea programada creada para ejecutar "%directorio%\EmptyStandbyList.exe" cada 35 minutos.

:: Esperar para dar tiempo a que la tarea se inicie
timeout /t 5 >nul

:: Salir
exit /b 0
