@echo off
echo.
echo ISLC Boost FPS

echo Administrative permissions required. Please wait...
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :runScript
) else (
    echo This script must be run as Administrator.
    echo Please right-click and select "Run as Administrator".
    pause
    exit /B
)

:runScript
bcdedit /set useplatformtick yes
bcdedit /set disabledynamictick yes
bcdedit /set useplatformclock false
bcdedit /deletevalue useplatformclock

setlocal enabledelayedexpansion
:: Configura la clave del Registro para desactivar HPET
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HyperKitty\Services\ebdrv\Parameters" /v Start /t REG_DWORD /d 4 /f
reg add HKLM\System\CurrentControlSet\Services\TPM /v Start /t REG_DWORD /d 4 /f
reg add HKLM\System\CurrentControlSet\Services\WinRing0_1_2_0 /v Start /t REG_DWORD /d 4 /f

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f 
timeout /t 1 /nobreak > NUL

echo %w% - Setting Latency Tolerance%b%
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "Latency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "TransitionLatency" /t REG_DWORD /d "1" /f 

echo %w% - Setting NVIDIA Latency Tolerance%b%
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "D3PCLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "F1TransitionLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "LOWLATENCY" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Node3DLowLatency" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PciLatencyTimerControl" /t REG_DWORD /d "20" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMDeepL1EntryLatencyUsec" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMaxFtuS" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcMinFtuS" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmGspcPerioduS" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrEiIdleThresholdUs" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrIdleThresholdUs" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrGrRgIdleThresholdUs" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMLpwrMsIdleThresholdUs" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipDPCDelayUs" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectFlipTimingMarginUs" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "VRDirectJITFlipMsHybridFlipDelayUs" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrCursorMarginUs" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMarginUs" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "vrrDeflickerMaxUs" /t REG_DWORD /d "1" /f 
timeout /t 1 /nobreak > NUL

echo %w% - Disabling NVIDIA Telemetry%b%
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "NvBackend" /f 
Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d "0" /f 
schtasks /change /disable /tn "NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" 
schtasks /change /disable /tn "NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" 
schtasks /change /disable /tn "NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" 
schtasks /change /disable /tn "NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" 
schtasks /change /disable /tn "NvDriverUpdateCheckDaily_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" 
schtasks /change /disable /tn "NVIDIA GeForce Experience SelfUpdate_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" 
schtasks /change /disable /tn "NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" 
timeout /t 1 /nobreak > NUL

:: Ajusta la programación del procesador para asignar recursos del procesador a programas
:: 10D Hex = 269 Dec
Reg query "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" 2>nul | find "0x18" >nul && call :ControlSet "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" "Win32PrioritySeparation" "269"
Reg query "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" 2>nul | find "0x26" >nul && call :ControlSet "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" "Win32PrioritySeparation" "269"
echo W32PrioSep
::Disable GPU Isolation
reg add " KLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "IOMMUFlags" /t REG_DWORD /d 0 /f >nul
echo Disable GPU Isolation

::Enable GPU MSI Mode
for /f %%a in ('wmic path Win32_VideoController get PNPDeviceID ^| find "PCI\VEN_"') do ^
reg query "HKLM\System\CurrentControlSet\Enum\%%a\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" >nul 2>&1 && (
call :ControlSet "Enum\%%a\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" "MSISupported" "1"
echo Enable GPU MSI Mode
)

::Background Apps
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d "2" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f >nul
echo Disable Background Apps

::Enable Windowed Optimizations
call :DirectXSetting SwapEffectUpgradeEnable 1
Reg add HKCU\Software\Microsoft\DirectX\GraphicsSettings /v SwapEffectUpgradeCache /t REG_DWORD /d 1 /f >nul
echo Enable Windowed Optimizations
::Animations
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f >nul
Reg add "HKCU\Control Panel\Desktop" /f /v "UserPreferencesMask" /t REG_BINARY /d "9012078012000000" >nul
Reg add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "1" /f >nul
Reg add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "2" /f >nul
Reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\DWM" /v "AlwaysHibernateThumbnails" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\DWM" /v "ListviewShadow" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f >nul
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f >nul
echo Animations

::Quick Shutdown
rem Quickly kill apps during shutdown
Reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f >nul
rem Quickly end services at shutdown
Reg add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f >nul
rem Kill apps at shutdown
Reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f >nul
echo Quick Shutdown

::Quickly kill non-responsive apps
Reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f >nul
::Quickly show menus
Reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "20" /f >nul
echo Speed-up Windows

::Harden Windows
rem Disable SMBv1 and SMBv2 as it's outdated and vulnerable to exploitation.
Reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB2" /t REG_DWORD /d "0" /f >nul
rem Block Anonymous Enumeration of SAM Accounts
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220929
Reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymous" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d "1" /f >nul
rem Disable NetBios, can be exploited and is highly vulnerable.
call :ControlSet "Services\NetBT\Parameters\Interfaces" "NetbiosOptions" "2"
rem If NetBios manages to become enabled, protect against NBT-NS poisoning attacks
call :ControlSet "Services\NetBT\Parameters" "NodeType" "2"
rem Disable LanmanWorkstation
rem https://cyware.com/news/what-is-smb-vulnerability-and-how-it-was-exploited-to-launch-the-wannacry-ransomware-attack-c5a97c48
sc stop LanmanWorkstation >nul 2>&1
sc config LanmanWorkstation start=disabled >nul 2>&1
rem If LanmanWorkstation manages to become enabled, protect against other attacks
rem https://www.stigviewer.com/stig/windows_10/2021-03-10/finding/V-220932
Reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v "RestrictNullSessAccess" /t REG_DWORD /d "1" /f >nul
rem Disable SMB Compression (Possible SMBGhost Vulnerability workaround)
Reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v "DisableCompression" /t REG_DWORD /d "1" /f >nul
rem Harden lsass
Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe" /v "AuditLevel" /t REG_DWORD /d "8" /f >nul
Reg add "HKLM\Software\Policies\Microsoft\Windows\CredentialsDelegation" /v "AllowProtectedCreds" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DisableRestrictedAdminOutboundCreds" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DisableRestrictedAdmin" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RunAsPPL" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v "Negotiate" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v "UseLogonCredential" /t REG_DWORD /d "0" /f >nul
rem Delete defaultuser0
net user defaultuser0 /delete >nul 2>&1
rem Disable Remote Assistance
Reg add "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f >nul
rem Set Strong Cryptography
Reg add "HKLM\Software\Microsoft\.NetFramework\v4.0.30319" /v "SchUseStrongCrypto" /t REG_DWORD /d "1" /f >nul
Reg add "HKLM\Software\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" /v "SchUseStrongCrypto" /t REG_DWORD /d "1" /f >nul
rem Mitigate CVE-2022-30190
Reg delete HKEY_CLASSES_ROOT\ms-msdt /f >nul 2>&1
echo Harden Windows

::Enable xAPIC on Windows Servers
Reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v "InstallationType" 2>nul | find /I "Server Core" >nul && (
bcdedit /set x2apicpolicy enable >nul
bcdedit /set uselegacyapicmode no >nul
echo Enable xAPIC
)

::SvcSplitThreshold
for /f "tokens=2 delims==" %%n in ('wmic os get TotalVisibleMemorySize /format:value') do set mem=%%n
call :ControlSet "Control" "SvcHostSplitThresholdInKB" "%mem%"
echo SvcSplitThreshold

::IOPageLockLimit
Reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "IOPageLockLimit" /t REG_DWORD /d "%mem%" /f >nul
echo IOPageLockLimit

::Increase Decommitting Memory Threshold
Reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "HeapDeCommitFreeBlockThreshold" /t REG_DWORD /d "262144" /f >nul
echo Increase Decommitting Memory Threshold

::Enable PAE
bcdedit /set pae ForceEnable >nul
echo Enable PAE

::Enable Weak Host Model
for /f "tokens=1" %%a in ('netsh interface ip show interface ^| findstr /I "connected"') do (
netsh interface ipv6 set interface %%a weakhostreceive=enabled weakhostsend=enabled
netsh interface ipv4 set interface %%a weakhostreceive=enabled weakhostsend=enabled
) >nul
echo Enable Weak Host Model

::Disable Delivery Optimization
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f >nul
echo Disable Delivery Optimization

::Set Congestion Provider To BBR2
netsh int tcp set global ecncapability=enabled >nul
for /f "tokens=7" %%a in ('netsh int tcp show supplemental ^| findstr /I "template"') do netsh int tcp set supplemental %%a CongestionProvider=bbr2 >nul
echo Set Congestion Provider To BBR2

::Disable Nagle's Algorithm
Reg add "HKLM\Software\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f >nul 2>&1  
for /f "tokens=3*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s ^|findstr /i /l "ServiceName"') do (
	Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
	Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
	Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
) >nul 2>&1
echo Disable Nagle's Algorithm

::Enable Winsock Autotuning
netsh winsock set autotuning on >nul
echo Enable Winsock Autotuning

::NIC
mkdir "%SYSTEMDRIVE%\Backup" 2>nul
for /f "tokens=2 delims==" %%n in ('wmic cpu get numberOfCores /format:value') do set CORES=%%n
for /f "tokens=3*" %%a in ('Reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\NetworkCards" /k /v /f "Description" /s /e ^| findstr /ri "REG_SZ"') do (
for /f %%g in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" /s /f "%%b" /d ^| findstr /C:"HKEY"') do (
if not exist "%SYSTEMDRIVE%\Backup\(Default) %%b.reg" Reg export "%%g" "%SYSTEMDRIVE%\Backup\(Default) %%b.reg" /y
::Disable Wake Features
Reg add "%%g" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f
Reg add "%%g" /v "*WakeOnPattern" /t REG_SZ /d "0" /f
Reg add "%%g" /v "WakeOnLink" /t REG_SZ /d "0" /f
Reg add "%%g" /v "S5WakeOnLan" /t REG_SZ /d "0" /f
Reg add "%%g" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f
Reg add "%%g" /v "*ModernStandbyWoLMagicPacket	" /t REG_SZ /d "0" /f
Reg add "%%g" /v "*DeviceSleepOnDisconnect" /t REG_SZ /d "0" /f
::Disable Power Saving Features
Reg add "%%g" /v "*NicAutoPowerSaver" /t REG_SZ /d "0" /f
Reg add "%%g" /v "*FlowControl" /t REG_SZ /d "0" /f
Reg add "%%g" /v "*EEE" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnablePME" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f
Reg add "%%g" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f
Reg add "%%g" /v "PowerSavingMode" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f
Reg add "%%g" /v "ULPMode" /t REG_SZ /d "0" /f
Reg add "%%g" /v "GigaLite" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnableSavePowerNow" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnablePowerManagement" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnableDynamicPowerGating" /t REG_SZ /d "0" /f
Reg add "%%g" /v "EnableConnectedPowerGating" /t REG_SZ /d "0" /f
Reg add "%%g" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f
Reg add "%%g" /v "AutoDisableGigabit" /t REG_SZ /d "0" /f
Reg add "%%g" /v "AdvancedEEE" /t REG_SZ /d "0" /f
Reg add "%%g" /v "PowerDownPll" /t REG_SZ /d "0" /f
Reg add "%%g" /v "S5NicKeepOverrideMacAddrV2" /t REG_SZ /d "0" /f
Reg add "%%g" /v "MIMOPowerSaveMode" /t REG_SZ /d "3" /f
Reg add "%%g" /v "AlternateSemaphoreDelay" /t REG_SZ /d "0" /f
::Disable Interrupt Moderation
Reg add "%%g" /v "*interruptmoderation" /t REG_SZ /d "0" /f
::Disable JumboPacket
Reg add "%%g" /v "JumboPacket" /t REG_SZ /d "0" /f
::Interrupt Moderation Adaptive (Default)
Reg add "%%g" /v "ITR" /t REG_SZ /d "125" /f
::Receive/Transmit Buffers
Reg delete "%%g" /v "ReceiveBuffers" /f
Reg delete "%%g" /v "TransmitBuffers" /f
::Enable Throughput Booster
Reg add "%%g" /v "ThroughputBoosterEnabled" /t REG_SZ /d "1" /f
::PnPCapabilities
Reg add "%%g" /v "PnPCapabilities" /t REG_DWORD /d "24" /f
::Enable LargeSendOffloads
Reg add "%%g" /v "LsoV1IPv4" /t REG_SZ /d "1" /f
Reg add "%%g" /v "LsoV2IPv4" /t REG_SZ /d "1" /f
Reg add "%%g" /v "LsoV2IPv6" /t REG_SZ /d "1" /f
::Enable Offloads
Reg add "%%g" /v "TCPUDPChecksumOffloadIPv4" /t REG_SZ /d "3" /f
Reg add "%%g" /v "TCPUDPChecksumOffloadIPv6" /t REG_SZ /d "3" /f
Reg add "%%g" /v "UDPChecksumOffloadIPv4" /t REG_SZ /d "3" /f
Reg add "%%g" /v "UDPChecksumOffloadIPv6" /t REG_SZ /d "3" /f
Reg add "%%g" /v "TCPChecksumOffloadIPv4" /t REG_SZ /d "3" /f
Reg add "%%g" /v "TCPChecksumOffloadIPv6" /t REG_SZ /d "3" /f
Reg add "%%g" /v "IPChecksumOffloadIPv4" /t REG_SZ /d "3" /f
Reg add "%%g" /v "IPsecOffloadV1IPv4" /t REG_SZ /d "3" /f
Reg add "%%g" /v "IPsecOffloadV2" /t REG_SZ /d "3" /f
Reg add "%%g" /v "*IPsecOffloadV2IPv4" /t REG_SZ /d "3" /f
Reg add "%%g" /v "*PMARPOffload" /t REG_SZ /d "1" /f
Reg add "%%g" /v "*PMNSOffload" /t REG_SZ /d "1" /f
Reg add "%%g" /v "*PMWiFiRekeyOffload" /t REG_SZ /d "1" /f
::RSS
Reg add "%%g" /v "RSS" /t REG_SZ /d "1" /f
Reg add "%%g" /v "*NumRssQueues" /t REG_SZ /d "2" /f
if %CORES% geq 6 (
Reg add "%%g" /v "*RssBaseProcNumber" /t REG_SZ /d "4" /f
Reg add "%%g" /v "*RssMaxProcNumber" /t REG_SZ /d "5" /f
) else if %CORES% geq 4 (
Reg add "%%g" /v "*RssBaseProcNumber" /t REG_SZ /d "2" /f
Reg add "%%g" /v "*RssMaxProcNumber" /t REG_SZ /d "3" /f
) else (
Reg delete "%%g" /v "*RssBaseProcNumber" /f
Reg delete "%%g" /v "*RssMaxProcNumber" /f
)
) >nul 2>&1
)
echo Configure NIC

::Enable RSS
netsh int tcp set global rss=enabled >nul
echo Enable RSS

::Max Port Ranges
netsh int ipv4 set dynamicport udp start=1025 num=64511 >nul
netsh int ipv4 set dynamicport tcp start=1025 num=64511 >nul
echo Max Port Ranges

::Enable Network Task Offloading
Netsh int ip set global taskoffload=enabled >nul 2>&1
Reg add HKLM\System\CurrentControlSet\Services\TCPIP\Parameters /v DisableTaskOffload /t REG_DWORD /d 0 /f >nul
Reg add HKLM\System\CurrentControlSet\Services\Ipsec /v EnabledOffload /t REG_DWORD /d 1 /f >nul
echo Enable Network Task Offloading


::Disable Hibernation
call :ControlSet "Control\Power" "HibernateEnabled" "0"
powercfg /h off >nul
echo Disable Hibernation

::Opt out of nvidia telemetry
call :ControlSet "Services\NvTelemetryContainer" "Start" "4"
sc stop NvTelemetyContainer >nul
sc config NvTelemetyContainer start=disabled >nul
if exist "%systmedrive%\Program Files\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL" (rundll32 "%systmedrive%\Program Files\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetryContainer)
Reg add "HKLM\Software\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d 0 /f >nul
Reg add "HKLM\System\CurrentControlSet\Services\nvlddmkm\Global\Startup" /v "SendTelemetryData" /t REG_DWORD /d "0" /f >nul
Reg add "HKLM\Software\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d 0 /f >nul
Reg add "HKLM\Software\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d 0 /f >nul
Reg add "HKLM\Software\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d 0 /f >nul
Reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "NvBackend" /f >nul 2>&1
schtasks /change /disable /tn "NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
schtasks /change /disable /tn "NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
schtasks /change /disable /tn "NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
schtasks /change /disable /tn "NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" >nul 2>&1
echo Disable Nvidia Telemetry


::Disable HDCP
for /f %%a in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" ^| findstr "HKEY"') do ^
if exist "C:\Program Files (x86)\Steam\steamapps\common\SteamVR" (
call :DelControlSet "%%a" "RMHdcpKeyglobZero"
echo Enable HDCP
) else if exist "C:/Program Files/Oculus/Software" (
call :DelControlSet "%%a" "RMHdcpKeyglobZero"
echo Enable HDCP
) else (
call :ControlSet "%%a" "RMHdcpKeyglobZero" "1"
echo Disable HDCP
)

::NVCP Settings
if "%GPU%" equ "NVIDIA" (
::GSync: Fullscreen And Windowed
call :NVCP "278196727" "2"
call :NVCP "294973784" "2"
echo Enable GSync for Fullscreen and Windowed Mode

::Enable Low Latency Mode
call :NVCP "390467" "1"
call :NVCP "277041152" "1"
echo Enable Low Latency Mode

::Texture Filtering Quality: Performance
call :NVCP "13510289" "10"
echo Set Texture Filtering Quality to Performance

::Enable ReBar
call :NVCP "983226" "1"
call :NVCP "983227" "1"
call :NVCP "983295" "AAAAQAAAAAA=" "Binary"
echo Enable ReBar

::Disable Ansel
call :NVCP "271965065" "0"
call :NVCP "276158834" "0"
echo Disable Ansel
)

::Disable HPET (Stock)
bcdedit /deletevalue useplatformclock >nul
echo Disable HPET

::Disable Synthetic Timers
bcdedit /set useplatformtick yes >nul
echo Disable Synthetic Timers

Reg query HKCU\Software\CoutX /v DisableDeviceThrottling 2>nul | find "0x1" >nul && (

	::Disable NVMe Power Saving
	rem NVMe Power State Transition Latency Tolerance: 0
	powercfg -setacvalueindex scheme_current SUB_DISK dbc9e238-6de9-49e3-92cd-8c2b4946b472 0 >nul
	powercfg -setacvalueindex scheme_current SUB_DISK fc95af4d-40e7-4b6d-835a-56d131dbc80e 0 >nul
	rem Disable NVMe Idle Timeout
	powercfg /setacvalueindex scheme_current SUB_DISK d3d55efd-c1ff-424e-9dc3-441be7833010 0 >nul
	powercfg /setacvalueindex scheme_current SUB_DISK d639518a-e56d-4345-8af2-b9f32fb26109 0 >nul
	rem NVME NOPPME: ON
	powercfg /setacvalueindex scheme_current SUB_DISK DISKNVMENOPPME 1 >nul
	echo Disable NVMe Power Saving
	
	::Disable USB Power Savings
	for /f "tokens=*" %%a in ('Reg query "HKLM\System\CurrentControlSet\Enum" /s /f "StorPort" 2^>nul ^| findstr "StorPort"') do call :ControlSet "%%a" "EnableIdlePowerManagement" "0"
	for /f %%a in ('wmic PATH Win32_PnPEntity GET DeviceID ^| find "USB\VID_"') do (
	call :ControlSet "Enum\%%a\Device Parameters" "EnhancedPowerManagementEnabled" "0"
	call :ControlSet "Enum\%%a\Device Parameters" "AllowIdleIrpInD3" "0"
	call :ControlSet "Enum\%%a\Device Parameters" "EnableSelectiveSuspend" "0"
	call :ControlSet "Enum\%%a\Device Parameters" "DeviceSelectiveSuspended" "0"
	call :ControlSet "Enum\%%a\Device Parameters" "SelectiveSuspendEnabled" "0"
	call :ControlSet "Enum\%%a\Device Parameters" "SelectiveSuspendOn" "0"
	call :ControlSet "Enum\%%a\Device Parameters" "D3ColdSupported" "0"
	)
	echo Disable USB Power Savings
	
	::Disable Selective USB Suspension
	powercfg -setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 0 >nul
	powercfg -setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 >nul
	powercfg -setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 0853a681-27c8-4100-a2fd-82013e970683 0 >nul
	echo Disable Selective USB Suspension
	
	::Disable Link State Power Management
	powercfg -setacvalueindex scheme_current SUB_PCIEXPRESS ASPM 0 >nul
	rem Disable AHCI Link Power Management
	powercfg -setacvalueindex scheme_current SUB_DISK 0b2d69d7-a2a1-449c-9680-f91c70521c60 0 >nul
	powercfg -setacvalueindex scheme_current SUB_DISK dab60367-53fe-4fbc-825e-521d069d2456 0 >nul
	echo Disable Link State Power Management

	::Disable Storage Device Idle
	Reg add "HKLM\System\CurrentControlSet\Services\stornvme\Parameters\Device" /v "IdlePowerMode" /t REG_DWORD /d "0" /f >nul
	echo Disable Storage Device Idle
	
	::Apply Power Plan Changes
	powercfg -setactive scheme_current >nul
	
	 Reg add HKCU\Software\CoutX /v DisableDeviceThrottlingRan /t REG_DWORD /d 1 /f >nul
) || Reg query HKCU\Software\CoutX /v DisableDeviceThrottlingRan 2>nul | find "0x1" >nul && (

	::Reset USB Power Savings
	for /f "tokens=*" %%a in ('Reg query "HKLM\System\CurrentControlSet\Enum" /s /f "StorPort" 2^>nul ^| findstr "StorPort"') do call :ControlSet "%%a" "EnableIdlePowerManagement" "0"
	for /f %%a in ('wmic PATH Win32_PnPEntity GET DeviceID ^| find "USB\VID_"') do (
	call :DelControlSet "Enum\%%a\Device Parameters" "EnhancedPowerManagementEnabled"
	call :DelControlSet "Enum\%%a\Device Parameters" "AllowIdleIrpInD3"
	call :DelControlSet "Enum\%%a\Device Parameters" "EnableSelectiveSuspend"
	call :DelControlSet "Enum\%%a\Device Parameters" "DeviceSelectiveSuspended"
	call :DelControlSet "Enum\%%a\Device Parameters" "SelectiveSuspendEnabled"
	call :DelControlSet "Enum\%%a\Device Parameters" "SelectiveSuspendOn"
	call :DelControlSet "Enum\%%a\Device Parameters" "D3ColdSupported"
	)
	echo Disable USB Power Savings
	
	::Reset Storage Device Idle
	Reg delete "HKLM\System\CurrentControlSet\Services\stornvme\Parameters\Device" /v "IdlePowerMode" /f >nul
	echo Disable Storage Device Idle

	 Reg delete HKCU\Software\CoutX /v DisableDeviceThrottlingRan /f >nul
)

::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::
::::Disable GPU Power Throttling::::
::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::

Reg query HKCU\Software\CoutX /v DisableGPUThrottling 2>nul | find "0x1" >nul && (
	if "%GPU%" equ "NVIDIA" (
		::Disable Forced P2 State
		call :NVCP "1343646814" "0"
		echo Disable Forced P2 State
		::Prefer Maximum Performance
		call :NVCP "274197361" "1"
		echo Prefer Maximum Performance
	)

	::Disable GpuEnergyDrv
	call :ControlSet "Services\GpuEnergyDrv" "Start" "4"
	echo Disable GpuEnergyDrv
	::Grab Nvidia Graphics Card Registry Key
	for /f %%a in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" ^| findstr "HKEY"') do (
	::Disable Dynamic PStates
	reg query "%%a" /v "DisableDynamicPState" >nul 2>&1 && (
	Call :ControlSet "%%a" "DisableDynamicPState" "1"
	echo Disable Dynamic PStates
	)
	::Enable KBoost
	Call :ControlSet "%%a" "PowerMizerEnable" "1"
	Call :ControlSet "%%a" "PowerMizerLevel" "1"
	Call :ControlSet "%%a" "PowerMizerLevelAC" "1"
	Call :ControlSet "%%a" "PerfLevelSrc" "8755"
	echo Enable KBoost
	::Disable Overheat Slowdown
	Call :ControlSet "%%a" "EnableCoreSlowdown" "0"
	Call :ControlSet "%%a" "EnableMClkSlowdown" "0"
	Call :ControlSet "%%a" "EnableNVClkSlowdown" "0"
	echo Disable Overheat Slowdown
	)

	::Grab iGPU Registry Key
	for /f %%i in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "Intel" ^| findstr "HKEY"') do (
	::Disable iGPU CStates
	reg query "%%i" /v "AllowDeepCStates" >nul 2>&1 && (
	Call :ControlSet "%%i" "AllowDeepCStates" "0"
	echo Disable iGPU CStates
	)
	::Intel iGPU Settings
	Call :ControlSet "%%i" "Disable_OverlayDSQualityEnhancement" "1"
	Call :ControlSet "%%i" "IncreaseFixedSegment" "1"
	Call :ControlSet "%%i" "AdaptiveVsyncEnable" "0"
	Call :ControlSet "%%i" "DisablePFonDP" "1"
	Call :ControlSet "%%i" "EnableCompensationForDVI" "1"
	Call :ControlSet "%%i" "NoFastLinkTrainingForeDP" "0"
	Call :ControlSet "%%i" "ACPowerPolicyVersion" "16898"
	Call :ControlSet "%%i" "DCPowerPolicyVersion" "16642"
	echo Intel iGPU Settings
	)
	
	 Reg add HKCU\Software\CoutX /v DisableGPUThrottlingRan /t REG_DWORD /d 1 /f >nul
) || Reg query HKCU\Software\CoutX /v DisableGPUThrottlingRan 2>nul | find "0x1" >nul && (
	::Prefer Optimal Performance
	call :NVCP "274197361" "5"
	echo Reset NVCP Settings
	
	::Enable GpuEnergyDrv
	call :ControlSet "Services\GpuEnergyDrv" "Start" "2"
	echo Enable GpuEnergyDrv

	for /f %%a in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" ^| findstr "HKEY"') do (
	reg query "%%a" /v "DisableDynamicPState" >nul 2>&1 && (
	Call :ControlSet "%%a" "DisableDynamicPState" "0"
	echo Enable Dynamic PStates
	)
	Call :DelControlSet "%%a" "PowerMizerEnable"
	Call :DelControlSet "%%a" "PowerMizerLevel"
	Call :DelControlSet "%%a" "PowerMizerLevelAC"
	Call :DelControlSet "%%a" "PerfLevelSrc"
	echo Disable KBoost
	Call :DelControlSet "%%a" "EnableCoreSlowdown"
	Call :DelControlSet "%%a" "EnableMClkSlowdown"
	Call :DelControlSet "%%a" "EnableNVClkSlowdown"
	echo Enable Overheat Slowdown
	)
	
	::Grab iGPU Registry Key
	for /f %%i in ('Reg query "HKLM\System\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "Intel" ^| findstr "HKEY"') do (
	::Reset iGPU CStates
	reg query "%%i" /v "AllowDeepCStates" >nul 2>&1 && (
	Call :ControlSet "%%i" "AllowDeepCStates" "1"
	echo Enable iGPU CStates
	)
	)
	Reg delete HKCU\Software\CoutX /v DisableGPUThrottlingRan /f >nul
)

::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::
::::Disable CPU Power Throttling::::
::::::::::::::::::::::::::::::::::::
::::::::::::::::::::::::::::::::::::

::QoS Packet Scheduler
>"%tmp%\tmp.vbs" echo a = msgbox("CoutX detected that the QoS Packet Scheduler has been disabled. Would you like to re-enable it?",vbYesNo+vbQuestion + vbSystemModal,"CoutX")
>>"%tmp%\tmp.vbs" echo if a = 6 then
>>"%tmp%\tmp.vbs" echo CreateObject("WScript.Shell").Run "Reg add HKLM\System\CurrentControlSet\Services\Psched /v Start /t REG_DWORD /d 2 /f", 0, True
>>"%tmp%\tmp.vbs" echo CreateObject("WScript.Shell").Run "sc config Psched start=auto", 0, True
>>"%tmp%\tmp.vbs" echo CreateObject("WScript.Shell").Run "sc start Psched", 0, True
>>"%tmp%\tmp.vbs" echo end if

Reg query HKCU\Software\CoutX /v DisableCPUThrottling 2>nul | find "0x1" >nul && (
	::Configure C-States
	powercfg -setacvalueindex scheme_current sub_processor IDLEPROMOTE 100 >nul
	powercfg -setacvalueindex scheme_current sub_processor IDLEDEMOTE 100 >nul
	powercfg -setacvalueindex scheme_current sub_processor IDLECHECK 100000 >nul
	powercfg -setacvalueindex scheme_current sub_processor IDLESCALING 0 >nul
	::Apply Changes
	powercfg -setactive scheme_current >nul
	echo Configure C-States
	
	::Disable Dynamic Tick
	bcdedit /set disabledynamictick yes >nul
	echo Disable Dynamic Tick

	::Timer Resolution
	Call :ControlSet "Control\Session Manager\kernel" "GlobalTimerResolutionRequests" "1"
	taskkill /f /im SetTimerResolution.exe >nul 2>&1
	Copy /Y SetTimerResolution.exe %systemdrive%\SetTimerResolution.exe >nul 2>&1
	%systemdrive%\SetTimerResolution.exe -Install >nul 2>&1
	net start STR >nul 2>&1
	echo Timer Resolution
	
	::Set QoS TimerResolution
	sc query Psched | find "STOPPED" >nul && start "CoutX" wscript "%tmp%\tmp.vbs"
	::Enable QoS Policy outside domain networks
	Reg add "HKLM\System\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_DWORD /d "1" /f >nul 2>&1
	::QoS Timer Resolution
	Reg add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "1" /f >nul 2>&1
	echo QoS TimerResolution
	
	::Disable The Processor Power Management Driver
	call :ControlSet "Services\IntelPPM" "Start" "4"
	call :ControlSet "Services\AmdPPM" "Start" "4"
	echo Disable The Processor Power Management Driver
	
	 Reg add HKCU\Software\CoutX /v DisableCPUThrottlingRan /t REG_DWORD /d 1 /f >nul
) || Reg query HKCU\Software\CoutX /v DisableCPUThrottlingRan 2>nul | find "0x1" >nul && (
	::Reset Dynamic Tick
	bcdedit /deletevalue disabledynamictick >nul
	echo Reset Dynamic Tick

	::Timer Resolution
	net stop STR >nul 2>&1
	%systemdrive%\SetTimerResolution.exe -Uninstall >nul 2>&1
	del /f "%systemdrive%\SetTimerResolution.exe" 2>nul
	echo Reset Timer Resolution
	
	::QoS Timer Resolution
	Reg delete "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /f >nul 2>&1
	::Reset QoS Timer Resolution
	Reg delete "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /f >nul 2>&1
	echo Reset QoS TimerResolution

	::Enable The Processor Power Management Driver
	call :ControlSet "Services\IntelPPM" "Start" "2"
	call :ControlSet "Services\AmdPPM" "Start" "2"
	echo Enable The Processor Power Management Driver

	Reg delete HKCU\Software\CoutX /v DisableCPUThrottlingRan /f >nul
)

::Flush DNS
ipconfig /flushdns >nul
::Restart Explorer
(taskkill /f /im explorer.exe && start explorer.exe) >nul
::End
taskkill /f /im regedit.exe >nul 2>&1
taskkill /f /im MinSudo.exe >nul 2>&1
taskkill /f /im fsutil.exe >nul 2>&1
exit 0

timeout /t 5 >nul

:: Salir
exit /b 0
