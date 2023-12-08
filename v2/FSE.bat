@echo off
echo Disable GameDVR
::Enable Detailed BSOD
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "DisplayParameters" /t REG_DWORD /d "1" /f >nul 2>&1
echo Enable Detailed BSOD

::Remove Potential GameDVR and FSO Overrides
Reg delete "HKLM\System\CurrentControlSet\Control\Session Manager\Environment" /v "__COMPAT_LAYER" /f >nul 2>&1
Reg delete "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /f >nul 2>&1
Reg delete "HKCU\System\GameConfigStore" /v "GameDVR_DSEBehavior" /f >nul 2>&1
Reg delete "HKLM\System\GameConfigStore" /f >nul 2>&1
Reg delete "HKU\.Default\System\GameConfigStore" /f >nul 2>&1
Reg delete "HKU\S-1-5-19\System\GameConfigStore" /f >nul 2>&1
Reg delete "HKU\S-1-5-20\System\GameConfigStore" /f >nul 2>&1
Reg delete "HKCU\Software\Classes\System\GameConfigStore" /f >nul 2>&1

::Disable GameDVR
Reg add HKCU\System\GameConfigStore /v GameDVR_Enabled /t REG_DWORD /d 0 /f >nul
Reg add HKCU\Software\Policies\Microsoft\Windows\GameDVR /v AllowGameDVR /t REG_DWORD /d 0 /f >nul
Reg add HKLM\Software\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR /v value /t REG_DWORD /d 0 /f >nul
::Disable GameDVR Capture
Reg add HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR /v AppCaptureEnabled /t REG_DWORD /d 0 /f >nul
Reg add HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR /v AudioCaptureEnabled /t REG_DWORD /d 0 /f >nul
Reg add HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR /v CursorCaptureEnabled /t REG_DWORD /d 0 /f >nul
Reg add HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR /v MicrophoneCaptureEnabled /t REG_DWORD /d 0 /f >nul
Reg add HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR /v HistoricalCaptureEnabled /t REG_DWORD /d 0 /f >nul
::Disable Game Bar Shortcuts
Reg add HKCU\Software\Microsoft\GameBar /v UseNexusForGameBarEnabled /t REG_DWORD /d 0 /f >nul
Reg add HKCU\Software\Microsoft\GameBar /v GamepadDoublePressIntervalMs /t REG_DWORD /d 0 /f >nul
Reg add HKCU\Software\Microsoft\GameBar /v ShowStartupPanel /t REG_DWORD /d 0 /f >nul
Reg add HKCU\Software\Microsoft\GameBar /v GamePanelStartupTipIndex /t REG_DWORD /d 0 /f >nul
::Disable Game Bar Presence Writer
Reg add "HKLM\Software\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /v "ActivationType" /t REG_DWORD /d "0" /f >nul 2>&1
echo Disable GameDVR

::Enable GameDVR FSO
Reg add HKCU\System\GameConfigStore /v GameDVR_FSEBehaviorMode /t REG_DWORD /d 2 /f >nul
Reg add HKCU\System\GameConfigStore /v GameDVR_EFSEFeatureFlags /t REG_DWORD /d 0 /f >nul
Reg add HKCU\System\GameConfigStore /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 0 /f >nul
Reg add HKCU\System\GameConfigStore /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 1 /f >nul
echo Enable GameDVR FSO

::Enable Windows VRR
call :DirectXSetting VRROptimizeEnable 1
echo Enable Windows VRR

::Enable Windowed Optimizations
call :DirectXSetting SwapEffectUpgradeEnable 1
Reg add HKCU\Software\Microsoft\DirectX\GraphicsSettings /v SwapEffectUpgradeCache /t REG_DWORD /d 1 /f >nul
echo Enable Windowed Optimizations
exit