@echo off
Echo Installing PowerPlan
echo.

::Disable HPET (Stock)
bcdedit /deletevalue useplatformclock >nul
echo Disable HPET

::Disable Synthetic Timers
bcdedit /set useplatformtick yes >nul
echo Disable Synthetic Timers

::Set power policy to Minimal Power Management
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f >nul
::Restore Power Settings
call :ControlSet "System\Services\NetBT\Parameters" "CsEnabled" "0"
call :ControlSet "System\Services\NetBT\Parameters" "PlatformAoAcOverride" "0"
::Import Ultimate Performance Power Plan
powercfg /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb >nul 2>&1
powercfg /setactive bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb >nul
powercfg /delete eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee >nul 2>&1
powercfg /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee >nul 2>&1
powercfg /setactive eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee >nul
powercfg /delete bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb >nul
::Disable Throttle States
powercfg -setacvalueindex scheme_current sub_processor THROTTLING 0 >nul
::Device Idle Policy: Performance
powercfg -setacvalueindex scheme_current sub_none DEVICEIDLE 0 >nul
::Interrupt Steering: Processor 1
echo %PROCESSOR_IDENTIFIER% | find /I "Intel" >nul && powercfg -setacvalueindex scheme_current SUB_INTSTEER MODE 6 >nul
::TDP Level High
call :ControlSet "Control\Power\PowerSettings\48df9d60-4f68-11dc-8314-0800200c9a66\07029cd8-4664-4698-95d8-43b2e9666596" "ACSettingIndex" "0"
::Hardware P-states
powercfg -setacvalueindex scheme_current sub_processor PERFAUTONOMOUS 1 >nul
powercfg -setacvalueindex scheme_current sub_processor PERFAUTONOMOUSWINDOW 1000 >nul
::Disable Hardware P-states Energy Saving
powercfg -setacvalueindex scheme_current sub_processor PERFEPP 0 >nul
::Enable Turbo Boost
powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 1 >nul
powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTPOL 100 >nul
::Disable Sleep States
powercfg -setacvalueindex scheme_current SUB_SLEEP AWAYMODE 0 >nul
powercfg -setacvalueindex scheme_current SUB_SLEEP ALLOWSTANDBY 0 >nul
powercfg -setacvalueindex scheme_current SUB_SLEEP HYBRIDSLEEP 0 >nul
powercfg -setacvalueindex scheme_current SUB_SLEEP UNATTENDSLEEP 0 >nul
powercfg -setacvalueindex scheme_current SUB_IR DEEPSLEEP 0 >nul
::Disable Core Parking
echo %PROCESSOR_IDENTIFIER% | find /I "Intel" >nul && (
powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100 >nul
) || (
powercfg -setacvalueindex scheme_current SUB_INTSTEER UNPARKTIME 0 >nul
powercfg -setacvalueindex scheme_current SUB_INTSTEER PERPROCLOAD 10000 >nul
)
::Disable Frequency Scaling
powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 100 >nul
::Prefer Performant Processors
powercfg -setacvalueindex scheme_current sub_processor SHORTSCHEDPOLICY 2 >nul
powercfg -setacvalueindex scheme_current sub_processor SCHEDPOLICY 2 >nul
::Don't turn off display when plugged in
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
::Apply Changes
powercfg -setactive scheme_current >nul
powercfg -changename scheme_current "TobbyTweaks Ultimate Performance" "For TobbyTweaks Optimizer" >nul
exit
