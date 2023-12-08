@echo off
echo Disabling System energy-saving techniques.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f

::v2
::Disable Network Power Savings and Mitigations
powershell -NoProfile -NonInteractive -ExecutionPolicy Unrestricted -Command ^
$ErrorActionPreference = 'SilentlyContinue';^
Disable-NetAdapterPowerManagement -Name "*";^
Set-NetOffloadGlobalSetting -PacketCoalescingFilter Disabled -Chimney Disabled;^
Set-NetTCPSetting -SettingName "Internet" -MemoryPressureProtection Disabled
echo Disable Network Power Savings And Mitigations

Reg query HKCU\Software\CoutX /v DisableMitigations 2>nul | find "0x1" >nul && (
	::Disable Kernel Mitigations
	for /f "tokens=3 skip=2" %%i in ('Reg query "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions"') do set mitigation_mask=%%i
	for /l %%i in (0,1,9) do set mitigation_mask=!mitigation_mask:%%i=2!
	Reg add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "!mitigation_mask!" /f >nul
	Reg add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "!mitigation_mask!" /f >nul
	::Disable More Kernel Mitigations (Enforced Intel SGX causes boot crashes/loops)
	echo %PROCESSOR_IDENTIFIER% | find /I "Intel" >nul || bcdedit /set allowedinmemorysettings 0x0 >nul
	echo Disable Kernel Mitigations
	
	::Disable CSRSS mitigations
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationAuditOptions /t REG_BINARY /d "!mitigation_mask!" /f >nul
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationOptions /t REG_BINARY /d "!mitigation_mask!" /f >nul
	echo Disable CSRSS mitigations
	
	::Disable Process Mitigations
	PowerShell -nop "ForEach($v in (Get-Command -Name \"Set-ProcessMitigation\").Parameters[\"Disable\"].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue}" >nul
	echo Disable Process Mitigations
	
	::Disable TsX
	call :ControlSet "Control\Session Manager\kernel" "DisableTsx" "1"
	echo Disable TsX
	
	::Disable VSM
	bcdedit /set vm No >nul
	bcdedit /set vsmlaunchtype Off >nul
	bcdedit /set hypervisorlaunchtype off >nul
	echo Disable VSM
	
	::Disable VBS
	call :ControlSet "Control\DeviceGuard" "EnableVirtualizationBasedSecurity" "0"
	bcdedit /set loadoptions "DISABLE-LSA-ISO,DISABLE-VBS" >nul
	bcdedit /set isolatedcontext No >nul
	echo Disable VBS
	
	::Disable Memory Integrity
	call :ControlSet "Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" "Enabled" "0"
	call :ControlSet "Control\DeviceGuard" "HypervisorEnforcedCodeIntegrity" "0"
	echo Disable Memory Integrity

	::Disable Data Execution Prevention
	echo %PROCESSOR_IDENTIFIER% | find /I "Intel" >nul && (
	bcdedit /set nx AlwaysOff >nul
	Reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" /v "DEPOff" /t REG_DWORD /d 1 /f >nul
	Reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 1 /f >nul
	Reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 1 /f >nul
	)
	echo Disable Data Execution Prevention
	
	::Disable Dma Memory Protection
	Reg add "HKLM\Software\Microsoft\PolicyManager\default\DmaGuard\DeviceEnumerationPolicy" /v "value" /t REG_DWORD /d "2" /f >nul
	Reg add "HKLM\Software\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d "0" /f >nul
	Reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f >nul
	echo Disable Dma Remapping / Memory Protection
	
	::Disable SEHOP
	call :ControlSet "Control\Session Manager\kernel" "DisableExceptionChainValidation" "1"
	call :ControlSet "Control\Session Manager\kernel" "KernelSEHOPEnabled" "0"
	echo Disable SEHOP
	
	::Disable File System Mitigations
	call :ControlSet "Control\Session Manager" "ProtectionMode" "0"
	
	::Disable Control Flow Guard
	call :ControlSet "Control\Session Manager\Memory Management" "EnableCfg" "0"
	echo Disable Control Flow Guard
	
	::Disable Spectre And Meltdown
	call :ControlSet "Control\Session Manager\Memory Management" "FeatureSettings" "3"
	call :ControlSet "Control\Session Manager\Memory Management" "FeatureSettingsOverride" "3"
	call :ControlSet "Control\Session Manager\Memory Management" "FeatureSettingsOverrideMask" "3"
	rem Disabling Microcode Mitigations on Windows 24H2 Causes BSOD
	for /f "tokens=4-9 delims=. " %%i in ('ver') do if %%k lss 25967 (
		takeown /f "C:\Windows\System32\mcupdate_GenuineIntel.dll" /r /d y >nul 2>&1
		takeown /f "C:\Windows\System32\mcupdate_AuthenticAMD.dll" /r /d y >nul 2>&1
		ren %WinDir%\System32\mcupdate_GenuineIntel.dll mcupdate_GenuineIntel.dll.old 2>nul
		ren %WinDir%\System32\mcupdate_AuthenticAMD.dll mcupdate_AuthenticAMD.dll.old 2>nul
	)
	echo Disable Spectre And Meltdown
	
	::Disable ITLB Multi-hit mitigations
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Virtualization" /v "IfuErrataMitigations" /t REG_DWORD /d "0" /f >nul
	echo Disable ITLB Multi-hit mitigations
	
	::Disable FTH
	Reg add HKLM\Software\Microsoft\FTH /v Enabled /t REG_DWORD /d 0 /f >nul
	rundll32.exe fthsvc.dll,FthSysprepSpecialize
	echo Disable FTH
	
	 Reg add HKCU\Software\CoutX /v DisableMitigationsgRan /t REG_DWORD /d 1 /f >nul
) || Reg query HKCU\Software\CoutX /v DisableMitigationsgRan 2>nul | find "0x1" >nul && (
	::Reset Kernel Mitigations
	Reg delete "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /f >nul 2>&1
	Reg delete "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /f >nul 2>&1
	::Reset More Kernel Mitigations
	bcdedit /deletevalue allowedinmemorysettings >nul
	
	::Reset CSRSS mitigations
	Reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationAuditOptions /f >nul 2>&1
	Reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v MitigationOptions /f >nul 2>&1
	
	::Reset System Mitigations
	PowerShell -nop "Set-ProcessMitigation -System -Reset" >nul 2>&1
	
	::Reset TsX
	call :DelControlSet "Control\Session Manager\kernel" "DisableTsx"
	
	::Reset VSM
	bcdedit /deletevalue vm >nul
	bcdedit /deletevalue vsmlaunchtype >nul
	bcdedit /deletevalue hypervisorlaunchtype >nul
	
	::Reset VBS
	call :DelControlSet "Control\DeviceGuard" "EnableVirtualizationBasedSecurity"
	bcdedit /deletevalue loadoptions >nul
	bcdedit /deletevalue isolatedcontext >nul
	
	::Reset Memory Integrity
	call :DelControlSet "Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" "Enabled"
	call :DelControlSet "Control\DeviceGuard" "HypervisorEnforcedCodeIntegrity"
	
	::Reset Data Execution Prevention
	bcdedit /deletevalue nx >nul
	Reg delete "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" /v "DEPOff" /f >nul 2>&1
	Reg delete "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /f >nul 2>&1
	Reg delete "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /f >nul 2>&1
	
	::Reset Dma Memory Protection
	Reg delete "HKLM\Software\Microsoft\PolicyManager\default\DmaGuard\DeviceEnumerationPolicy" /v "value" /f >nul 2>&1
	Reg delete "HKLM\Software\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /f >nul 2>&1
	Reg delete "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /f >nul 2>&1
	
	::Reset SEHOP
	call :DelControlSet "Control\Session Manager\kernel" "DisableExceptionChainValidation" "1"
	call :DelControlSet "Control\Session Manager\kernel" "KernelSEHOPEnabled" "0"
	
	::Reset File System Mitigations
	call :DelControlSet "Control\Session Manager" "ProtectionMode"
	
	::Reset Control Flow Guard
	call :DelControlSet "Control\Session Manager\Memory Management" "EnableCfg"
	
	::Reset Spectre And Meltdown
	call :DelControlSet "Control\Session Manager\Memory Management" "FeatureSettings"
	call :DelControlSet "Control\Session Manager\Memory Management" "FeatureSettingsOverride"
	call :DelControlSet "Control\Session Manager\Memory Management" "FeatureSettingsOverrideMask"
	takeown /f "C:\Windows\System32\mcupdate_GenuineIntel.dll.old" /r /d y >nul 2>&1
	takeown /f "C:\Windows\System32\mcupdate_AuthenticAMD.dll.old" /r /d y >nul 2>&1
	ren %WinDir%\System32\mcupdate_GenuineIntel.dll.old mcupdate_GenuineIntel.dll
	ren %WinDir%\System32\mcupdate_AuthenticAMD.dll.old mcupdate_AuthenticAMD.dll
	echo Reset Mitigations
	
	::Reset ITLB Multi-hit mitigations
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Virtualization" /v "IfuErrataMitigations" /t REG_DWORD /d "0" /f >nul
	echo Reset ITLB Multi-hit mitigations
	
	::Reset FTH
	Reg delete HKLM\Software\Microsoft\FTH /v Enabled /f >nul
	rundll32.exe fthsvc.dll,FthSysprepSpecialize
	echo Reset FTH
	
	Reg delete HKCU\Software\CoutX /v DisableMitigationsgRan /f >nul
)
exit