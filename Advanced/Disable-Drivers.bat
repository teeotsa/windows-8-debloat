@ECHO OFF
SET "UAC_FILE=%TEMP%\DISABLE_DRIVER_UAC.VBS"
REG QUERY "HKEY_USERS\S-1-5-20" > NUL 2>&1 || (
    ECHO CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%UAC_FILE%" && "%UAC_FILE%" 
    EXIT /B
)
IF EXIST "%UAC_FILE%" DEL "%UAC_FILE%" /F /Q > NUL 2>&1

reg add "HKLM\SYSTEM\CurrentControlSet\Services\ahcache" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Beep" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BthAvrcpTg" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BthHFEnum" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\bthhfhid" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BTHMODEM" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\cdfs" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CmBatt" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\CSC" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\FileInfo" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Filetrace" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\flpydisk" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\gencounter" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\HidBatt" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\HidBth" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\HidIr" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\kdnic" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lltdio" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\luafv" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Ndu" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetBIOS" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\QWAVEdrv" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasAcd" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RasPppoe" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\rdpbus" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RDPDR" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\RdpVideoMiniport" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\rspndr" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\secdrv" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\sfloppy" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\storflt" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpipreg" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\udfs" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\vpci" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\vpcivsp" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\vwifibus" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WacomPen" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdBoot" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Wof" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wpcfltr" /v "Start" /f /t REG_DWORD /d 4 >nul 2>&1