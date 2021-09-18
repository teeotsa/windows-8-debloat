$ErrorActionPreference = 'SilentlyContinue'
$wshell = New-Object -ComObject Wscript.Shell
$Button = [System.Windows.MessageBoxButton]::YesNoCancel
$ErrorIco = [System.Windows.MessageBoxImage]::Error
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

#This function will create restore point (only if function is called)
function createRestorePoint
{
    Clear-Host
    write-Host "Making Restore Point before starting the script!"
    Enable-ComputerRestore -Drive "C:\"
    Checkpoint-Computer -Description "RestorePoint1" -RestorePointType "MODIFY_SETTINGS" | Out-Null
    Start-Sleep -Seconds 2
}

#This function will restart Windows Explorer whenever the function is called
function restartExplorer
{
    clear-Host 
    Write-Host "Restarting Windows Explorer..."
    Stop-Process -Name "explorer" -Force -PassThru -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep -Seconds 1
}

#You can comment this out if you dont need restore point! Not reccomended tho
createRestorePoint

$Services = @(
    #"wuauserv" -Windows Update ... needed if you want to update or install updates on your Windows 8.0 system
    "LanmanWorkstation" #-Workstation
    "MpsSvc" #-Windows Firewall ... you can disable this service if you dont use Windows Firewall
    "Fax"
    "TabletInputService" #-Touch Keyboard and Handwriting Panel Service ... you can disable this if you are using desktop/laptop computer
    "SysMain" #-Superfetch ... safe to disable, please re-enable this if you experience any kindof issues
    "LanmanServer" #-Server
    "Spooler" #-Print Spooler ... needed for printing
    "iphlpsvc" #-IP Helper
    "HomeGroupProvider" #-HomeGroup Provider ... needed for HomeGroup
    "HomeGroupListener" #-HomeGroup Listener ... needed for HomeGroup
    #Read what homegroup is from : https://support.microsoft.com/en-us/windows/homegroup-from-start-to-finish-9f802c8c-900f-60fb-826f-6fe06add8fe9#:~:text=A%20homegroup%20is%20a%20group,other%20people%20in%20your%20homegroup.&text=Other%20people%20can't%20change,them%20permission%20to%20do%20so.
    "TrkWks" #-Distributed Link Tracking Client ... telemetry, safe to disable
    "WwanSvc" #-WWAN AutoConfig ... might be needed for some laptops/tablets
    "WlanSvc" #-WLAN AutoConfig ... might be needed for some laptops/tablets
    "dot3svc"
    "W32Time" #-Windows Time
    "WSService" #-Windows Store Service (WSService) ... needed for windows store to function
    "WerSvc" #-Windows Error Reporting Service ... kindof telemetry, safe to disable
    "WinDefend" #-Windows Defender ... safe to disable if you dont use Windows Defender and you have some kindof diffrent av program
    "WdNisSvc"
    "WebClient" #-WebClient
    #"VSS" -Volume Shadow Copy ... needed for Windows Backup, Restore Points
    #"SDRSVC" -Windows Backup ... needed for Windows Backup, Restore Points
    "vds"
    "TapiSrv" #-Telephony
    #"StorSvc" #-Storage Service ... needed for Disk Managment
    "svsvc" #-Spot Verifier
    "SCPolicySvc" #-Smart Card Removal Policy
    "ScDeviceEnum"
    "SCardSvr" #-Smart Card
    "SensrSvc"
    "wscsvc" #-Security Center
    "RemoteRegistry" #-Remote Registry
    "TermService" #-Remote Desktop Services ... needed for Remote Desktop
    "UmRdpService" #-Remote Desktop Services UserMode Port Redirector ... needed for Remote Desktop
    "SessionEnv" #-Remote Desktop Configuration ... needed for Remote Desktop
    "RasMan" #-Remote Access Connection Manager ... needed for Remote Desktop
    "RasAuto" #-Remote Access Auto Connection Manager ... needed for Remote Desktop
    "PrintNotify" #-Printer Extensions and Notifications ... needed for printing
    "CscService" #-Offline Files 
    "defragsvc" #-Optimise drives ... needed for disk defragmantation
    "Netlogon" #-Netlogon
    "smphost"
    "swprv" #-Microsoft Software Shadow Copy Provider ... needed for Windows Backup, Restore Points
    "MsKeyboardFilter"
    "MSiSCSI" #-Microsoft iSCSI Initiator Service
    "wlidsvc" #-Microsoft Account Sign-in Assistant ... needed if you want to use Microsoft Account
    "fhsvc" #-File History Service ... needed for File History
    "WPCSvc" #-Family Safety ... needed for parental controls
    "DPS" #-Diagnostic Policy Service ... needed for Diagnostics
    "WdiServiceHost" #-Diagnostic Service Host ... needed for Diagnostics
    "WdiSystemHost" #-Diagnostic System Host ... needed for Diagnostics
    "DeviceAssociationService"
    "bthserv" #-Bluetooth Support Service ... needed for Bluetooth
    "BthHFSrv"
    "BDESVC" #-BitLocker Drive Encryption Service ... needed for BitLocker
    "W3SVC"
    "WAS"
    "FontCache3.0.0.0"
    "WMPNetworkSvc" #-Windows Media Player Network Sharing Service ... not really needed, safe to disable
    "lfsvc"
    "Wecsvc" #-Windows Event Collector
    "w3logsvc"
    "seclogon"
    "QWAVE" #-Quality Windows Audio Video Experience
    "wercplsupport" #-Problem Reports and Solutions Control Panel Support ... kindof telemetry
    "MSMQ"
    "IEEtwCollectorService"
    "hkmsvc"
    "WinHttpAutoProxySvc" #-WinHTTP Web Proxy Auto-Discovery Service
    "NetTcpPortSharing" #-Net.Tcp Port Sharing Service
    "NetTcpActivator"
    "NetPipeActivator"
    "NetMsmqActivator"
    "lmhosts" #-TCP/IP NetBIOS Helper
    "IKEEXT" #-IKE and AuthIP IPsec Keying Modules
    "WSearch" #-Windows Search ... needed for any kind of searches in Windows
    "AllUserInstallAgent" #-Windows All-User Install Agent ... installs AppxPackages (metro apps)
    "sppsvc" #-Software Protection ... needed for some updates or programs, generally safe to disable
    #enable this if you cant install some kindof program/service/update
    #"PcaSvc" -Program Compatibility Assistant Service ... needed for "Compatibility" in some executables 
    "pla" #-Performance Logs & Alerts ... collects pc performance info 
    "vmicvss" #-Hyper-V Volume Shadow Copy Requestor ... needed for Hyper-V
    "vmictimesync" #-Hyper-V Time Synchronization Service ... needed for Hyper-V
    "vmicrdv" #-Hyper-V Remote Desktop Virtualization Service ... needed for Hyper-V
    "vmicheartbeat" #-Hyper-V Heartbeat Service ... needed for Hyper-V
    "vmicshutdown" #-Hyper-V Guest Shutdown Service ... needed for Hyper-V
    "vmickvpexchange" #-Hyper-V Data Exchange Service ... needed for Hyper-V
    "DsmSvc" #-Device Setup Manager ... automaticly downloads Device Drivers for that specific device
    #if needed, you can pretty much disable this
    "VaultSvc" #-Credential Manager ... keeps ur passwords "safe", safe to disable
    "Browser" #-Computer Browser ... Maintains an updated list of computers on the network and supplies this list to computers designated as browsers.
    #If this service is stopped, this list will not be updated or maintained.
)


#this section will disable and stop services listed above
foreach ($Services in $Services) {
    Get-Service -Name $Services -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled
    write-Host "$Services has been disabled" 
    $running = Get-Service -Name $Services -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'}
        if ($running) { 
            Stop-Service -Name $Services -Force -PassThru -ErrorAction SilentlyContinue
            write-Warning "$Services has been stopped"
        }
}

Write-Host "Now, registry tweaks!"

#Disable Active Corners, might not work on Windows 8.0 because there is no option in taskbar options
#to disable active corners and charms bar
$ActiveCorner = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUI"
if (!(Test-Path $ActiveCorner)){
    New-Item $ActiveCorner -Force | Out-Null
}
Set-ItemProperty -Path $ActiveCorner -Name "DisableCharmsHint" -Type DWord -Value 1
Set-ItemProperty -Path $ActiveCorner -Name "DisableTLCorner" -Type DWord -Value 1
write-Host "'Hot Corners' and 'Charms Bar' has been disabled"

#Disable File Histroy
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory")){
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory" -Name "Disabled" -Type DWord -Value 1
write-Host "File History should be disabled now"

#Disable Consumer Features, kindof telemetry. Safe to disable
$ConsumerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
if (!(Test-Path $ConsumerPath)){
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
write-Host "Consumer Features should be disabled now"

#No Use Open With dialog, might not work with Windows 8.0
$NoUseWithPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
if (!(Test-Path $NoUseWithPath)){
    New-Item $NoUseWithPath -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
write-Host "Open With prompts should be disabled now"

#No New App Alert, might not work with Windows 8.0
$NoNewAppAlertPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
if (!(Test-Path $NoNewAppAlertPath)){
    New-Item $NoNewAppAlertPath -Force |  Out-Null
} 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1
write-Host "No new application prompts should be disabled now"

#No LockScreen
$NoLockScreenPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
if (!(Test-Path $NoLockScreenPath)){
    New-Item $NoLockScreenPath -Force | Out-Null
}
Set-ItemProperty -Path $NoLockScreenPath -Name "NoLockScreen" -Type DWord -Value 1
write-Host "Lock Screen has been disabled"

#No Application Backups
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync")){
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "EnableBackupForWin8Apps" -Type DWord -Value 0
write-Host "Application backups has been disabled"


#Disable Infrared Stuff
if (!(Test-Path "HKCU:\Control Panel\Infrared\Global")){
    New-Item "HKCU:\Control Panel\Infrared\Global" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Control Panel\Infrared\Global" -Name "ShowTrayIcon" -Type DWord -Value 0
if (!(Test-Path "HKCU:\Control Panel\Infrared\File Transfer")){
    New-Item "HKCU:\Control Panel\Infrared\File Transfer" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Control Panel\Infrared\File Transfer" -Name "AllowSend" -Type DWord -Value 0
write-Host "Infrared should be disabled now"

#Disable Smart Screen
$DisableSmartScreen = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (!(Test-Path $DisableSmartScreen)){
    New-Item $DisableSmartScreen
}
Set-ItemProperty -Path $DisableSmartScreen -Name "EnableSmartScreen" -Type DWord -Value 0
write-Host "Smartscreen is disabled now"

#No Activity History
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")){
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
write-Host "Activity History is disabled"

#Disable Anti Spyware (No Windows Defender)
if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows Defender")){
    New-Item "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
write-Host "Windows Defender should be disabled now (Service is still running tho)"

#Disable -shortcut text
#if you create any shortcuts anywhere, usually filename will be "filename.exe -shortcut"
#this portion of the script will remove "-shortcut" from any shortcuts you make
$RemoveShortcut = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
if (!(Test-Path $RemoveShortcut)){
    New-Item -Path $RemoveShortcut -Force | Out-Null
}
Set-ItemProperty -Path $RemoveShortcut -Name "link" -Type Binary -Value ([byte[]](00,00,00,00))
write-Host "-shortcut text on shortcuts has been disabled"

#Remove Shortcut arrow
if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons")){
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Name "29" -Type String -Value ""
write-Host "Shortcut arrows are disabled"

#Launch Apps Faster
if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize")){
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Force | Out-Null
} 
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -Type DWord -Value 0
restartExplorer #restarts windows explorer, function above
write-Host "You should be able to launch applications faster now"

#Disable Windows Error Reporting
if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting")){
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
write-Host "Windows Error Reporting has been disbaled"

#No store apps on taskbar, this will hide all running metro apps from your taskbar
if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")){
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "StoreAppsOnTaskbar" -Type DWord -Value 0
write-Host "Store apps on taskbar should be disabled now"

#Taskbar Small Icons
if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")){
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
restartExplorer
write-Host "You should now have Small Taskbar Icons"

#Windows Explorer Status Bar - Disabled
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowStatusBar" -Type DWord -Value 0
write-Host "Status Bar from Explorer is gone now"

#Hide Favourites from Windows Explorer
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowFavorites" -Type DWord -Value 0
write-Host "Favourites is gone from Explorer now"

#This will show you File Extensions, useful
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
write-Host "You will be able to see file extensions now"

#Disable Aero Shake
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Type DWord -Value 1
Write-Host "Aero Share is disabled"

#Disable AutoPlay
if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers")){
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
write-Host "AutoPlay is disabled"

#Disable AeroPeek
if (!(Test-Path "HKCU:\Software\Microsoft\Windows\DWM")){
    New-Item -Path "HKCU:\Software\Microsoft\Windows\DWM" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
write-Host "AeroPeek is disabled now"

#Disable Auto Screen Rotation
if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation")){
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation" -Name "Enable" -Type DWord -Value 0
Write-Host "Auto Screen Rotation is disabled now"

#Disable Settings Sync
$DisableSettingsSyncing = "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync"
if (!(Test-Path $DisableSettingsSyncing)){
    New-Item $DisableSettingsSyncing -Force | Out-Null
}
Set-ItemProperty -Path $DisableSettingsSyncing -Name "Enabled" -Type DWord -Value 0
write-Host "Settings sync has been disabled"

#Disable Scheduled Tasks
$ScheduledTasks = @(
"\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization"
"\Microsoft\Windows\Work Folders\Work Folders Maintenance Work"
"\Microsoft\Windows\WS\Badge Update"
"\Microsoft\Windows\WS\License Validation"
"\Microsoft\Windows\WS\Sync Licenses"
"\Microsoft\Windows\WS\WSRefreshBannedAppsListTask"
"\Microsoft\Windows\WS\WSTask"
"\Microsoft\Windows\WindowsUpdate\AUFirmwareInstall"
"\Microsoft\Windows\WindowsUpdate\AUScheduledInstall"
"\Microsoft\Windows\WindowsUpdate\AUSessionConnect"
"\Microsoft\Windows\WindowsUpdate\Scheduled Start"
"\Microsoft\Windows\WindowsUpdate\Scheduled Start With Network"
"\Microsoft\Windows\Windows Error Reporting\QueueReporting"
"\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
"\Microsoft\Windows\Windows Defender\Windows Defender Cleanup"
"\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
"\Microsoft\Windows\Windows Defender\Windows Defender Verification"
"\Microsoft\Windows\SystemRestore\SR" # ... might be needed for System Restore, Windows Backup, Restore Points
"\Microsoft\Windows\SkyDrive\Idle Sync Maintenance Task"
"\Microsoft\Windows\SkyDrive\Routine Maintenance Task"
"\Microsoft\Windows\Shell\IndexerAutomaticMaintenance"
"\Microsoft\Windows\SettingSync\BackgroundUploadTask"
"\Microsoft\Windows\SettingSync\BackupTask"
"\Microsoft\Windows\SettingSync\NetworkStateChangeTask"
"\Microsoft\Windows\Offline Files\Background Synchronization"
"\Microsoft\Windows\Offline Files\Logon Synchronization"
"\Microsoft\Windows\File Classification Infrastructure\Property Definition Sync"
"\Microsoft\Windows\Registry\RegIdleBackup"
"\Microsoft\Windows\Location\Notifications"
"\Microsoft\Windows\FileHistory\File History (maintenance mode)"
"\Microsoft\Windows\FileHistory\File History"
"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"
"\Microsoft\Windows\Autochk\Proxy"
"\Microsoft\Windows\DiskCleanup\SilentCleanup"
"\Microsoft\Windows\Defrag\ScheduledDefrag"
"\Microsoft\Windows\Application Experience\AitAgent"
"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
"\Microsoft\Windows\Application Experience\ProgramDataUpdater"
"\Microsoft\Windows\Application Experience\StartupAppTask"
"\Microsoft\Windows\ApplicationData\CleanupTemporaryState"
"\Microsoft\Windows\Bluetooth\UninstallDeviceTask"
"\Microsoft\Windows\Chkdsk\ProactiveScan"
"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
"\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
"\Microsoft\Windows\Customer Experience Improvement Program\BthSQM"
"\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan for Crash Recovery"
"\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan"
"\Microsoft\Windows\Defrag\ScheduledDefrag"
"\Microsoft\Windows\Diagnosis\Scheduled"
"\Microsoft\Windows\Maintenance\WinSAT"
"\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents"
"\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic"
"\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser"
"\Microsoft\Windows\MUI\LPRemove"
"\Microsoft\Windows\NetTrace\GatherNetworkInfo"
"\Microsoft\Windows\PerfTrack\BackgroundConfigSurveyor"
"\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
"\Microsoft\Windows\RAC\RacTask"
"\Microsoft\Windows\Ras\MobilityManager"
"\Microsoft\Windows\RecoveryEnvironment\VerifyWinRE"
"\Microsoft\Windows\Servicing\StartComponentCleanup"
"\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask"
"\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon"
#"\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork"
"\Microsoft\Windows\SpacePort\SpaceAgentTask"
"\Microsoft\Windows\Sysmain\HybridDriveCachePrepopulate"
"\Microsoft\Windows\Sysmain\HybridDriveCacheRebalance"
"\Microsoft\Windows\Sysmain\WsSwapAssessmentTask"
"\Microsoft\Windows\TPM\Tpm-Maintenance"
"\Microsoft\Windows\WDI\ResolutionHost"
"\Microsoft\Windows\Windows Media Sharing\UpdateLibrary"
"\Microsoft\Windows\WS\License Validation"
"\Microsoft\Windows\WS\WSTask"
"\Microsoft\Windows\WS\WSRefreshBannedAppsListTask"
"\Microsoft\Windows\WS\Sync Licenses"
"\Microsoft\Windows\WS\Badge Update"
)

#Clear output before prompting 
Clear-Host

foreach ($ScheduledTasks in $ScheduledTasks){
    Disable-ScheduledTask -TaskName $ScheduledTasks -ErrorAction SilentlyContinue | Out-Null 
    write-Host "Trying to disable '$ScheduledTasks'"
}

function tweakVisualEffects
{
    #Tweak visual effects
    if (!(Test-Path "HKCU:\Control Panel\Desktop")){
        New-Item -Path "HKCU:\Control Panel\Desktop" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 200
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))
    if (!(Test-Path "HKCU:\Control Panel\Desktop\WindowMetrics")){
        New-Item -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
    if (!(Test-Path "HKCU:\Control Panel\Keyboard")){
        New-Item -Path "HKCU:\Control Panel\Keyboard" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\DWM")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\DWM" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" -Name "DefaultApplied" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" -Name "DefaultApplied" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled" -Name "DefaultApplied" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" -Name "DefaultApplied" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation" -Name "DefaultApplied" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation" -Name "DefaultApplied" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" -Name "DefaultApplied" -Type DWord -Value 0
    restartExplorer 
}

function askVisual
{
    Clear-Host
    $VisualEffectAnswer = read-Host "Do you want to tweak your Visual Effects?
Answer : (Y/N)"
    switch($VisualEffectAnswer){

        'Y'
        {
            Write-Host "Starting to tweak Visual Effects!"
            tweakVisualEffects
        }

        'N'{Write-Host "Skipping Visual Effects"}
        ''{askVisual}
    }
}
askVisual
<#
Optional Features Commands : ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
                                                                                                                                             :: 
    Enable-WindowsOptionalFeature -Online -FeatureName "Feature Full Name Here" -NoRestart -WarningAction SilentlyContinue | Out-Null        ::
    Disable-WindowsOptionalFeature -Online -FeatureName "Feature Full Name Here" -NoRestart -WarningAction SilentlyContinue | Out-Null       ::
                                                                                                                                             ::
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::


List of Useful Optional Feature Names : 

-NetFx3
-WindowsMediaPlayer
-DirectPlay
-LegacyComponents

You can get full list of optional features with this command:: 
::            Get-WindowsOptionalFeature -Online            ::
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
#>

$OptionalFeatures = @(
    "WindowsMediaPlayer"
    "NetFx3"
    "LegacyComponents"
    "DirectPlay"
)
foreach ($OptionalFeatures in $OptionalFeatures){
    write-Host "Trying to enable '$OptionalFeatures'"
    Enable-WindowsOptionalFeature -Online -FeatureName $OptionalFeatures -NoRestart -WarningAction SilentlyContinue | Out-Null
}

#List of all Bloatware apps installed
$Bloatware = @(
"windows.immersivecontrolpanel" #... Control Panel for Windows
"WinStore"
"Microsoft.BingFinance"
"Microsoft.WinJS.1.0"
"Microsoft.BingMaps"
"Microsoft.VCLibs.110.00"
"Microsoft.VCLibs.110.00"
"Microsoft.BingNews"
"Microsoft.BingSports"
"Microsoft.BingTravel"
"Microsoft.BingWeather"
"Microsoft.Bing"
"Microsoft.Camera"
"microsoft.microsoftskydrive"
"Microsoft.Reader"
"microsoft.windowscommunicationsapps"
"microsoft.windowsphotos"
"Microsoft.XboxLIVEGames"
"Microsoft.ZuneMusic"
"Microsoft.Media.PlayReadyClient"
"Microsoft.Media.PlayReadyClient"
"Microsoft.ZuneVideo"
)

#Remove bloatware from list above
foreach($Bloat in $Bloatware){

    Get-AppxPackage -Name $Bloat | Remove-AppxPackage 
    Get-AppxPackage -AllUsers -Name $Bloat | Remove-AppxPackage 
    Get-AppxProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online
    write-Host "Trying to remove '$Bloat'"

}
Disable-ScheduledTask -TaskName "\Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup" | Out-Null -ErrorAction SilentlyContinue
#Disable AppxService (kill Metro Apps)
$AppX = "AppXSvc"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppXSvc" -Name "Start" -Type DWord -Value 4
Get-Service -Name $AppX | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue

#Last part of the script
restartExplorer
Start-Sleep -Milliseconds 500


#Ask user if they want to restart their computer
function askRestart{
    Clear-Host
    $RestartAnswer = read-Host "Do you want to restart your computer?
    Answer (Y/N)"
    switch($RestartAnswer){

    'Y'{ shutdown -r -t 0}
    'N'{ exit }
    ''{ askRestart }

    }
}

askRestart


