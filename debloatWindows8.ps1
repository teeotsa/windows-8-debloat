#This script should get you around 30 processes also 500mb ram

$ErrorActionPreference = 'SilentlyContinue'
$wshell = New-Object -ComObject Wscript.Shell
$Button = [System.Windows.MessageBoxButton]::YesNoCancel
$ErrorIco = [System.Windows.MessageBoxImage]::Error
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

Write-Host "Script made by Teeotsa"
Start-Sleep -Seconds 2
cls
Write-Host "Starting script..."

#   Disable services!
#   Set-Service -StartupType Disabled ""
#   Stop-Service -Force -Name ""
#   Write-Host ""
#   Disable-ScheduledTask -TaskName "Path" | Out-Null
#   Set-ItemProperty -Path "" -Name "" -Type DWord -Value 1
#   Disable-WindowsOptionalFeature -Online -FeatureName "" -NoRestart -WarningAction SilentlyContinue | Out-Null
#   Stop-Process -Force -Name ""

#Killing some processes before starting
write-Host "Killing some processes before starting debloating..."
Stop-Process -Force -Name "SystemSettings"
Stop-Process -Force -Name "SystemSettingsAdminFlows"
Stop-Process -Force -Name "TiWorker"
Stop-Process -Force -Name "TrustedInstaller"
Stop-Process -Force -Name "WmiPrvSE"
Stop-Process -Force -Name "mobsync"



#Disable Windows Update Service
#wuauserv
Set-Service -StartupType Disabled "wuauserv"
Stop-Service -Force -Name "wuauserv"
Write-Host "Windows Update service has been disabled and stopped"

#Disable Windows Search Service
#WSearch
Set-Service -StartupType Disabled "WSearch"
Stop-Service -Force -Name "WSearch"
Write-Host "Windows Search service has been disabled and stopped"

#Disable Workstation service
#LanmanWorkstation
Set-Service -StartupType Disabled "LanmanWorkstation"
Stop-Service -Force -Name "LanmanWorkstation"
Write-Host "Workstation service has been disabled and stopped"

#Disable Windows Firewall service
#MpsSvc
Set-Service -StartupType Disabled "MpsSvc"
Stop-Service -Force -Name "MpsSvc"
Write-Host "Windows Firewall service has been disabled and stopped"

#Disable Fax service
#Fax
Set-Service -StartupType Disabled "Fax"
Stop-Service -Force -Name "Fax"
Write-Host "Fax service has been disabled and stopped"

#Disable Touch Keyboard service
#TabletInputService
Set-Service -StartupType Disabled "TabletInputService"
Stop-Service -Force -Name "TabletInputService"
Write-Host "Touch Keyboard service has been disabled and stopped"
  
#Disable superfetch service
#SysMain
Set-Service -StartupType Disabled "SysMain"
Stop-Service -Force -Name "SysMain"
Write-Host "superfetch has been disabled and stopped"

#Disable server service
#LanmanServer
Set-Service -StartupType Disabled "LanmanServer"
Stop-Service -Force -Name "LanmanServer"
Write-Host "Server service has been disabled and stopped"

#Disable Print Spooler service
#Spooler
Set-Service -StartupType Disabled "Spooler"
Stop-Service -Force -Name "Spooler"
Write-Host "Print Spooler service has been disabled and stopped"

#Disable IP Helper service
#iphlpsvc
Set-Service -StartupType Disabled "iphlpsvc"
Stop-Service -Force -Name "iphlpsvc"
Write-Host "IP Helper service has been disabled and stopped"

#Disable Homegroup services
 #HomeGroupProvider
 #HomeGroupListener
Set-Service -StartupType Disabled "HomeGroupProvider"
Set-Service -StartupType Disabled "HomeGroupListener"
Stop-Service -Force -Name "HomeGroupProvider"
Stop-Service -Force -Name "HomeGroupListener"
Write-Host "Homegroup services has been disabled and stopped"

#Disable Distributed Link Tracking Client
#TrkWks
Set-Service -StartupType Disabled "TrkWks"
Stop-Service -Force -Name "TrkWks"
Write-Host "Distributed Link Tracking Client service has been disabled and stopped"

#Disable WWAN AutoConfig
#WwanSvc
Set-Service -StartupType Disabled "WwanSvc"
Stop-Service -Force -Name "WwanSvc"
Write-Host "WWAN AutoConfig has been disabled! If you want to use WiFi, please re-enable this service"

#Disable WLAN AutoConfig
#WlanSvc
Set-Service -StartupType Disabled "WlanSvc"
Stop-Service -Force -Name "WlanSvc"
Write-Host "WLAN AutoConfig has been disabled! If you want to use WiFi, please re-enable this service"

#Disable Wired AutoConfig
#dot3svc
Set-Service -StartupType Disabled "dot3svc"
Stop-Service -Force -Name "dot3svc"
Write-Host "Wired AutoConfig has been disabled"

#Disable Windows Time 
#W32Time
Set-Service -StartupType Disabled "W32Time"
Stop-Service -Force -Name "W32Time"
Write-Host "Windows Time has been disabled" 

#Disable Windows Store Service
#WSService
Set-Service -StartupType Disabled "WSService"
Stop-Service -Force -Name "WSService"
Write-Host "Windows Store Service has been disabled"

#Disable Windows Error Reporting Service
#WerSvc
Set-Service -StartupType Disabled "WerSvc"
Stop-Service -Force -Name "WerSvc"
Write-Host "Windows Error Reporting Service has been disabled"

#Disable Windows Defender Service
#WinDefend
Set-Service -StartupType Disabled "WinDefend"
Stop-Service -Force -Name "WinDefend"
Write-Host "Windows Defender Service has been disabled"

#Disable Windows Defender Network Inspection Service
#WdNisSvc
Set-Service -StartupType Disabled "WdNisSvc"
Stop-Service -Force -Name "WdNisSvc"
Write-Host "Windows Defender Network Inspection Service has been disabled"
 
#Disable Web Client service
#WebClient
Set-Service -StartupType Disabled "WebClient"
Stop-Service -Force -Name "WebClient"
Write-Host "WebClient Service has been disabled"

#Disable Volume Shadow Copy Service
#VSS
Stop-Process -Force -Name "VSSVC"
Start-Sleep -Milliseconds 200
Set-Service -StartupType Disabled "VSS"
Stop-Service -Force -Name "VSS"
Write-Host "Volume Shadow Copy has been disabled"

#Disable Virtual Disk service
#vds
Set-Service -StartupType Disabled "vds"
Stop-Service -Force -Name "vds"
Write-Host "Virtual Disk service has been disabled"

#Disable Telephony Service
#TapiSrv
Set-Service -StartupType Disabled "TapiSrv"
Stop-Service -Force -Name "TapiSrv"
Write-Host "Telephony Service has been disabled"

#Disable Storage Service
#StorSvc
Set-Service -StartupType Disabled "StorSvc"
Stop-Service -Force -Name "StorSvc"
Write-Host "Storage Service has been disabled"

#Disable Spot Veifier Service
#svsvc
Set-Service -StartupType Disabled "svsvc"
Stop-Service -Force -Name "svsvc"
Write-Host "Spot Veifier Service has been disabled"

#Disable Smart Card Services
#SCPolicySvc
#ScDeviceEnum
#SCardSvr
Set-Service -StartupType Disabled "SCPolicySvc"
Set-Service -StartupType Disabled "ScDeviceEnum"
Set-Service -StartupType Disabled "SCardSvr"
Stop-Service -Force -Name "SCPolicySvc"
Stop-Service -Force -Name "ScDeviceEnum"
Stop-Service -Force -Name "SCardSvr"
Write-Host "Smart Card Services has been disabled"

#Disable Sensor Service
#SensrSvc
Set-Service -StartupType Disabled "SensrSvc"
Stop-Service -Force -Name "SensrSvc"
Write-Host "Sensor Service has been disabled! If you use laptop, please re-enable this service!"

#Disable Security Center Service
#wscsvc
Set-Service -StartupType Disabled "wscsvc"
Stop-Service -Force -Name "wscsvc"
Write-Host "Security Center Service has been disabled"

#Disable Remote Registry  Service
#RemoteRegistry
Set-Service -StartupType Disabled "RemoteRegistry"
Stop-Service -Force -Name "RemoteRegistry"
Write-Host "Remote Registry Service has been disabled"

#Disable Remote Access Service
#TermService
#UmRdpService
#SessionEnv
#RasMan
#RasAuto
Set-Service -StartupType Disabled "TermService"
Stop-Service -Force -Name "TermService"
Set-Service -StartupType Disabled "UmRdpService"
Stop-Service -Force -Name "UmRdpService"
Set-Service -StartupType Disabled "SessionEnv"
Stop-Service -Force -Name "SessionEnv"
Set-Service -StartupType Disabled "RasMan"
Stop-Service -Force -Name "RasMan"
Set-Service -StartupType Disabled "RasAuto"
Stop-Service -Force -Name "RasAuto"
Write-Host "Remote Desktop has been disabled"

#Disable Printing Stuff
#PrintNotify
Set-Service -StartupType Disabled "PrintNotify"
Stop-Service -Force -Name "PrintNotify"
Write-Host "Printer Extensions and Notifications Service has been disabled"

#Disable Offline Files Service
#CscService
Set-Service -StartupType Disabled "CscService"
Stop-Service -Force -Name "CscService"
Write-Host "Offline Files Service has been disabled"

#Disable Optimize Drives Service
#defragsvc
Set-Service -StartupType Disabled "defragsvc"
Stop-Service -Force -Name "defragsvc"
Write-Host "Optimize Drives Service has been disabled"

#Disable Netlogon Server
#Netlogon
Set-Service -StartupType Disabled "Netlogon"
Stop-Service -Force -Name "Netlogon"
Write-Host "Netlogon Service has been disabled"

#Disable Microsoft Services
#smphost
#swprv
#MsKeyboardFilter
#MSiSCSI
#wlidsvc
Set-Service -StartupType Disabled "smphost"
Set-Service -StartupType Disabled "swprv"
Set-Service -StartupType Disabled "MsKeyboardFilter"
Set-Service -StartupType Disabled "MSiSCSI"
Set-Service -StartupType Disabled "wlidsvc"
Stop-Service -Force -Name "smphost"
Stop-Service -Force -Name "swprv"
Stop-Service -Force -Name "MsKeyboardFilter"
Stop-Service -Force -Name "MSiSCSI"
Stop-Service -Force -Name "wlidsvc"
Write-Host "Microsoft Services has been disabled"

#Disable File History Service
#fhsvc
Set-Service -StartupType Disabled "fhsvc"
Stop-Service -Force -Name "fhsvc"
Write-Host "File History Service has been disabled"

#Disable Family Safety Service
#WPCSvc
Set-Service -StartupType Disabled "WPCSvc"
Stop-Service -Force -Name "WPCSvc"
Write-Host "Family Safety Service has been disabled"

#Disable Diagnostic Services
#DPS
#WdiServiceHost
#WdiSystemHost
Set-Service -StartupType Disabled "DPS"
Set-Service -StartupType Disabled "WdiServiceHost"
Set-Service -StartupType Disabled "WdiSystemHost"
Stop-Service -Force -Name "DPS"
Stop-Service -Force -Name "WdiServiceHost"
Stop-Service -Force -Name "WdiSystemHost"
Write-Host "Diagnostic Services has been disabled"

#Disable Pairing between devices
#DeviceAssociationService
Set-Service -StartupType Disabled "DeviceAssociationService"
Stop-Service -Force -Name "DeviceAssociationService"
Write-Host "DeviceAssociationService has been disabled"

#Disable Bluetooth
#bthserv
#BthHFSrv
Set-Service -StartupType Disabled "bthserv"
Set-Service -StartupType Disabled "BthHFSrv"
Stop-Service -Force -Name "bthserv"
Stop-Service -Force -Name "BthHFSrv"
Write-Host "Bluetooth Services has been disabled"

#Disable BitLocker
#BDESVC
Set-Service -StartupType Disabled "BDESVC"
Stop-Service -Force -Name "BDESVC"
Write-Host "BitLocker has been disabled"

#Registry Tweaks
Write-Host "Now, registry tweaks!"

#Disable Consumer Features
Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1

#No Use Open With
Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1

#No New App Alert
Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1

#No LockScreen
Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1

#No Application Backups
Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "EnableBackupForWin8Apps" -Type DWord -Value 0

#Disable Infrared
# Set-ItemProperty -Path "" -Name "" -Type DWord -Value 1
#HKEY_CURRENT_USER\Control Panel\Infrared\File Transfer

    #Show Tray Icon - Disable
    Set-ItemProperty -Path "HKCU:\Control Panel\Infrared\Global" -Name "ShowTrayIcon" -Type DWord -Value 0

    #Allow File Transfer - Disable
    Set-ItemProperty -Path "HKCU:\Control Panel\Infrared\File Transfer" -Name "AllowSend" -Type DWord -Value 0

#Random registry tweaks
Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0

#Disable Anti Spyware
Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1

###Disable Tasks###
# Disable-ScheduledTask -TaskName "" | Out-Null

#Disable Work Folder tasks
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Work Folders\Work Folders Maintenance Work" | Out-Null

#Disable Windows Store tasks
Disable-ScheduledTask -TaskName "\Microsoft\Windows\WS\Badge Update" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\WS\License Validation" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\WS\Sync Licenses" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\WS\WSRefreshBannedAppsListTask" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\WS\WSTask" | Out-Null

#Disable Windows Update tasks
Disable-ScheduledTask -TaskName "\Microsoft\Windows\WindowsUpdate\AUFirmwareInstall" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\WindowsUpdate\AUScheduledInstall" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\WindowsUpdate\AUSessionConnect" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\WindowsUpdate\Scheduled Start" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\WindowsUpdate\Scheduled Start With Network" | Out-Null

#Disable Windows Error Reporting task
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null

#Disable Windows Defender tasks
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Verification" | Out-Null

#Disable System Restore task
Disable-ScheduledTask -TaskName "\Microsoft\Windows\SystemRestore\SR" | Out-Null

#Disable OneDrive sync tasks
Disable-ScheduledTask -TaskName "\Microsoft\Windows\SkyDrive\Idle Sync Maintenance Task" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\SkyDrive\Routine Maintenance Task" | Out-Null

#Disable indexing task
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Shell\IndexerAutomaticMaintenance" | Out-Null

#Disabe sync tasks
Disable-ScheduledTask -TaskName "\Microsoft\Windows\SettingSync\BackgroundUploadTask" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\SettingSync\BackupTask" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\SettingSync\NetworkStateChangeTask" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Offline Files\Background Synchronization" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Offline Files\Logon Synchronization" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\File Classification Infrastructure\Property Definition Sync" | Out-Null

#Disable Registry Backup task
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Registry\RegIdleBackup" | Out-Null

#Disable Location task
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Location\Notifications" | Out-Null

#Disable File History task
Disable-ScheduledTask -TaskName "\Microsoft\Windows\FileHistory\File History (maintenance mode)" | Out-Null

#Disable Telemetry tasks
Disable-ScheduledTask -TaskName "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Autochk\Proxy" | Out-Null

#Disable SilentCleanup
Disable-ScheduledTask -TaskName "\Microsoft\Windows\DiskCleanup\SilentCleanup" | Out-Null

#Disable Defrag
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null

#Tweak visual effects
write-Host "Tweaking visual effects..."
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 200
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" -Name "DefaultApplied" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" -Name "DefaultApplied" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled" -Name "DefaultApplied" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" -Name "DefaultApplied" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation" -Name "DefaultApplied" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation" -Name "DefaultApplied" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" -Name "DefaultApplied" -Type DWord -Value 0

#No store apps on taskbar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "StoreAppsOnTaskbar" -Type DWord -Value 0

#Windows Explorer Tweaks
#   Set-ItemProperty -Path "" -Name "" -Type String -Value 0
#   Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "" -Type String -Value 0
#   Advanced - HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced

    #Taskbar Small Icons - Enable
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type String -Value 1

    #Explorer Status Bar - Disable
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowStatusBar" -Type String -Value 0

    #Dont Show Favourites in Windows Explorer
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowFavorites" -Type String -Value 0

    #Show File Extensions
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type String -Value 0

    #Disable Aero Shake
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Type String -Value 1

    #Disable AutoPlay
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type String -Value 1

    #Disable Aero Peek
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type String -Value 0

    #Disable Auto Screen Rotation
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation" -Name "Enable" -Type String -Value 0






#Disable Settings Sync
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" -Name "Enabled" -Type String -Value 0

#Delete Metro Applications
$title    = 'Do you want to remove all Metro applications?'
$question = 'Are you sure you want to proceed?'

$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))

$decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
if ($decision -eq 0) {
    write-Host "Removing all metro applications..."
    Get-AppxPackage -AllUsers | Remove-AppxPackage
    Get-AppxPackage | Remove-AppxPackage
    Get-AppxProvisionedPackage –online | Remove-AppxProvisionedPackage –online
} else {
    write-Host "User chose not to remove metro applications"
}

#Remove all Metro Apps
    #write-Host "Removing all metro applications..."
    #Get-AppxPackage -AllUsers | Remove-AppxPackage

#Enable and Disable some optional features

Enable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
#Disable-WindowsOptionalFeature -Online -FeatureName "Xps-Foundation-Xps-Viewer" -NoRestart -WarningAction SilentlyContinue | Out-Null
#Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
#Disable-WindowsOptionalFeature -Online -FeatureName "TelnetServer" -NoRestart -WarningAction SilentlyContinue | Out-Null
#Disable-WindowsOptionalFeature -Online -FeatureName "TelnetClient" -NoRestart -WarningAction SilentlyContinue | Out-Null
#Disable-WindowsOptionalFeature -Online -FeatureName "SearchEngine-Client-Package" -NoRestart -WarningAction SilentlyContinue | Out-Null
#Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-MobilePC-LocationProvider-INF" -NoRestart -WarningAction SilentlyContinue | Out-Null
#Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-MobilePC-Client-Premium-Package-net" -NoRestart -WarningAction SilentlyContinue | Out-Null


#Restart Windows Explorer
write-Host "Restarting Windows Explorer..."
Stop-Process -Force -Name "explorer"
Start-Sleep -Milliseconds 500

#Just opens explorer :)
#Start-Process "C:\Windows\explorer.exe"

#   Write-Host "Script will close in 5 seconds..."
#   Start-Sleep -Seconds 5

$title    = 'Do you want to restart your computer?'
$question = ' '

$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))

$decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
if ($decision -eq 0) {
    shutdown -r
} else {
    Write-Host "Script will close in 5 seconds..."
    Start-Sleep -Seconds 5
    exit
}
