#This script should get you around 30 processes also 500mb ram

#Windows 8.1 Required
#Atleast build 9600

$ErrorActionPreference = 'SilentlyContinue'
$wshell = New-Object -ComObject Wscript.Shell
$Button = [System.Windows.MessageBoxButton]::YesNoCancel
$ErrorIco = [System.Windows.MessageBoxImage]::Error
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

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

$Processes = @(
"SystemSettings"
"SystemSettingsAdminFlows"
"TiWorker"
"TrustedInstaller"
"WmiPrvSE"
"mobsync"
"PresentationFontCache"
"SMSvcHost"
)

foreach ($Pro in $Processes) {
    Stop-Process -Name $Pro -Force -PassThru -ErrorAction SilentlyContinue
}

$Services = @(
"wuauserv"
"WSearch"
"LanmanWorkstation"
"MpsSvc"
"Fax"
"TabletInputService"
"SysMain"
"LanmanServer"
"Spooler"
"iphlpsvc"
"HomeGroupProvider"
"HomeGroupListener"
"TrkWks"
"WwanSvc"
"WlanSvc"
"dot3svc"
"W32Time"
"WSService"
"WerSvc"
#"WinDefend" | You need to use NSudo to disable Windows Defender
#"WdNisSvc" | Same here, NSudo is needed to disable this service
"WebClient"
"VSS"
"vds"
"TapiSrv"
"StorSvc"
"svsvc"
"SCPolicySvc"
"ScDeviceEnum"
"SCardSvr"
"SensrSvc"
"wscsvc"
"RemoteRegistry"
"TermService"
"UmRdpService"
"SessionEnv"
"RasMan"
"RasAuto"
"PrintNotify"
"CscService"
"defragsvc"
"Netlogon"
"smphost"
"swprv"
"MsKeyboardFilter"
"MSiSCSI"
"wlidsvc"
"fhsvc"
"WPCSvc"
"DPS"
"WdiServiceHost"
"WdiSystemHost"
"DeviceAssociationService"
"bthserv"
"BthHFSrv"
"BDESVC"
"W3SVC"
"WAS"
"FontCache3.0.0.0"
"WMPNetworkSvc"
"lfsvc"
#"Wecsvc"
"w3logsvc"
"seclogon"
"QWAVE"
"wercplsupport"
"MSMQ"
"IEEtwCollectorService"
"hkmsvc"

#TCP Services
"NetTcpPortSharing"
"NetTcpActivator"
"NetPipeActivator"
"NetMsmqActivator"


)

#Stop-Service -InputObject Name -Confirm -Force -PassThru -ErrorAction SilentlyContinue

foreach ($s in $Services) {
Get-Service -Name $s -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled
write-Host "$s has been disabled" 
$running = Get-Service -Name $service -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'}
    if ($running) { 
        Stop-Service -InputObject $service -Confirm -Force -PassThru -ErrorAction SilentlyContinue
        #write-Host "$s has been stopped"
    }
}

#Registry Tweaks
Write-Host "Now, registry tweaks!"

#Disable Active Corners
$ActiveCorner = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUI"
if (!(Test-Path $ActiveCorner)){
    New-Item $ActiveCorner
    Start-Sleep -Milliseconds 200
    Set-ItemProperty -Path $ActiveCorner -Name "DisableCharmsHint" -Type DWord -Value 1
    Set-ItemProperty -Path $ActiveCorner -Name "DisableTLCorner" -Type DWord -Value 1
} else {
    Set-ItemProperty -Path $ActiveCorner -Name "DisableCharmsHint" -Type DWord -Value 1
    Set-ItemProperty -Path $ActiveCorner -Name "DisableTLCorner" -Type DWord -Value 1
}


#Disable File Histroy
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory" -ItemType DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory" -Name "Disabled" -Type DWord -Value 1
write-Host "File History should be disabled now"

#Disable Consumer Features
$ConsumerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
if (!(Test-Path $ConsumerPath)){
    write-Host "Consumer Features key directory not found... Script will make new key for that"
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    Start-Sleep -Milliseconds 200
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
} else {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
}

#No Use Open With
$NoUseWithPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
if (!(Test-Path $NoUseWithPath)){
    write-Host "No Use With key directory not found... Script will make new key for that"
    New-Item $NoUseWithPath
    Start-Sleep -Milliseconds 200
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
} else {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
}

#No New App Alert
$NoNewAppAlertPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
if (!(Test-Path $NoNewAppAlertPath)){
    write-Host "No New App Alert key directory not found... Script will make new key for that"
    New-Item $NoNewAppAlertPath
    Start-Sleep -Milliseconds 200
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1
} else {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1
}


#No LockScreen
$NoLockScreenPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
if (!(Test-Path $NoLockScreenPath)){
    write-Host "No Lock Screen key directory not found... Script will make new key for that"
    New-Item $NoLockScreenPath
    Start-Sleep -Milliseconds 200
    Set-ItemProperty -Path $NoLockScreenPath -Name "NoLockScreen" -Type DWord -Value 1
} else {
    Set-ItemProperty -Path $NoLockScreenPath -Name "NoLockScreen" -Type DWord -Value 1
}

#No Application Backups
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "EnableBackupForWin8Apps" -Type DWord -Value 0

#Disable Infrared Stuff
Set-ItemProperty -Path "HKCU:\Control Panel\Infrared\Global" -Name "ShowTrayIcon" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Infrared\File Transfer" -Name "AllowSend" -Type DWord -Value 0

#Disable Smart Screen
$DisableSmartScreen = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (!(Test-Path $DisableSmartScreen)){
    write-Host "Smart Screen key directory not found... Script will make new key for that"
    New-Item $DisableSmartScreen
    Start-Sleep -Milliseconds 200
    Set-ItemProperty -Path $DisableSmartScreen -Name "EnableSmartScreen" -Type DWord -Value 0
} else {
    Set-ItemProperty -Path $DisableSmartScreen -Name "EnableSmartScreen" -Type DWord -Value 0
}

#No Activity History
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0

#Disable Anti Spyware (No Windows Defender)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1

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
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1

    #Explorer Status Bar - Disable
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowStatusBar" -Type DWord -Value 0

    #Dont Show Favourites in Windows Explorer
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowFavorites" -Type DWord -Value 0

    #Show File Extensions
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

    #Disable Aero Shake
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Type DWord -Value 1

    #Disable AutoPlay
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1

    #Disable Aero Peek
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0

    #Disable Auto Screen Rotation
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation" -Name "Enable" -Type DWord -Value 0



#Disable Settings Sync
$DisableSettingsSyncing = "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync"
if (!(Test-Path $DisableSettingsSyncing)){
    write-Host "Settings Sync key directory not found... Script will make new key for that"
    New-Item $DisableSettingsSyncing
    Start-Sleep -Milliseconds 200
    Set-ItemProperty -Path $DisableSettingsSyncing -Name "Enabled" -Type DWord -Value 0
} else {
    Set-ItemProperty -Path $DisableSettingsSyncing -Name "Enabled" -Type DWord -Value 0
}

#Delete Metro Applications
write-Host "Trying to remove all metro applications..."
Get-AppxPackage -AllUsers | Remove-AppxPackage
Get-AppxPackage | Remove-AppxPackage
Get-AppxProvisionedPackage –online | Remove-AppxProvisionedPackage –online

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

#Disable AppX service and tasks
Get-Service -Name "AppXSvc" -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled
Stop-Service -InputObject "AppXSvc" -Force -PassThru -ErrorAction SilentlyContinue
Disable-ScheduledTask -TaskName "\Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup" | Out-Null


#Restart Windows Explorer
write-Host "Restarting Windows Explorer..."
Stop-Process -Name "explorer" -Force -PassThru
Start-Sleep -Milliseconds 500

<#

Clean folders, You can uncomment this section

$CacheDeleteFile = @"
@echo off
title Cleaning...
color 0a
cd %windir%\SoftwareDistribution
del /f/q/s *
cd %windir%\Prefetch
del /f/q/s *
cd %temp%
del /f/q/s *
cd %windir%\Temp
del /f/q/s *
"@
$CurrentUser = $env:UserName
$Path = "C:\Users\$CurrentUser\Appdata\Local\Temp\CacheCleanup.bat"
New-Item -Path $Path -Value $CacheDeleteFile -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Start-Process -FilePath $Path -PassThru -Wait

#>

#PowerShell output will be cleared
Clear-Host

$title    = 'Do you want to restart your computer?'
$question = ' '

$choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
$choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))

$decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
if ($decision -eq 0) {
    shutdown -r
    exit
} else {
    exit
}

