Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

$ErrorActionPreference = 'SilentlyContinue'
$wshell = New-Object -ComObject Wscript.Shell
$Button = [System.Windows.MessageBoxButton]::YesNoCancel
$ErrorIco = [System.Windows.MessageBoxImage]::Error
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

Clear-Host

#Some Form settings
$WindowsUpdateLabelLeft = 295
$SystemTweaksLeft = 40

$Form                            = New-Object system.Windows.Forms.Form
$Form.ClientSize                 = New-Object System.Drawing.Point(1050,700)
$Form.text                       = "Windows 8 Debloater GUI"
$Form.StartPosition              = "CenterScreen"
$Form.TopMost                    = $false
$Form.BackColor                  = [System.Drawing.ColorTranslator]::FromHtml("#FFFFFF")
$Form.AutoScaleDimensions        = '192, 192'
$Form.AutoSize                   = $False
$Form.ClientSize                 = '340, 380'
$Form.FormBorderStyle            = 'Fixed3D'

$TweaksLabel                     = New-Object system.Windows.Forms.Label
$TweaksLabel.text                = "Tweaks"
$TweaksLabel.AutoSize            = $true
$TweaksLabel.width               = 25
$TweaksLabel.height              = 10
$TweaksLabel.location            = New-Object System.Drawing.Point(80,11)
$TweaksLabel.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',24)

$SystemTweaks                    = New-Object system.Windows.Forms.Button
$SystemTweaks.text               = "System Tweaks"
$SystemTweaks.width              = 204
$SystemTweaks.height             = 30
$SystemTweaks.location           = New-Object System.Drawing.Point($SystemTweaksLeft,56)
$SystemTweaks.Font               = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$MinimalTweaks                   = New-Object system.Windows.Forms.Button
$MinimalTweaks.text              = "Minimal Tweaks"
$MinimalTweaks.width             = 204
$MinimalTweaks.height            = 30
$MinimalTweaks.location          = New-Object System.Drawing.Point($SystemTweaksLeft,96)
$MinimalTweaks.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$OtherSystemTweaks               = New-Object system.Windows.Forms.Label
$OtherSystemTweaks.text          = "Other System Tweaks"
$OtherSystemTweaks.AutoSize      = $true
$OtherSystemTweaks.width         = 25
$OtherSystemTweaks.height        = 10
$OtherSystemTweaks.location      = New-Object System.Drawing.Point(15,145)
$OtherSystemTweaks.Font          = New-Object System.Drawing.Font('Microsoft Sans Serif',20)

$RemoveBloatware                 = New-Object system.Windows.Forms.Button
$RemoveBloatware.text            = "Remove Bloatware"
$RemoveBloatware.width           = 204
$RemoveBloatware.height          = 30
$RemoveBloatware.location        = New-Object System.Drawing.Point($SystemTweaksLeft,186)
$RemoveBloatware.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$VisualEffects                   = New-Object system.Windows.Forms.Button
$VisualEffects.text              = "Visual Tweaks"
$VisualEffects.width             = 204
$VisualEffects.height            = 30
$VisualEffects.location          = New-Object System.Drawing.Point($SystemTweaksLeft,226)
$VisualEffects.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$Information                     = New-Object system.Windows.Forms.Label
$Information.text                = "Press 'Minimal Tweaks' if you want to use most
of the Windows 8.1 features like
Windows Update, Store and Metro Apps
Press 'System Tweaks' if you want
to fully debloat Windows and 
disable alot of features"
$Information.AutoSize            = $true
$Information.width               = 25
$Information.height              = 10
$Information.location            = New-Object System.Drawing.Point(10,270)
$Information.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',10)

$Form.controls.AddRange(@($Information,$SystemTweaks,$MinimalTweaks,$TweaksLabel,$RemoveBloatware,$OtherSystemTweaks,$VisualEffects))

function RestartWindowsExplorer{

    write-Host "Restarting Windows Explorer..."
    Stop-Process -Name "explorer" -PassThru -Force -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep -Milliseconds 500

}

$SystemTweaks.Add_Click({
    write-Host "Killing some processes before starting script..."
    $Processes = @(
        "TabTip"
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
        Stop-Process -Name $Pro -Force -PassThru -ErrorAction SilentlyContinue | Out-Null
        write-Host "$Pro has been killed!"
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
        "WinDefend"
        "WdNisSvc"
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
        "Wecsvc"
        "w3logsvc"
        "seclogon"
        "QWAVE"
        "wercplsupport"
        "MSMQ"
        "IEEtwCollectorService"
        "hkmsvc"
        "WinHttpAutoProxySvc"
        "NetTcpPortSharing"
        "NetTcpActivator"
        "NetPipeActivator"
        "NetMsmqActivator"
        "lmhosts"
        "IKEEXT"
    )
    foreach ($Services in $Services) {
        Get-Service -Name $Services -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled
        write-Host "$Services has been disabled" 
        $running = Get-Service -Name $Services -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'}
            if ($running) { 
                Stop-Service -Name $Services -Force -PassThru -ErrorAction SilentlyContinue | Out-Null 
                write-Warning "$Services has been stopped"
            }
    }

    #Disable Active Corners & Charms Bar
    #This might not work with Windows 8.1 
    $ActiveCorner = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUI"
    if (!(Test-Path $ActiveCorner)){
        New-Item $ActiveCorner
        Start-Sleep -Milliseconds 200
    }
    Set-ItemProperty -Path $ActiveCorner -Name "DisableCharmsHint" -Type DWord -Value 1
    Set-ItemProperty -Path $ActiveCorner -Name "DisableTLCorner" -Type DWord -Value 1
    write-Host "Hot cornesr and Charms Bar has been disabled"
    #Disable File Histroy
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory")){
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory" -Name "Disabled" -Type DWord -Value 1
    write-Host "File History should be disabled now"
    #Disable Consumer Features
    $ConsumerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    if (!(Test-Path $ConsumerPath)){
        write-Host "Consumer Features key directory not found... Script will make new key for that"
        New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
    write-Host "Consumer Features should be disabled now"
    #No Use Open With
    $NoUseWithPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    if (!(Test-Path $NoUseWithPath)){
        write-Host "No Use With key directory not found... Script will make new key for that"
        New-Item $NoUseWithPath -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
    write-Host "Open With prompts should be disabled now"
    #No New App Alert
    $NoNewAppAlertPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    if (!(Test-Path $NoNewAppAlertPath)){
        write-Host "No New App Alert key directory not found... Script will make new key for that"
        New-Item $NoNewAppAlertPath -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1
    write-Host "No new application prompts should be disabled now"
    #No LockScreen
    $NoLockScreenPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    if (!(Test-Path $NoLockScreenPath)){
        write-Host "No Lock Screen key directory not found... Script will make new key for that"
        New-Item $NoLockScreenPath -Force | Out-Null
    }
    Set-ItemProperty -Path $NoLockScreenPath -Name "NoLockScreen" -Type DWord -Value 1
    write-Host "Lock Screen has been disabled"
    #No Application Backups
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync")){
        write-Host "Application Backup key not found, script will make it for you..."
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
        write-Host "Smart Screen key directory not found... Script will make new key for that"
        New-Item $DisableSmartScreen -Force | Out-Null
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
    #Launch Apps Faster
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Force | Out-Null
    } 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -Type DWord -Value 0
    write-Host "You should be able to launch applications faster now"
    #Disable Windows Error Reporting
    if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting")){
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
    write-Host "Windows Error Reporting has been disbaled"
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Type DWord -Value 1
    write-Host "Aero Shake disabled"
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
    write-Host "Auto Play disabled"
    if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation")){
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation" -Name "Enable" -Type DWord -Value 0
    write-Host "Auto Rotation disabled"
    #Disable Settings Sync
    $DisableSettingsSyncing = "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync"
    if (!(Test-Path $DisableSettingsSyncing)){
        write-Host "Settings Sync key directory not found... Script will make new key for that"
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
    "\Microsoft\Windows\SystemRestore\SR"
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
    foreach ($ScheduledTasks in $ScheduledTasks){
        Disable-ScheduledTask -TaskName $ScheduledTasks | Out-Null -ErrorAction SilentlyContinue
    }
    write-Host "'Scheduled Tasks' should be disabled now!"
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

    RestartWindowsExplorer
    Clear-Host
    write-Host "Tweaks are done!"
})

$MinimalTweaks.Add_Click({
    $MinimalServices = @(
    "Wecsvc"
    "LanmanWorkstation"
    "WerSvc"
    "TabletInputService"
    "SysMain"
    "Fax"
    "svsvc"
    "LanmanServer"
    "SCardSvr"
    "wscsvc"
    "Spooler"
    "wlidsvc" #needed for Microsoft Account
    "HomeGroupProvider"
    "HomeGroupListener"
    "fhsvc"
    "TrkWks"
    "VaultSvc"
    )
    foreach($Service in $MinimalServices) {
        write-Host "Trying to disable $Service"
        Stop-Service -Name $Service -Force -PassThru -ErrorAction SilentlyContinue | Out-Null
        Set-Service -Name $Service -StartupType Disabled -PassThru -ErrorAction SilentlyContinue | Out-Null
    }
    write-Host "Trying to enable some 'Optional Features'"
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
    $ScheduledTasks = @(
    "\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization"
    "\Microsoft\Windows\Work Folders\Work Folders Maintenance Work"
    "\Microsoft\Windows\WS\Badge Update"
    "\Microsoft\Windows\WS\License Validation"
    "\Microsoft\Windows\WS\Sync Licenses"
    "\Microsoft\Windows\WS\WSRefreshBannedAppsListTask"
    "\Microsoft\Windows\WS\WSTask"
    "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
    "\Microsoft\Windows\SystemRestore\SR"
    "\Microsoft\Windows\Shell\IndexerAutomaticMaintenance"
    "\Microsoft\Windows\SettingSync\BackgroundUploadTask"
    "\Microsoft\Windows\SettingSync\BackupTask"
    "\Microsoft\Windows\SettingSync\NetworkStateChangeTask"
    "\Microsoft\Windows\Offline Files\Background Synchronization"
    "\Microsoft\Windows\Offline Files\Logon Synchronization"
    "\Microsoft\Windows\File Classification Infrastructure\Property Definition Sync"
    "\Microsoft\Windows\Location\Notifications"
    "\Microsoft\Windows\FileHistory\File History (maintenance mode)"
    "\Microsoft\Windows\FileHistory\File History"
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"
    "\Microsoft\Windows\Autochk\Proxy"
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
    "\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan"
    "\Microsoft\Windows\Defrag\ScheduledDefrag"
    "\Microsoft\Windows\Diagnosis\Scheduled"
    "\Microsoft\Windows\Maintenance\WinSAT"
    "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents"
    "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic"
    "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser"
    "\Microsoft\Windows\MUI\LPRemove"
    "\Microsoft\Windows\PerfTrack\BackgroundConfigSurveyor"
    "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
    "\Microsoft\Windows\RAC\RacTask"
    "\Microsoft\Windows\Servicing\StartComponentCleanup"
    "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask"
    "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon"
    "\Microsoft\Windows\Sysmain\HybridDriveCachePrepopulate"
    "\Microsoft\Windows\Sysmain\HybridDriveCacheRebalance"
    "\Microsoft\Windows\Sysmain\WsSwapAssessmentTask"
    )
    foreach ($ScheduledTasks in $ScheduledTasks){
        Disable-ScheduledTask -TaskName $ScheduledTasks | Out-Null -ErrorAction SilentlyContinue
    }
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Force | Out-Null
    } 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -Type DWord -Value 0
    RestartWindowsExplorer
    Clear-Host 
    write-Host "Minimal tweaks are done!"
})

$RemoveBloatware.Add_Click({
    $StartService = "AppXSvc"
    #Set Service to automatic
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppXSvc" -Name "Start" -Type DWord -Value 2
    Get-Service -Name $StartService | Start-Service -Verbose RunAs -PassThru
    Clear-Host
    write-Host "Trying to remove all Metro applications..."
    Get-AppxPackage -AllUsers | Remove-AppxPackage 
    Get-AppxPackage | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online
    write-Host "Permanently remove Metro applications, you wont be able to recover any of those applications!"
    $ProgramFile = "$env:ProgramFiles\WindowsApps"
    $Folders = Get-ChildItem -Path $ProgramFile | ForEach-Object{
        takeown /f $_.FullName 
        Remove-Item -Path $_.FullName -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
    }
    write-Host "Script will now Disable 'AppXSvc' service! "
    #HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AppXSvc
    #2 - Automatic
    #4 - Disabled
    #Set Service to Disabled
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppXSvc" -Name "Start" -Type DWord -Value 4
    Stop-Service -Name AppXSvc -Force -PassThru -ErrorAction SilentlyContinue | Out-Null
    Clear-Host
    RestartWindowsExplorer
    write-Host "All 'Metro' applications should be gone now!"
})

$VisualEffects.Add_Click({
    write-Host "Tweaking visual effects..."
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
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\DWM")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\DWM" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowStatusBar" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowFavorites" -Type DWord -Value 0
    #Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Type DWord -Value 1
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "StoreAppsOnTaskbar" -Type DWord -Value 0
    #Disable -shortcut text
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
    #No store apps on taskbar
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "StoreAppsOnTaskbar" -Type DWord -Value 0
    write-Host "Store apps on taskbar should be disabled now"
    Clear-Host 
    RestartWindowsExplorer
    write-Host "Visual Effects applied!"
})

[void]$Form.ShowDialog()