[String] $ErrorActionPreference = "SilentlyContinue"
[String] $global:RequiredOSString = "Windows 8.1"

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

function Dark-Mode{
    param(
        [Parameter()]
        [Switch] $Disable,

        [Parameter()]
        [Switch] $Enable
    )
    if($Disable){
        $Host.UI.RawUI.BackgroundColor = "Blue"
        Clear-Host
    }

    if($Enable){
        $Host.UI.RawUI.BackgroundColor = "Black"
        Clear-Host
    }
}

function Get-WindowsVersion{

    $RegistryKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $Name = "ProductName"

    $Value = (Get-ItemProperty -Path $RegistryKey -Name $Name).$Name

    if($Value -match $RequiredOSString){
        return $True
    }

}

Dark-Mode -Enable

if(!(Get-WindowsVersion)){
    Clear
    Write-Host "This script was meant for " -NoNewline
    Write-Host $RequiredOSString -ForegroundColor Cyan -NoNewline
    Write-Host " only!"
}

Get-AppxPackage -AllUsers | ForEach-Object {
    Write-Host "Trying to remove `"" -NoNewline
    Write-Host $_ -ForegroundColor Green -NoNewline
    Write-Host "`" package!"
    Remove-AppxPackage -Package $_ | Out-Null
}
    
$OptionalFeatures = @(
    "WindowsMediaPlayer"
    "NetFx3"
    "LegacyComponents"
    "DirectPlay"
)
$OptionalFeatures | ForEach-Object{
    Write-Host "Trying to enable `"" -NoNewline
    Write-Host $_ -ForegroundColor Green
    Write-Host "`""
    Set-Service -Name wuauserv -StartupType Automatic | Out-Null
    Start-Service -Name wuauserv | Out-Null
    Enable-WindowsOptionalFeature -Online -FeatureName $_ -NoRestart -WarningAction SilentlyContinue | Out-Null
}

$ServiceList = @(
    "LanmanWorkstation"     # Workstation
    "workfolderssvc"        # Work Folders
    "WSService"             # Windows Store Service (WSService)
    "WMPNetworkSvc"         # Windows Media Player Network Sharing Service
    "lfsvc"                 # Windows Location Framework Service
    "MpsSvc"                # Windows Firewall
    "WerSvc"                # Windows Error Reporting Service
    "TabletInputService"    # Touch Keyboard and Handwriting Panel Service
    "SysMain"               # Superfetch
    "svsvc"                 # Spot Verifier
    "SCPolicySvc"           # Smart Card Removal Policy
    "ScDeviceEnum"          # Smart Card Device Enumeration Service
    "SCardSvr"              # Smart Card
    "LanmanServer"          # Server
    "wscsvc"                # Security Center
    "wercplsupport"         # Problem Reports and Solutions Control Panel Support
    "Spooler"               # Print Spooler
    "defragsvc"             # Optimize drives
    "CscService"            # Offline Files
    "wlidsvc"               # Microsoft Account Sign-in Assistant
    "IEEtwCollectorService" # Internet Explorer ETW Collector Service
    "HomeGroupProvider"     # HomeGroup Provider
    "HomeGroupListener"     # HomeGroup Listener
    "fhsvc"                 # File History Service
    "Fax"                   # Fax
    "TrkWks"                # Distributed Link Tracking Client
    "AppReadiness"          # App Readiness
)

$ServiceList | ForEach-Object {
    $Status          = (Get-Service -Name $_).Status
    $StartupType     = (Get-Service -Name $_).StartType
    $CanStop         = (Get-Service -Name $_).CanStop
    $DisplayName     = (Get-Service -Name $_).DisplayName
    $CanShutdown     = (Get-Service -Name $_).CanShutdown

    if($Status -eq "Running"){
        Stop-Service -Name $_ -Force | Out-Null
        Write-Host "Service " -NoNewline
        Write-Host "`"$DisplayName`"" -NoNewline -ForegroundColor Green
        Write-Host " was stopped!"
    }
    if($StartupType -ne "Disabled"){
        Set-Service -Name $_ -StartupType Disabled
        Write-Host "Service " -NoNewline
        Write-Host "`"$DisplayName`"" -NoNewline -ForegroundColor Green
        Write-Host " is disabled now!"
    }
    
}

$ScheduledTasks = @(
    "\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization"
    "\Microsoft\Windows\Work Folders\Work Folders Maintenance Work"
    "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
    "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
    "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup"
    "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
    "\Microsoft\Windows\Windows Defender\Windows Defender Verification"
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
    "\Microsoft\Windows\DiskCleanup\SilentCleanup"
    "\Microsoft\Windows\Defrag\ScheduledDefrag"
    "\Microsoft\Windows\Application Experience\AitAgent"
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
    "\Microsoft\Windows\Application Experience\StartupAppTask"
    "\Microsoft\Windows\ApplicationData\CleanupTemporaryState"
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
    "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
    "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM"
    "\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan for Crash Recovery"
    "\Microsoft\Windows\Data Integrity Scan\Data Integrity Scan"
    "\Microsoft\Windows\Defrag\ScheduledDefrag"
    "\Microsoft\Windows\Diagnosis\Scheduled"
    "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents"
    "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic"
    "\Microsoft\Windows\PerfTrack\BackgroundConfigSurveyor"
    "\Microsoft\Windows\Servicing\StartComponentCleanup"
    "\Microsoft\Windows\Sysmain\HybridDriveCachePrepopulate"
    "\Microsoft\Windows\Sysmain\HybridDriveCacheRebalance"
    "\Microsoft\Windows\Sysmain\WsSwapAssessmentTask"
    "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary"
    "\Microsoft\Windows\WS\License Validation"
    "\Microsoft\Windows\WS\WSTask"
    "\Microsoft\Windows\WS\WSRefreshBannedAppsListTask"
    "\Microsoft\Windows\WS\Sync Licenses"
    "\Microsoft\Windows\WS\Badge Update"
)

$ScheduledTasks | ForEach-Object {

    Disable-ScheduledTask -TaskName $_ | Out-Null
    Write-Host "Scheduled Task " -NoNewline
    Write-Host "`"$_`"" -ForegroundColor Green -NoNewline
    Write-Host " is disabled now!"

}

function Aero-Peek{
    param(
        [Parameter()]
        [Switch] $Disable,
        [Parameter()]
        [Switch] $Enable
    )
    if($Disable){
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
    }
    if($Enable){
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 1
    }
}

function Keyboard-Delay{
    param(
        [Parameter()]
        [Int] $Value = 0
    )
    if(($Value -ge 1) -and ($Value -lt 10)){
        Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value $Value | Out-Null
    }
}

function Hot-Corners{
    param(
        [Parameter()]
        [Switch] $Disable,
        [Parameter()]
        [Switch] $Enable
    )
    if($Disable){
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUI" -Name "DisableCharmsHint" -Type DWord -Value 1 | Out-Null
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUI" -Name "DisableTLCorner" -Type DWord -Value 1 | Out-Null
    }
    if($Enable){
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUI" -Name DisableCharmsHint -Force | Out-Null
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUI" -Name DisableTLCorner -Force | Out-Null
    }
}

function File-History{
    param(
        [Parameter()]
        [Switch] $Disable,
        [Parameter()]
        [Switch] $Enable
    )
    if($Disable){
        if(!(Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory")){
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory" -Name "Disabled" -Type DWord -Value 1
    }
    if($Enable){
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory" -Name Disabled -Force | Out-Null
    }
}

function Consumer-Features{
    param(
        [Parameter()]
        [Switch] $Disable,
        [Parameter()]
        [Switch] $Enable
    )
    if($Disable){
        if (!(Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")){
            New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
    }
    if($Enable){
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name DisableWindowsConsumerFeatures -Force | Out-Null
    }
}

function Open-With{
    param(
        [Parameter()]
        [Switch] $Disable,
        [Parameter()]
        [Switch] $Enable
    )
    if($Disable){
        if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")){
            New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1 | Out-Null
    }
    if($Enable){
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name NoUseStoreOpenWith -Force | Out-Null
    }
}

function Application-Alert{
    param(
        [Parameter()]
        [Switch] $Disable,
        [Parameter()]
        [Switch] $Enable
    )
    if($Disable){
        if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")){
            New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
        } 
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1
    }
    if($Enable){
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name NoNewAppAlert -Force | Out-Null
    }
}

function Lock-Screen{
    param(
        [Parameter()]
        [Switch] $Disable,
        [Parameter()]
        [Switch] $Enable
    )
    if($Disable){
        if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")){
            New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1
    }
    if($Enable){
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name NoLockScreen -Force | Out-Null
    }
}

function SmartScreen{
    param(
        [Parameter()]
        [Switch] $Disable,
        [Parameter()]
        [Switch] $Enable
    )
    if($Disable){
        if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")){
            New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
    }
    if($Enable){
        if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")){
            New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 1
    }
}

function Activity-History{
    param(
        [Parameter()]
        [Switch] $Disable,
        [Parameter()]
        [Switch] $Enable
    )
    if($Disable){
        if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")){
            New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
    }
    if($Enable){
        if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")){
            New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 1
    }
}

function Reduce-Launch{
    param(
        [Parameter()]
        [Switch] $Disable,
        [Parameter()]
        [Switch] $Enable
    )
    if($Disable){
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name StartupDelayInMSec -Force | Out-Null
    }
    if($Enable){
        if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize")){
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Force | Out-Null
        } 
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -Type DWord -Value 0
    }
}

function Store-ApplicationsOnTaskbar{
    param(
        [Parameter()]
        [Switch] $Disable,
        [Parameter()]
        [Switch] $Enable
    )
    if($Disable){
        if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")){
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "StoreAppsOnTaskbar" -Type DWord -Value 0
    }
    if($Enable){
        if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")){
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "StoreAppsOnTaskbar" -Type DWord -Value 1
    }
}

function Explorer-StatusBar{
    param(
        [Parameter()]
        [Switch] $Disable,
        [Parameter()]
        [Switch] $Enable
    )
    if($Disable){
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowStatusBar" -Type DWord -Value 0
    }
    if($Enable){
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowStatusBar" -Type DWord -Value 1
    }
}

function Explorer-Favourites{
    param(
        [Parameter()]
        [Switch] $Disable,
        [Parameter()]
        [Switch] $Enable
    )
    if($Disable){
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowFavorites" -Type DWord -Value 0
    }
    if($Enable){
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowFavorites" -Type DWord -Value 1 
    }
}

function Explorer-AeroShake{
    param(
        [Parameter()]
        [Switch] $Disable,
        [Parameter()]
        [Switch] $Enable
    )
    if($Disable){
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Type DWord -Value 1
    }
    if($Enable){
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Type DWord -Value 0
    }
}

Aero-Peek -Disable
Keyboard-Delay -Value 0
Hot-Corners -Disable
File-History -Disable
Consumer-Features -Disable
Open-With -Disable
Application-Alert -Disable
Lock-Screen -Disable
SmartScreen -Disable
Activity-History -Disable
Reduce-Launch -Enable
Store-ApplicationsOnTaskbar -Disable
Explorer-AeroShake -Disable
Explorer-Favourites -Disable
Explorer-StatusBar -Disable
