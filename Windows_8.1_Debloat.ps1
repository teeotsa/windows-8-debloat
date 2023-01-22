If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

<#

$Job = Start-Job -ScriptBlock {}
Wait-Job -Id $Job.Id | Out-Null

#>

# Removing AppX Packages
Write-Host 'Removing packages'
$Job = Start-Job -ScriptBlock {
    Get-AppxPackage -AllUsers | Remove-AppxPackage
    Get-ProvisionedAppxPackage -Online | Remove-ProvisionedAppxPackage -Online
}
Wait-Job -Id $Job.Id | Out-Null
Write-Host "Done with packages`n"

# Disable Telemetry
Write-Host 'Disable Telemetry'
$Job = Start-Job -ScriptBlock {
    @("HKLM:\SOFTWARE\Policies\Microsoft\SQMClient", "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows", "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent", "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection") | ForEach-Object {
        If (!(Test-Path $_))
        {
            New-Item -Path $_ -Force | Out-Null
        }
    }
    Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'MaxTelemetryAllowed' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'MaxTelemetryAllowed' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableTailoredExperiencesWithDiagnosticData' -Value 1 -Force-ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
}
Wait-Job -Id $Job.Id | Out-Null
Write-Host "Telemetry should be disabled!`n"

# Disable Windows Error Reporting
Write-Host 'Disable Windows Error Reporting'
$Job = Start-Job -ScriptBlock {
    $Service = Get-Service | ?{$_.DisplayName -match 'Windows Error Reporting'}
    $Service.Stop() | Out-Null
    Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-Service -Name $Service.Name -StartupType Disabled | Out-Null
    Get-ChildItem -Path "$env:ProgramData\Microsoft\Windows\WER" -Force -Recurse | %{ Remove-Item -Path $_.FullName -Force -Recurse | Out-Null }
}
Wait-Job -Id $Job.Id | Out-Null
Write-Host "Windows Error Reporting is disabled!`n"

# Disable Services
Write-Host 'Disable Services'
$Job = Start-Job -ScriptBlock {
    $RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\'
    $List = @(
        # Default Windows Services
        'workfolderssvc','W32Time','WSService','WSearch','WinRM','WMPNetworkSvc','lfsvc','MpsSvc','WbioSrvc'
        'VSS','TabletInputService','Themes','SysMain','svsvc','SCardSvr','ScDeviceEnum','SCPolicySvc'
        'LanmanServer','SensrSvc','wscsvc','RemoteRegistry','QWAVE','PcaSvc','wercplsupport','PrintNotify'
        'Spooler','pla','defragsvc','CscService','NcaSvc','NcbService','smphost','swprv','MsKeyboardFilter'
        'edgeupdatem','edgeupdate','MicrosoftEdgeElevationService','wlidsvc','lltdsvc','iphlpsvc','IEEtwCollectorService'
        'HomeGroupProvider','HomeGroupListener','fhsvc','Fax','WPCSvc','TrkWks','DiagTrack','DsmSvc','VaultSvc'
        'bthserv','BthHFSrv','AppXSvc','AppReadiness','stisvc','WdNisSvc','WcsPlugInService','TapiSrv'
        'WiaRpc','wbengine','Browser','LanmanWorkstation','TrkWks'

        # Drivers & System Services
    )
    Foreach ($ServiceName in $List)
    {
        $CombinedPath = $RegistryPath + $ServiceName
        If (Test-Path $CombinedPath)
        {
            Set-ItemProperty -Path $CombinedPath -Name 'Start' -Value 4 -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
}
# Wait-Job -Id $Job.Id | Out-Null
Write-Host "Useless Services are disabled now! System Reboot is required!`n"

# Disable Scheduled Tasks
Write-Host 'Disable Scheduled Tasks'
$Job = Start-Job -ScriptBlock {
    $Paths = @(
        '\Microsoft\Windows\.NET Framework'
        '\Microsoft\Windows\Active Directory Rights Management Services Client'
        '\Microsoft\Windows\AppID'
        '\Microsoft\Windows\Application Experience'
        '\Microsoft\Windows\ApplicationData'
        '\Microsoft\Windows\AppxDeploymentClient'
        '\Microsoft\Windows\Autochk'
        '\Microsoft\Windows\Chkdsk'
        '\Microsoft\Windows\Customer Experience Improvement Program'
        '\Microsoft\Windows\Data Integrity Scan'
        '\Microsoft\Windows\Defrag'
        '\Microsoft\Windows\Device Setup'
        '\Microsoft\Windows\Diagnosis'
        '\Microsoft\Windows\DiskCleanup'
        '\Microsoft\Windows\DiskDiagnostic'
        '\Microsoft\Windows\DiskFootprint'
        '\Microsoft\Windows\DiskFootprint'
        '\Microsoft\Windows\FileHistory'
        '\Microsoft\Windows\IME'
        '\Microsoft\Windows\Location'
        '\Microsoft\Windows\Maintenance'
        '\Microsoft\Windows\MemoryDiagnostic'
        '\Microsoft\Windows\Mobile Broadband Accounts'
        '\Microsoft\Windows\PerfTrack'
        '\Microsoft\Windows\Offline Files'
        '\Microsoft\Windows\PI'
        '\Microsoft\Windows\Power Efficiency Diagnostics'
        '\Microsoft\Windows\RAC'
        '\Microsoft\Windows\RecoveryEnvironment'
        '\Microsoft\Windows\Registry'
        '\Microsoft\Windows\Servicing'
        '\Microsoft\Windows\SettingSync'
        '\Microsoft\Windows\SkyDrive'
        '\Microsoft\Windows\SoftwareProtectionPlatform'
        '\Microsoft\Windows\SpacePort'
        '\Microsoft\Windows\Sysmain'
        '\Microsoft\Windows\SystemRestore'
        '\Microsoft\Windows\TextServicesFramework'
        '\Microsoft\Windows\Time Synchronization'
        '\Microsoft\Windows\TPM'
        '\Microsoft\Windows\User Profile Service'
        '\Microsoft\Windows\WDI'
        '\Microsoft\Windows\Windows Defender'
        '\Microsoft\Windows\Windows Error Reporting'
        '\Microsoft\Windows\Windows Filtering Platform'
        '\Microsoft\Windows\Windows Media Sharing'
        '\Microsoft\Windows\WindowsColorSystem'
        '\Microsoft\Windows\WindowsUpdate'
        '\Microsoft\Windows\WOF'
        '\Microsoft\Windows\Work Folders'
        '\Microsoft\Windows\Workplace Join'
        '\Microsoft\Windows\WS'
    )
    Foreach ($TaskRoot in $Paths)
    {
        Get-ScheduledTask -TaskPath (-join($TaskRoot,'\')) | %{
            $FullPath = -join($_.TaskPath, '', $_.TaskName)
            Disable-ScheduledTask -TaskName "$FullPath" | Out-Null
        }
    }
}
Wait-Job -Id $Job.Id | Out-Null
Write-Host "Scheduled Tasks disabled!`n"

# Explorer Tweaks
Write-Host 'Explorer Tweaks'
$Job = Start-Job -ScriptBlock {
    # HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'VisualFXSetting' -Value 3

    # HKCU:\Control Panel\Desktop
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'UserPreferencesMask' -Value ([Byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00))
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'DragFullWindows' -Value 3
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'FontSmoothing' -Value 2
    
    # HKCU:\Control Panel\Desktop\WindowMetrics
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'MinAnimate' -Value 0
    
    # HKCU:\Software\Microsoft\Windows\DWM
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'EnableAeroPeek' -Value 0
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'AlwaysHibernateThumbnails' -Value 0

    # HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowInfoTip' -Value 0
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowStatusBar' -Value 0
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'StoreAppsOnTaskba' -Value 0
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ListviewShadow' -Value 0
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarAnimations' -Value 0
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'IconsOnly' -Value 1
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ListviewAlphaSelect' -Value 1

    # HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax' -Name 'DefaultApplied' -Value 0
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation' -Name 'DefaultApplied' -Value 0
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations' -Name 'DefaultApplied' -Value 0
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow' -Name 'DefaultApplied' -Value 0
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow' -Name 'DefaultApplied' -Value 0
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled' -Name 'DefaultApplied' -Value 0
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow' -Name 'DefaultApplied' -Value 0
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation' -Name 'DefaultApplied' -Value 0

    # HKCU:\Control Panel\Accessibility\StickyKeys
    Set-ItemProperty -Path 'HKCU:\Control Panel\Accessibility\StickyKeys' -Name 'Flags' -Value 2

    # HKCU:\Control Panel\Mouse
    Set-ItemProperty -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseSpeed' -Value 0
    Set-ItemProperty -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseThreshold1' -Value 0
    Set-ItemProperty -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseThreshold2' -Value 0

    # Restart Explorer
    Stop-Process -Name 'explorer' | Out-Null
}
Wait-Job -Id $Job.Id | Out-Null
Write-Host "Applied Explorer Tweaks`n"

# Disable Windows Defender
Write-Host 'Disable Windows Defender'
$Job = Start-Job -ScriptBlock {
    Try
    {
        # Enable TLS 1.2 Capabilities
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12  
        $WebClient = New-Object System.Net.WebClient
        $Link = 'https://github.com/M2Team/NSudo/releases/download/8.2/NSudo_8.2_All_Components.zip'

        # Path
        $ArchiveSavePath = [System.IO.Path]::Combine($env:TEMP, $Link.Substring($Link.LastIndexOf('/') + 1))
        $ExpandPath = [System.IO.Path]::Combine($env:TEMP, 'NSudo_Expand')
        $NSudoLauncher = [System.IO.Path]::Combine($ExpandPath, 'NSudo Launcher', 'Win32', 'NSudoLG.exe')

        # Download
        If (!(Test-Path $ArchiveSavePath))
        {
            $WebClient.DownloadFile($Link, $ArchiveSavePath)
        }

        # Expand
        If (!(Test-Path $ExpandPath))
        {
            Expand-Archive -Path $ArchiveSavePath -DestinationPath $ExpandPath -Force | Out-Null
        }

        # Launch
        Start-Process -FilePath "$NSudoLauncher" -ArgumentList '-U:T -P:E -ShowWindowMode:Hide cmd /c sc config WinDefend start= disabled>nul' -Verb RunAs -Wait -WindowStyle Hidden
        Start-Process -FilePath "$NSudoLauncher" -ArgumentList '-U:T -P:E -ShowWindowMode:Hide cmd /c sc config WdNisSvc start= disabled>nul' -Verb RunAs -Wait -WindowStyle Hidden

        # Remove Files
        Remove-Item -Path $ArchiveSavePath -Force -Recurse | Out-Null
        Remove-Item -Path $ExpandPath -Force -Recurse | Out-Null
    }
    Catch
    {
        Exit
    }
}
Wait-Job -Id $Job.Id | Out-Null
Write-Host "Windows Defender is disabled!`n"

# Disable Logs
Write-Host 'Disable Logging'
$Job = Start-Job -ScriptBlock {
    Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger' | %{
        $Name = $_.Name.Replace('HKEY_LOCAL_MACHINE','HKLM:')
        Set-ItemProperty -Path $Name -Name 'Start' -Value 4 -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $Name -Name 'Enabled' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
    }
}
Wait-Job -Id $Job.Id | Out-Null
Write-Host "Logging is disabled!`n"

# Apply System Tweaks
Write-Host 'Tweaking System...'
$Job = Start-Job -ScriptBlock {
    Set-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'HiberbootEnabled' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Control\Session Manager\Memory Management' -Name 'LargeSystemCache' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Control\PriorityControl' -Name 'Win32PrioritySeparation' -Value 0x26 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters' -Name 'EnablePrefetcher' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKLM:\SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters' -Name 'EnableSuperfetch' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null

    # Disable Peernet
    If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Peernet')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Peernet' -Force | Out-Null }
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Peernet' -Name 'Disabled' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null

    # Disable NetCrawling
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'NoNetCrawling' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null

    # Disable Hibernation
    Start-Process -FilePath 'cmd' -ArgumentList '/c powercfg -h off' -Verb 'Runas' -WindowStyle Hidden -Wait
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name 'HibernateEnabled' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null

    # Clear Document Info on Exit
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'ClearRecentDocsOnExit' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null

    # Disable Settings Sync
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync' -Name 'EnableBackupForWin8Apps' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync' -Name 'DisableSettingSync' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null

    # Disable SmartScreen
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen' -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -Value 'Off' -Force -ErrorAction SilentlyContinue | Out-Null

    # Disable Input Data Collection
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' -Name 'RestrictImplicitInkCollection' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' -Name 'RestrictImplicitTextCollection' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null

    # Disable NTFS Encryption
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Policies' -Name 'NtfsDisableEncryption' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null

    # Disable System Restore
    If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore' -Force | Out-Null }
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore' -Name 'DisableConfig' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore' -Name 'DisableSR' -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null

    # File Protection
    If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Windows File Protection')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Windows File Protection' -Force | Out-Null }
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Windows File Protection' -Name SfcScan -Value 0 -ErrorAction SilentlyContinue | Out-Null
    
    # Disable Windows Digital Locker
    If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Digital Locker')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Digital Locker' -Force | Out-Null }
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Digital Locker' -Name DoNotRunDigitalLocker -Value 1 -ErrorAction SilentlyContinue | Out-Null

    # Disable DEP for Windows Explorer
    If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Force | Out-Null }
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name NoDataExecutionPrevention -Value 1 -ErrorAction SilentlyContinue | Out-Null
    
    # Disable File History
    If (!(Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory')) { New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory' -Force | Out-Null }
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory' -Name Disabled -Value 1 -ErrorAction SilentlyContinue | Out-Null

    # Disable Location Stuff
    If (!(Test-Path 'HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors')) { New-Item -Path 'HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors' -Force | Out-Null }
    Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors' -Name DisableLocationScripting -Value 1 -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors' -Name DisableLocation -Value 1 -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors' -Name DisableSensors -Value 1 -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors' -Name DisableWindowsLocationProvider -Value 1 -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Sensors\LocationProvider' -Name CSEnable -Value 0 -ErrorAction SilentlyContinue | Out-Null

    # Disable Remote Desktop
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name fAllowFullControl -Value 0 -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name fAllowToGetHelp -Value 0 -ErrorAction SilentlyContinue | Out-Null

    # Configure Windows Update
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name AUOptions -Value 0 -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name CachedAUOptions -Value 0 -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name IncludeRecommendedUpdates -Value 0 -ErrorAction SilentlyContinue | Out-Null
    
    # Disable EdgeUI Corners
    If (!(Test-Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUi')) { New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUi' -Force | Out-Null }
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUi' -Name DisableTLCorner -Value 1 -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUi' -Name DisableTRCorner -Value 1 -ErrorAction SilentlyContinue | Out-Null

    # Disable Tracking
    If (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\Tracing')) { New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Tracing' -Force | Out-Null }
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Tracing' -Name EnableConsoleTracing -Value 0 -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Tracing' -Name EnableFileTracing -Value 0 -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Tracing' -Name EnableAutoFileTracing -Value 0 -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name Start_TrackDocs -Value 0 -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name Start_TrackProgs -Value 0 -ErrorAction SilentlyContinue | Out-Null
}
Wait-Job -Id $Job.Id | Out-Null
Write-Host "System has been tweaked!`n"

Write-Warning 'You should restart your system now!'

[System.Console]::ReadKey()

Exit
