#************************************************
#  This script is made only for Windows 8/8.1
#  Script was made by Teeotsa
#  Github : https://github.com/teeotsa
#************************************************              
#  Info : This version of Windows 8 Debloater GUI
#  is remade and optimized! Please dont use
#  older version of GUI debloater scripts
#  If you have any issues or questions, please
#  contact me via discord (Teeotsa#6167)
#************************************************

# --------------------------------------- #
# ------------ Documentation ------------ #
# --------------------------------------- #


# * Windows NT Versions *
#   5.0 = Windows XP
#   6.0 = Windows Vista
#   6.1 = Windows 7
#   6.2 = Windows 8 RTM
#   6.3 = Windows 8.1
#   10 = Windows 10
# ***********************


# * How to update your PowerShell 4.0 to 5.1? *
#  Its easy. First download updates from https://aka.ms/wmf5download and run them. After that just wait and restart your
#  system. Now you should have PowerShell 5.1
#  Note : This is only possible for : Windows Server 2012 R2, Windows Server 2012, Windows Server 2008 R2 SP1, Windows 8.1, Windows 7 SP1
#  Also you need Windows Update service to be running!
    


# Useful Links : **********************************************************************************************************************
# learn about formstyles here : https://docs.microsoft.com/en-us/dotnet/api/system.windows.forms.formborderstyle?view=net-5.0
# learn about windows nt versions here : https://docs.microsoft.com/en-us/windows/win32/msi/operating-system-property-values
# hex colors : https://www.color-hex.com/
#------------------------------------------------#
# you can download nsudo from their github
# nsudo github : https://github.com/M2Team/NSudo
#------------------------------------------------#
# guide on how to disable services : https://www.tenforums.com/tutorials/4499-start-stop-disable-services-windows-10-a.html
# updates for powershell 5.1 : https://aka.ms/wmf5download

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

# Check NT Version.
# Update 1 : Made this part of the script better and smaller :D

$WinMajor = [System.Environment]::OSVersion.Version.ToString()
if (!($WinMajor -match "6.3.*.*")){
    Clear-Host
    write-Host "This script is not made for your system! Please use Windows 8/8.1"
    pause
    exit
}

#=======================
#  Log system 
#=======================

$Desktop = "$env:SystemDrive\Users\$env:UserName\Desktop";
if (!(Test-Path "$Desktop\debloat_log.txt")){
    New-Item -Path "$Desktop\debloat_log.txt" -Force | Out-Null
}

function logAdd{
    if ($args -eq $null){ return };
    $SystemTime = Get-Date -DisplayHint Time;
    Add-Content -Path "$Desktop\debloat_log.txt" "[$SystemTime] $args"
}

#=======================
#  Custom Functions
#=======================

#This function will make restore point for C drive if function is called
function createRestorePoint
{
    Clear-Host
    write-Host "Making Restore Point before starting the script!"
    Enable-ComputerRestore -Drive "C:\"
    Checkpoint-Computer -Description "RestorePoint1" -RestorePointType "MODIFY_SETTINGS" | Out-Null
    logAdd "Restore point made"
    Start-Sleep -Seconds 2
}

function restartExplorer
{
    Stop-Process -Name "explorer" -Force -PassThru -ErrorAction SilentlyContinue | Out-Null
    logAdd "'Windows Explorer' restarted"
    Start-Sleep -Seconds 2

    #This will start Windows Explorer if havent started itself
    $Explorer = Get-Process -Name "explorer"
    if (!($Explorer)){
        Start-Process -FilePath "explorer"
    }
}


# Prompt Lines
# Update 1 : Made it better, no foreach loop anymore :'D
$Lines = @"
This script is made only for Windows 8/8.1 (Tablets / Hybrids / Laptops)
Script was made by Teeotsa
Github : https://github.com/teeotsa
    
Info : This version of Windows 8 Debloater
made for Tablets, Laptops or any kindof 
hybrids you use! 
   
If you have any issues or questions, please
contact me via discord (Teeotsa#6167).
"@;
Write-Host $Lines

$Form                            = New-Object system.Windows.Forms.Form
$Form.ClientSize                 = New-Object System.Drawing.Point(1050,700)
$Form.text                       = "Windows 8 Debloater GUI"
$Form.StartPosition              = "CenterScreen"
$Form.TopMost                    = $false
$Form.BackColor                  = [System.Drawing.ColorTranslator]::FromHtml("#DDDDDD")
$Form.AutoScaleDimensions        = '192, 192'
$Form.AutoSize                   = $False
$Form.ClientSize                 = '550, 400'
$Form.FormBorderStyle            = 'SizableToolWindow'

#===================
#  System Tweaks
#===================

$TweaksLabel                     = New-Object system.Windows.Forms.Label
$TweaksLabel.text                = "System Tweaks"
$TweaksLabel.AutoSize            = $true
$TweaksLabel.width               = 25
$TweaksLabel.height              = 05
$TweaksLabel.location            = New-Object System.Drawing.Point(10,10)
$TweaksLabel.Font                = New-Object System.Drawing.Font('Microsoft Sans Serif',25)

$Label2                          = New-Object system.Windows.Forms.Label
$Label2.text                     = "Disable Services/Tasks etc..."
$Label2.AutoSize                 = $true
$Label2.width                    = 25
$Label2.height                   = 10
$Label2.location                 = New-Object System.Drawing.Point(50,55)
$Label2.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',09)

$ExtremeTweaks                   = New-Object system.Windows.Forms.Button
$ExtremeTweaks.text              = "Extreme Tweaks"
$ExtremeTweaks.width             = 204
$ExtremeTweaks.height            = 30
$ExtremeTweaks.location          = New-Object System.Drawing.Point(25,80)
$ExtremeTweaks.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$MinimalTweaks                   = New-Object system.Windows.Forms.Button
$MinimalTweaks.text              = "Minimal Tweaks"
$MinimalTweaks.width             = 204
$MinimalTweaks.height            = 30
$MinimalTweaks.location          = New-Object System.Drawing.Point(25,120)
$MinimalTweaks.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',12)

$RemoveBloatware                 = New-Object system.Windows.Forms.Button
$RemoveBloatware.text            = "Remove Bloatware"
$RemoveBloatware.width           = 204
$RemoveBloatware.height          = 30
$RemoveBloatware.location        = New-Object System.Drawing.Point(25,160)
$RemoveBloatware.Font            = New-Object System.Drawing.Font('Microsoft Sans Serif',12)


#===================
#  Visual Tweaks
#===================


$Label3                          = New-Object system.Windows.Forms.Label
$Label3.text                     = "Visual Tweaks"
$Label3.AutoSize                 = $true
$Label3.width                    = 25
$Label3.height                   = 10
$Label3.location                 = New-Object System.Drawing.Point(280,10)
$Label3.Font                     = New-Object System.Drawing.Font('Microsoft Sans Serif',25)

$TweakVisualFX                   = New-Object system.Windows.Forms.Button
$TweakVisualFX.text              = "Visual FX"
$TweakVisualFX.width             = 204
$TweakVisualFX.height            = 30
$TweakVisualFX.location          = New-Object System.Drawing.Point(290,80)
$TweakVisualFX.Font              = New-Object System.Drawing.Font('Microsoft Sans Serif',12)


$Form.controls.AddRange(@($TweaksLabel,$ExtremeTweaks,$Label2,$MinimalTweaks,$RemoveBloatware,$Label3,$TweakVisualFX))

#===================
#  Button Functions
#===================

$ExtremeTweaks.Add_Click({

    #========================================================
    #  Create restore point before starting the script
    #========================================================

    createRestorePoint

    #======================
    #  Services part now
    #======================

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


    #==========================================
    #  Disable/Stop Services listed above
    #==========================================

    foreach($Service in $Services){
        Get-Service -Name $Service | Set-Service -StartupType Disabled
        $Running = Get-Service -Name $Service | Where-Object{$_.Status -eq "Running"}
        logAdd "'$Service' was disabled!"
        if ($Running){
            Write-Warning "'$Service' was running, trying to stop it now!"
            logAdd "'$Service' has been stopped"
            Stop-Service -Name $Service -Force -PassThru -ErrorAction SilentlyContinue | Out-Null
        }
    }

    #===================================
    #  Registry Tweaks Now
    #===================================

    # 'Disable' hot corners and charms bar in Windows. For some reason
    # this does not work quite well in Windows 8.1. Ive tried alot of thing
    # and it just wont work! But im still gonna keep it here
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUI")){
        New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUI" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUI" -Name "DisableCharmsHint" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUI" -Name "DisableTLCorner" -Type DWord -Value 1
    write-Host "'Hot Corners' and 'Charms Bar' has been disabled (Atleast they should be disabled now)";
    logAdd "'Hot Corners' has been disabled"

    # Disable File Histroy
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory")){
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\FileHistory" -Name "Disabled" -Type DWord -Value 1
    write-Host "'File History' should be disabled now"
    logAdd "'File History' should be disabled now"

    # Disable Consumer Features, kindof telemetry. Safe to disable
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")){
        New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
    write-Host "'Consumer Features' should be disabled now"
    logAdd "'Consumer Features' should be disabled now"

    # No Use Open With dialog
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")){
        New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
    write-Host "'Open With' prompts should be disabled now"
    logAdd "'Open With' prompts should be disabled now"

    # No New App Alert, might not work with Windows 8.0
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")){
        New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force |  Out-Null
    } 
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1
    write-Host "'No New Application' prompts should be disabled now"
    logAdd "'No New Application' prompts should be disabled now"

    # No LockScreen (Disable Lock Screen)
    # You should be able to re-enable it via Immersive Control Panel. If not, you
    # can always remove/delete this registry key. Path is : 'HKEY_LOCAL_MACHINE:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")){
        New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1
    write-Host "Lock Screen has been disabled"
    logAdd "Lock Screen has been disabled"

    # No Application Backups (I guess its application data backups, but who knows?) Anyways, safe to disable if
    # you wish to use Metro applications
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync")){
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync" -Name "EnableBackupForWin8Apps" -Type DWord -Value 0
    write-Host "Application backups has been disabled"
    logAdd "Metro Application backups has been disabled"

    # Disable Infrared Stuff (Who does even use Infrared on their computers these days? :'D)
    if (!(Test-Path "HKCU:\Control Panel\Infrared\Global")){
        New-Item "HKCU:\Control Panel\Infrared\Global" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Control Panel\Infrared\Global" -Name "ShowTrayIcon" -Type DWord -Value 0
    if (!(Test-Path "HKCU:\Control Panel\Infrared\File Transfer")){
        New-Item "HKCU:\Control Panel\Infrared\File Transfer" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Control Panel\Infrared\File Transfer" -Name "AllowSend" -Type DWord -Value 0
    write-Host "Infrared should be disabled now"
    logAdd "Infrared should be disabled now"

    # Disable Smart Screen (It should be Internet Explorer's smartscreen only) This needs some testing
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")){
        New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
    write-Host "'Smartscreen' is disabled now"
    logAdd "'Smartscreen' is disabled now"

    # No Activity History (System wont save/store search and run dialog texts after this 'tweak'. Atleast shouldn't)
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")){
        New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
    write-Host "Activity History is disabled"
    logAdd "Activity History is disabled"

    # Disable Anti Spyware (Disable Windows Defender, might not work if you update your system because updates include new
    # version of Windows Defender. I haven't tested new one out yet and i won't. You can disable newer versions of Windows
    # defender with NSudo. Just download NSudo from their github : "https://github.com/M2Team/NSudo". After your done with it
    # run NSudo and tick "Enable All Premissions" checkbox, and type "service.msc" in there. After that you should know
    # how to disable service.)
    if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows Defender")){
        New-Item "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWord -Value 1
    write-Host "Windows Defender should be disabled now (via Registry)"
    logAdd "Windows Defender should be disabled now (via Registry)"

    # Disable -shortcut text
    # If you tried to make any shortcuts in the past, you saw that "-shortcut" text. Well, this tweak will disable it
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Type Binary -Value ([byte[]](00,00,00,00))
    write-Host "-shortcut text on shortcuts has been disabled"
    logAdd "-shortcut text on shortcuts has been disabled"

    # Remove Shortcut Arrows on any shortcuts on your system
    if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons")){
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Name "29" -Type String -Value ""
    write-Host "Shortcut arrows are disabled"
    logAdd "Shortcut arrows are disabled"

    # Launch Apps Faster
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Force | Out-Null
    } 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -Type DWord -Value 0
    #restarts Windows Explorer, function above
    restartExplorer
    write-Host "You should be able to launch applications faster now"
    logAdd "You should be able to launch applications faster now"

    # Disable Windows Error Reporting (Telemetry)
    if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting")){
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
    write-Host "Windows Error Reporting has been disbaled"
    logAdd "Windows Error Reporting has been disbaled"

    # No store apps on taskbar, this will hide all running metro apps from your taskbar
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "StoreAppsOnTaskbar" -Type DWord -Value 0
    write-Host "Store apps on taskbar should be disabled now"
    logAdd "Store apps on taskbar should be disabled now"

    # Taskbar Small Icons. System will use small taskbar icons/small taskbar
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1
    restartExplorer
    write-Host "You should now have Small Taskbar Icons"
    logAdd "Small Taskbar Icons are enabled now"


    # Windows Explorer Status Bar - Disabled (Hide Windows Explorers Status Bar, its that white annoying bar with almost nothing on it)
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowStatusBar" -Type DWord -Value 0
    write-Host "Status Bar from Explorer is gone now"
    logAdd "Status Bar from Explorer is gone now"

    # Hide Favourites from Windows Explorer (Useless category)
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowFavorites" -Type DWord -Value 0
    write-Host "Favourites is gone from Explorer now"
    logAdd "Favourites is gone from Explorer now"

    # This will show you File Extensions, useful
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0
    write-Host "You will be able to see file extensions now"
    logAdd "You will be able to see file extensions now"

    # Disable Aero Shake. If you shake your windows on top of other windows, they will be minimized and its kinda annoying
    # This tweak will disable this feature. If you wish to use it, you can remove this registry key or enable this feature
    # from control panel
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Type DWord -Value 1
    Write-Host "Aero Share is disabled"
    logAdd "Aero Share is disabled"

    # Disable AutoPlay. If you plug USB Storage Device in your computer, you wont be promoted to open it right away
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1
    write-Host "AutoPlay is disabled"
    logAdd "AutoPlay is disabled"

    # Disable AeroPeek. You should disable this feature on low-end computers. Previews of windows wont be moving/running if you want to peek
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\DWM")){
        New-Item -Path "HKCU:\Software\Microsoft\Windows\DWM" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
    write-Host "AeroPeek is disabled now"
    logAdd "AeroPeek is disabled now"

    # Disable Auto Screen Rotation. Random registry tweak i found. Could be useful on tablets/hybrids?
    if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation")){
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation" -Name "Enable" -Type DWord -Value 0
    Write-Host "Auto Screen Rotation is disabled now"
    logAdd "Auto Screen Rotation is disabled now"

    # Disable Settings Sync. I think its like syncing your wallpapers and system settings with Microsoft Accounts. If so, you should disable it
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync")){
        New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" -Name "Enabled" -Type DWord -Value 0
    write-Host "Settings Sync has been disabled"
    logAdd "Settings Sync has been disabled"

    #===============================
    #  Scheduled Tasks
    #===============================

    # Disable Scheduled Tasks
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
        #"\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork" :: This can mess up your Internet Connection if you
        # disable this scheduled task! So it should be enabled
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
        Disable-ScheduledTask -TaskName $ScheduledTasks -ErrorAction SilentlyContinue | Out-Null 
        write-Host "Trying to disable '$ScheduledTasks'"
        logAdd "Scheduled Task : '$ScheduledTasks' has been disabled"
    }

    #=================================
    #  Optional Features 
    #=================================

    $OptionalFeatures = @(
        "WindowsMediaPlayer"
        "NetFx3"
        "LegacyComponents"
        "DirectPlay"
    )

    # Script will enable and start Windows Update service if it has been disabled, because
    # Windows Update is needed for optional features!
    $WindowsUpdateService = Get-Service -Name "wuauserv"
    if ($WindowsUpdateService.StartType -eq "Disabled"){
        Write-Warning "Windows Update service wasn't running. Script will enable and start it!"
        $WindowsUpdateService | Set-Service -StartupType Automatic 
        $WindowsUpdateService | Start-Service 
    }
    foreach ($OptionalFeatures in $OptionalFeatures){
        $Feature = Get-WindowsOptionalFeature -Online -FeatureName $OptionalFeatures | Out-Null
        if ($Feature.State -eq "Disabled"){
            Enable-WindowsOptionalFeature -Online -FeatureName $OptionalFeatures -NoRestart | Out-Null
        }
    }

})

$MinimalTweaks.Add_Click({

    #=================================
    #  Services 
    #=================================

    $Services = @(
    "LanmanWorkstation"
    "workfolderssvc"
    "WinHttpAutoProxySvc"
    "WSService"
    "WMPNetworkSvc"
    "lfsvc"
    "MpsSvc"
    "WerSvc"
    "TabletInputService"
    "lmhosts"
    "SysMain"
    "svsvc"
    "sppsvc"
    "SCPolicySvc"
    "ScDeviceEnum"
    "SCardSvr"
    "LanmanServer"
    "wscsvc"
    "seclogon"
    "RemoteRegistry"
    "Spooler"
    "QWAVE"
    "wercplsupport"
    "wlidsvc"
    "iphlpsvc"
    "IKEEXT"
    "HomeGroupProvider"
    "HomeGroupListener"
    "Fax"
    "fhsvc"
    "TrkWks"
    "WdiSystemHost"
    "WdiServiceHost"
    "DPS"
    "VaultSvc"
    )

    foreach($Services in $Services){
        Get-Service -Name $Services | Set-Service -StartupType Disabled
        $Running = Get-Service -Name $Services | Where-Object{$_.Status -eq "Running"}
        logAdd "'$Services' has been disabled"
        if ($Running){
            Write-Warning "'$Services' was running, trying to stop it now!"
            Stop-Service -Name $Services -Force -PassThru -ErrorAction SilentlyContinue | Out-Null
            logAdd "'$Services' has been stopped"
        }
    }

    #===============================
    #  Scheduled Tasks
    #===============================

    # Disable Scheduled Tasks
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
        #"\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork" :: This can mess up your Internet Connection if you
        # disable this scheduled task! So it should be enabled
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
        Disable-ScheduledTask -TaskName $ScheduledTasks -ErrorAction SilentlyContinue | Out-Null 
        write-Host "Trying to disable '$ScheduledTasks'"
        logAdd "Scheduled task : '$ScheduledTasks' has been disabled"
    }

    #=================================
    #  Optional Features 
    #=================================

    $OptionalFeatures = @(
        "WindowsMediaPlayer"
        "NetFx3"
        "LegacyComponents"
        "DirectPlay"
    )

    # Script will enable and start Windows Update service if it has been disabled, because
    # Windows Update is needed for optional features!
    $WindowsUpdateService = Get-Service -Name "wuauserv"
    if ($WindowsUpdateService.StartType -eq "Disabled"){
        Write-Warning "Windows Update service wasn't running. Script will enable and start it!"
        $WindowsUpdateService | Set-Service -StartupType Automatic 
        $WindowsUpdateService | Start-Service 
        logAdd "'Windows Update' services was disabled! Script enabled them for you"
    }
    foreach ($OptionalFeatures in $OptionalFeatures){
        $Feature = Get-WindowsOptionalFeature -Online -FeatureName $OptionalFeatures | Out-Null
        if ($Feature.State -eq "Disabled"){
            Enable-WindowsOptionalFeature -Online -FeatureName $OptionalFeatures -NoRestart | Out-Null
            logAdd "Optional Feature : '$OptionalFeatures' has been enabled"
        }
    }
})

$RemoveBloatware.Add_Click({

    <#

    Bloatware list is not complete right now! I have to update is sometime in the future

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
    #>
    #foreach($Bloat in $Bloatware){

        Get-AppxPackage | Remove-AppxPackage 
        Get-AppxPackage -AllUsers | Remove-AppxPackage 
        Get-AppxProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online
        logAdd "Removing all bloatware..."
        #write-Host "Trying to remove '$Bloat'"
    
    #}

})

$TweakVisualFX.Add_Click({

    Clear-Host
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
    #Makes your keyboard faster & better to use
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

})

[void]$Form.ShowDialog()

<#
Some script templates, maybe you need them!



This will enable all disabled Optional Features, saves alot of time
*=====================================================================================================*
$OptionalFeatures = @(
    "WindowsMediaPlayer"
    "NetFx3"
    "LegacyComponents"
    "DirectPlay"
)
foreach ($OptionalFeatures in $OptionalFeatures){
    $Feature = Get-WindowsOptionalFeature -Online -FeatureName $OptionalFeatures | Out-Null
    if ($Feature.State -eq "Disabled"){
        Enable-WindowsOptionalFeature -Online -FeatureName $OptionalFeatures -NoRestart | Out-Null
    }
}
*=====================================================================================================*

#>
