
# List of Rubish windows apps to uninstall, to view installed apps use 'Get-AppxPackage -AllUsers'

$uwpRubbishApps = @(
    "Microsoft.Messaging",
    "king.com.CandyCrushSaga",
    "Microsoft.BingNews",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.People",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.YourPhone",
    "Microsoft.MicrosoftOfficeHub",
    "Fitbit.FitbitCoach",
    "4DF9E0F8.Netflix",
    "Microsoft.GetHelp")

 # List of choclatey application to install. 
 # See https://chocolatey.org for more applications.

$Apps = @(
    "7zip.install",
    "git",
    "gitkracken",
    "microsoft-edge",
    "golang",
    "googlechrome",
    "vlc",
    "virtualbox",
    "docker-desktop",
    "dotnetcore-sdk",
    "wget",
    "openssl",
    "jetbrainstoolbox",
    "vscode",
    "visualstudio2019professional",
    "sysinternals",
    "sublimetext3.app",
    "linqpad",
    "fiddler",
    "postman",
    "nuget.commandline",
    "beyondcompare",
    "nodejs-lts",
    "nodejs",
    "awscli",
    "azure-cli",
    "powershell-core")

function CheckUserIsAdmin() { 
    
    Write-Host "Cheeck that the user has administration rights" -ForegroundColor Green
    Write-Host "------------------------------------" -ForegroundColor Green 

    if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) 
    { 
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; 
        exit 
    }
}


function ShowHiddenFile()
{
    param([Switch]$Off)
    
    $value = -not $Off.IsPresent
    Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced `
    -Name Hidden -Value $value -type DWORD

    $shell = New-Object -ComObject Shell.Application
    $shell.Windows() |
        Where-Object { $_.document.url -eq $null } |
        ForEach-Object { $_.Refresh() }
} 

function ShowFileExtensions()
{
    Push-Location
    Set-Location HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
    Set-ItemProperty . HideFileExt "0"
    Pop-Location
    Stop-Process -processName: Explorer -force
}

function Check-Command($cmdname) {
    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
}

function DisableACPowerSleep() {
    Write-Host "Disable Sleep on AC Power..." -ForegroundColor Green
    Write-Host "------------------------------------" -ForegroundColor Green
    Powercfg /Change monitor-timeout-ac 20
    Powercfg /Change standby-timeout-ac 0
}

function AddThisPcIcon() {
    Write-Host ""
    Write-Host "Add 'This PC' Desktop Icon..." -ForegroundColor Green
    Write-Host "------------------------------------" -ForegroundColor Green

    $thisPCIconRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
    $thisPCRegValname = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" 
    $item = Get-ItemProperty -Path $thisPCIconRegPath -Name $thisPCRegValname -ErrorAction SilentlyContinue

    if ($item) { 
        Set-ItemProperty  -Path $thisPCIconRegPath -name $thisPCRegValname -Value 0  
    } 
    else { 
        New-ItemProperty -Path $thisPCIconRegPath -Name $thisPCRegValname -Value 0 -PropertyType DWORD | Out-Null  
    } 
}

function RemoveRubishApps() {
    Write-Host "Removing UWP Rubbish..." -ForegroundColor Green
    Write-Host "------------------------------------" -ForegroundColor Green
    foreach ($uwp in $uwpRubbishApps) {
        Get-AppxPackage -Name $uwp | Remove-AppxPackage
    }
}

function InstallIIS() {

    Write-Host ""
    Write-Host "Installing IIS..." -ForegroundColor Green
    Write-Host "------------------------------------" -ForegroundColor Green

    Enable-WindowsOptionalFeature -Online -FeatureName IIS-DefaultDocument -All
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionDynamic -All
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionStatic -All
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebSockets -All
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationInit -All
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET45 -All
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-ServerSideIncludes
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-BasicAuthentication
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WindowsAuthentication
}

function EnableDeveloperMode() {

    Write-Host ""
    Write-Host "Enable Windows 10 Developer Mode..." -ForegroundColor Green
    Write-Host "------------------------------------" -ForegroundColor Green

    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /t REG_DWORD /f /v "AllowDevelopmentWithoutDevLicense" /d "1"
}

function EnableRemoteDesktop() {

    Write-Host ""
    Write-Host "Enable Remote Desktop..." -ForegroundColor Green
    Write-Host "------------------------------------" -ForegroundColor Green

    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\" -Name "fDenyTSConnections" -Value 0
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name "UserAuthentication" -Value 1
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
}

function InstallChoco() {
    if (Check-Command -cmdname 'choco') {
        Write-Host "Choco is already installed, skip installation."
    }
    else {
        Write-Host ""
        Write-Host "Installing Chocolate for Windows..." -ForegroundColor Green
        Write-Host "------------------------------------" -ForegroundColor Green
        Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
}

function InstallChocoApps() {

    Write-Host ""
    Write-Host "Installing Applications..." -ForegroundColor Green
    Write-Host "------------------------------------" -ForegroundColor Green

    foreach ($app in $Apps) {
        choco install $app -y
    }
}

function EnableWSL() {
    
    dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
    dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
    
    curl.exe -L -o wsl_update_x64.msi https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi
    . \wsl_update_x64.msi
    wsl --set-default-version 2
}

function InstallUbuntuSubsystem() { 
    
    curl.exe -L -o ubuntu-1804.appx https://aka.ms/wsl-ubuntu-1804
    Rename-Item ubuntu-1804.appx ubuntu-1804.zip
    Expand-Archive ubuntu-1804.zip ubuntu
    $userenv = [System.Environment]::GetEnvironmentVariable("Path", "User")
    [System.Environment]::SetEnvironmentVariable("PATH", $userenv + (get-location) + "\ubuntu", "User")
    .\ubuntu\ubuntu1804.exe
}

function Audit($message) {
    $Time=Get-Date 
    $message="$Time : $message `n" 
    $message | out-file C:\logs\audit.log -append
    Write-Host $message
}

try {
    # check the user is an admin
    CheckUserIsAdmin
    Audit("log folder created")
    
    # create new directory for logging
    Write-Host "Create new directory for logging the script" -ForegroundColor Green
    Write-Host "------------------------------------" -ForegroundColor Green 
    
    New-Item -ItemType Directory -Force -Path C:\logs
    Audit("log folder created")

    # show all hidden files in explorer
    Show-HiddenFile
    Audit("Hiden files revealed")

    # show all file extentsions in explorer
    ShowFileExtensions
    Audit("file extensions")

    # disable power sleep on AC power
    DisableACPowerSleep
    Audit("AC Power Sleep Disabled")

    # add 'This PC icon' to desktop
    AddThisPcIcon
    Audit("'This PC' icon added")

    # remove all rubish appx pre-installed apps
    RemoveRubishApps
    Audit("Removed rubbish pre-installed appx")

    # install IIS components on windows
    InstallIIS
    Audit("IIS components installed")

    # enable windows developer mode
    EnableDeveloperMode
    Audit("Windows Developer mode enabled")

    # enable remote desktop
    EnableRemoteDesktop
    Audit("Remote Desktop Enabled")

    # install choclatey
    InstallChoco
    Audit("Choclatey Installed")

    # install application with choclatey
    InstallChocoApps
    Audit("Applications List installed with choclatey")

    # Enable WSL 
    EnableWSL
    Audit("WSL enabled")

    InstallUbuntuSubsystem
    Audit("Ubuntu System installed")

    Write-Host "------------------------------------" -ForegroundColor Green
    Read-Host -Prompt "Setup is done, restart is needed, press [ENTER] to restart computer."
    Restart-Computer
}
catch 
{
    $Time = Get-Date
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    $message="$Time : $ErrorMessage $FailedItem `n"
    $message | out-file C:\logs\errors.log -append
    Write-Host $message

}
finally 
{
    Exit $LASTEXITCODE
}