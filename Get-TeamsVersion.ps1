Param(
    [string]$Path,
    [string]$Computer,
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$SkipModuleCheck
)
<#
        .SYNOPSIS
        Get Microsoft Teams Desktop Version

        .DESCRIPTION
        This function returns the installed Microsoft Teams desktop version for each user profile.

        .NOTES
        Version:    2.3
        Author:     David Paulino
        Info:       https://uclobby.com/2018/08/23/teams-check-client-version-using-powershell

        .PARAMETER Path
        Specify the path with Teams Log Files

        .PARAMETER Computer
        Specify the remote computer

        .PARAMETER Credential
        Specify the credential to be used to connect to the remote computer

        .EXAMPLE
        PS> Get-UcTeamsVersion

        .EXAMPLE
        PS> Get-UcTeamsVersion -Path C:\Temp\

        .EXAMPLE
        PS> Get-UcTeamsVersion -Computer workstation124

        .EXAMPLE
        PS> $cred = Get-Credential
        PS> Get-UcTeamsVersion -Computer workstation124 -Credential $cred
    #>
function Get-UcArch([string]$sFilePath) {
    <#
        .SYNOPSIS
        Funcion to get the Architecture from .exe file

        .DESCRIPTION
        Based on PowerShell script Get-ExecutableType.ps1 by David Wyatt, please check the complete script in:

        Identify 16-bit, 32-bit and 64-bit executables with PowerShell
        https://gallery.technet.microsoft.com/scriptcenter/Identify-16-bit-32-bit-and-522eae75

        .PARAMETER FilePath
        Specifies the executable full file path.

        .EXAMPLE
        PS> Get-UcArch -FilePath C:\temp\example.exe
    #>
    try {
        $stream = New-Object System.IO.FileStream(
            $sFilePath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read )
        $exeType = 'Unknown'
        $bytes = New-Object byte[](4)
        if ($stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin) -eq 0x3C -and $stream.Read($bytes, 0, 4) -eq 4) {
            if (-not [System.BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes, 0, 4) }
            $peHeaderOffset = [System.BitConverter]::ToUInt32($bytes, 0)

            if ($stream.Length -ge $peHeaderOffset + 6 -and
                $stream.Seek($peHeaderOffset, [System.IO.SeekOrigin]::Begin) -eq $peHeaderOffset -and
                $stream.Read($bytes, 0, 4) -eq 4 -and
                $bytes[0] -eq 0x50 -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0 -and $bytes[3] -eq 0) {
                $exeType = 'Unknown'
                if ($stream.Read($bytes, 0, 2) -eq 2) {
                    if (-not [System.BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes, 0, 2) }
                    $machineType = [System.BitConverter]::ToUInt16($bytes, 0)
                    switch ($machineType) {
                        0x014C { $exeType = 'x86' }
                        0x8664 { $exeType = 'x64' }
                    }
                }
            }
        }
        return $exeType
    }
    catch {
        return "Unknown"
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Test-UcElevatedPrivileges {
    if (!(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))) {
        return $false
    }
    return $true
}

$regexVersion = '("version":")([0-9.]*)'
$regexRing = '("ring":")(\w*)'
$regexEnv = '("environment":")(\w*)'
$regexCloudEnv = '("cloudEnvironment":")(\w*)'

$regexWindowsUser = '("upnWindowUserUpn":")([a-zA-Z0-9@._-]*)'
$regexTeamsUserName = '("userName":")([a-zA-Z0-9@._-]*)'

#20240309 - REGEX to get New Teams version from log file DesktopApp: Version: 23202.1500.2257.3700
$regexNewVersion = '(DesktopApp: Version: )(\d{5}.\d{4}.\d{4}.\d{4})'

$outTeamsVersion = [System.Collections.ArrayList]::new()

if ($Path) {
    if (Test-Path $Path -ErrorAction SilentlyContinue) {
        #region Teams Classic Path
        $TeamsSettingsFiles = Get-ChildItem -Path $Path -Include "settings.json" -Recurse
        foreach ($TeamsSettingsFile in $TeamsSettingsFiles) {
            $TeamsSettings = Get-Content -Path $TeamsSettingsFile.FullName
            $Version = ""
            $Ring = ""
            $Env = ""
            $CloudEnv = ""
            try {
                $VersionTemp = [regex]::Match($TeamsSettings, $regexVersion).captures.groups
                if ($VersionTemp.Count -ge 2) {
                    $Version = $VersionTemp[2].value
                }
                $RingTemp = [regex]::Match($TeamsSettings, $regexRing).captures.groups
                if ($RingTemp.Count -ge 2) {
                    $Ring = $RingTemp[2].value
                }
                $EnvTemp = [regex]::Match($TeamsSettings, $regexEnv).captures.groups
                if ($EnvTemp.Count -ge 2) {
                    $Env = $EnvTemp[2].value
                }
                $CloudEnvTemp = [regex]::Match($TeamsSettings, $regexCloudEnv).captures.groups
                if ($CloudEnvTemp.Count -ge 2) {
                    $CloudEnv = $CloudEnvTemp[2].value
                }
            }
            catch { }
            $TeamsDesktopSettingsFile = $TeamsSettingsFile.Directory.FullName + "\desktop-config.json"
            if (Test-Path $TeamsDesktopSettingsFile -ErrorAction SilentlyContinue) {
                $TeamsDesktopSettings = Get-Content -Path $TeamsDesktopSettingsFile
                $WindowsUser = ""
                $TeamsUserName = ""
                $RegexTemp = [regex]::Match($TeamsDesktopSettings, $regexWindowsUser).captures.groups
                if ($RegexTemp.Count -ge 2) {
                    $WindowsUser = $RegexTemp[2].value
                }
                $RegexTemp = [regex]::Match($TeamsDesktopSettings, $regexTeamsUserName).captures.groups
                if ($RegexTemp.Count -ge 2) {
                    $TeamsUserName = $RegexTemp[2].value
                }
            }
            $TeamsVersion = New-Object -TypeName PSObject -Property @{
                WindowsUser      = $WindowsUser
                TeamsUser        = $TeamsUserName
                Type             = "Teams Classic"
                Version          = $Version
                Ring             = $Ring
                Environment      = $Env
                CloudEnvironment = $CloudEnv
                Path             = $TeamsSettingsFile.Directory.FullName
            }
            $TeamsVersion.PSObject.TypeNames.Insert(0, 'TeamsVersionFromPath')
            $outTeamsVersion.Add($TeamsVersion) | Out-Null
        }
        #endregion
        #region New Teams Path
        $TeamsSettingsFiles = Get-ChildItem -Path $Path -Include "tma_settings.json" -Recurse
        foreach ($TeamsSettingsFile in $TeamsSettingsFiles) {
            if (Test-Path $TeamsSettingsFile -ErrorAction SilentlyContinue) {
                $NewTeamsSettings = Get-Content -Path $TeamsSettingsFile | ConvertFrom-Json
                $tmpAccountID = $NewTeamsSettings.primary_user.accounts.account_id
                try {
                    $Version = ""
                    $MostRecentTeamsLogFile = Get-ChildItem -Path $TeamsSettingsFile.Directory.FullName -Include "MSTeams_*.log" -Recurse | Sort-Object -Property CreationTime -Descending | Select-Object -First 1
                    $TeamLogContents = Get-Content $MostRecentTeamsLogFile
                    $RegexTemp = [regex]::Match($TeamLogContents, $regexNewVersion).captures.groups
                    if ($RegexTemp.Count -ge 2) {
                        $Version = $RegexTemp[2].value
                    }
                }
                catch {}

                $TeamsVersion = New-Object -TypeName PSObject -Property @{
                    WindowsUser      = "NA"
                    TeamsUser        = $NewTeamsSettings.primary_user.accounts.account_upn
                    Type             = "New Teams"
                    Version          = $Version
                    Ring             = $NewTeamsSettings.tma_ecs_settings.$tmpAccountID.ring
                    Environment      = $NewTeamsSettings.tma_ecs_settings.$tmpAccountID.environment
                    CloudEnvironment = $NewTeamsSettings.primary_user.accounts.cloud
                    Path             = $TeamsSettingsFile.Directory.FullName
                }
                $TeamsVersion.PSObject.TypeNames.Insert(0, 'TeamsVersionFromPath')
                [void]$outTeamsVersion.Add($TeamsVersion)
            }
        }
        #endregion
    }
    else {
        Write-Error -Message ("Invalid Path, please check if path: " + $path + " is correct and exists.")
    }
}
else {
    $currentDateFormat = [cultureinfo]::CurrentCulture.DateTimeFormat.ShortDatePattern
    if ($Computer) {
        $RemotePath = "\\" + $Computer + "\C$\Users"
        $ComputerName = $Computer
        if ($Credential) {
            if ($Computer.IndexOf('.') -gt 0) {
                $PSDriveName = $Computer.Substring(0, $Computer.IndexOf('.')) + "_TmpTeamsVersion"
            }
            else {
                $PSDriveName = $Computer + "_TmpTeamsVersion"
            }
            New-PSDrive -Root $RemotePath -Name $PSDriveName -PSProvider FileSystem -Credential $Credential | Out-Null
        }

        if (Test-Path -Path $RemotePath) {
            $Profiles = Get-ChildItem -Path $RemotePath -ErrorAction SilentlyContinue
        }
        else {
            Write-Error -Message ("Error: Cannot get users on " + $computer + ", please check if name is correct and if the current user has permissions.")
        }
    }
    else {
        $ComputerName = $Env:COMPUTERNAME
        $Profiles = Get-childItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object { Get-ItemProperty $_.pspath } | Where-Object { $_.fullprofile -eq 1 }
        $newTeamsFound = $false
    }
   
    foreach ($UserProfile in $Profiles) {
        if ($Computer) {
            $ProfilePath = $UserProfile.FullName
            $ProfileName = $UserProfile.Name
        }
        else {
            $ProfilePath = $UserProfile.ProfileImagePath
            #20231013 Added exception handeling, only known case is when a windows profile was created when the machine was joined to a previous domain.
            try {
                $ProfileName = (New-Object System.Security.Principal.SecurityIdentifier($UserProfile.PSChildName)).Translate( [System.Security.Principal.NTAccount]).Value
            }
            catch {
                $ProfileName = "Unknown Windows User"
            }
        }
        #region classic teams
        #20241030 - We will only add an entry if the executable exists.
        $TeamsApp = $ProfilePath + "\AppData\Local\Microsoft\Teams\current\Teams.exe"
        if (Test-Path -Path $TeamsApp) {
            $TeamsSettingPath = $ProfilePath + "\AppData\Roaming\Microsoft\Teams\settings.json"
            if (Test-Path $TeamsSettingPath -ErrorAction SilentlyContinue) {
                $TeamsSettings = Get-Content -Path $TeamsSettingPath
                $Version = ""
                $Ring = ""
                $Env = ""
                $CloudEnv = ""
                try {
                    $VersionTemp = [regex]::Match($TeamsSettings, $regexVersion).captures.groups
                    if ($VersionTemp.Count -ge 2) {
                        $Version = $VersionTemp[2].value
                    }
                    $RingTemp = [regex]::Match($TeamsSettings, $regexRing).captures.groups
                    if ($RingTemp.Count -ge 2) {
                        $Ring = $RingTemp[2].value
                    }
                    $EnvTemp = [regex]::Match($TeamsSettings, $regexEnv).captures.groups
                    if ($EnvTemp.Count -ge 2) {
                        $Env = $EnvTemp[2].value
                    }
                    $CloudEnvTemp = [regex]::Match($TeamsSettings, $regexCloudEnv).captures.groups
                    if ($CloudEnvTemp.Count -ge 2) {
                        $CloudEnv = $CloudEnvTemp[2].value
                    }
                }
                catch { }
                $TeamsInstallTimePath = $ProfilePath + "\AppData\Roaming\Microsoft\Teams\installTime.txt"
                #20240228 - In some cases the install file can be missing.
                $tmpInstallDate = ""
                if (Test-Path $TeamsInstallTimePath -ErrorAction SilentlyContinue) {
                    $InstallDateStr = Get-Content ($ProfilePath + "\AppData\Roaming\Microsoft\Teams\installTime.txt")
                    $tmpInstallDate = [Datetime]::ParseExact($InstallDateStr, 'M/d/yyyy', $null) | Get-Date -Format $currentDateFormat
                }
            
                $TeamsVersion = New-Object -TypeName PSObject -Property @{
                    Computer         = $ComputerName
                    Profile          = $ProfileName
                    ProfilePath      = $ProfilePath
                    Type             = "Teams Classic"
                    Version          = $Version
                    Ring             = $Ring
                    Environment      = $Env
                    CloudEnvironment = $CloudEnv
                    Arch             = Get-UcArch $TeamsApp
                    InstallDate      = $tmpInstallDate
                }
                $TeamsVersion.PSObject.TypeNames.Insert(0, 'TeamsVersion')
                [void]$outTeamsVersion.Add($TeamsVersion)
            }
        }
        #endregion

        #region New Teams
        #20241028 - Running this in Windows 10 with PowerShell 7 an exception could be raised while importing the Appx PowerShell module. Thank you Steve Chupack for reporting this issue.
        $newTeamsLocation = ""
        if ($Computer) {
            $newTeamsLocation = Get-ChildItem -Path ( $RemotePath + "\..\Program Files\Windowsapps" ) -Filter "ms-teams.exe" -Recurse -Depth 1 | Sort-Object -Property CreationTime -Descending | Select-Object -First 1
        }
        else {
            #If running as Administrator then we can search instead, this is to prevent using Get-AppPackage MSTeams -AllUser which also requires Administrator
            if (Test-UcElevatedPrivileges) {
                $newTeamsLocation = Get-ChildItem -Path "C:\Program Files\Windowsapps" -Filter "ms-teams.exe" -Recurse -Depth 1 | Sort-Object -Property CreationTime -Descending | Select-Object -First 1
            }
            else {
                try {
                    #Checking if the module is already loaded
                    if (!(Get-Module Appx)) {
                        Import-Module Appx
                    }
                }
                catch [System.PlatformNotSupportedException] {
                    Import-Module Appx -UseWindowsPowerShell
                }
                $TeamsAppPackage = Get-AppPackage MSTeams
                if ($TeamsAppPackage) {
                    $newTeamsInstallPath = $TeamsAppPackage.InstallLocation + ".\ms-teams.exe"
                    $newTeamsLocation = Get-ItemProperty -Path ($newTeamsInstallPath)
                }
            }
        }
        if ($newTeamsLocation) {
            if (Test-Path -Path $newTeamsLocation.FullName -ErrorAction SilentlyContinue) {
                $tmpRing = ""
                $tmpEnvironment = ""
                $tmpCloudEnvironment = ""
                $NewTeamsSettingPath = $ProfilePath + "\AppData\Local\Publishers\8wekyb3d8bbwe\TeamsSharedConfig\tma_settings.json"
                if (Test-Path $NewTeamsSettingPath -ErrorAction SilentlyContinue) {
                    try {
                        $NewTeamsSettings = Get-Content -Path $NewTeamsSettingPath | ConvertFrom-Json
                        $tmpAccountID = $NewTeamsSettings.primary_user.accounts.account_id
                        $tmpRing = $NewTeamsSettings.tma_ecs_settings.$tmpAccountID.ring
                        $tmpEnvironment = $NewTeamsSettings.tma_ecs_settings.$tmpAccountID.environment
                        $tmpCloudEnvironment = $NewTeamsSettings.primary_user.accounts.cloud
                    }
                    catch {}
                }
                $TeamsVersion = New-Object -TypeName PSObject -Property @{
                    Computer         = $ComputerName
                    Profile          = $ProfileName
                    ProfilePath      = $ProfilePath
                    Type             = "New Teams"
                    Version          = $newTeamsLocation.VersionInfo.ProductVersion
                    Ring             = $tmpRing
                    Environment      = $tmpEnvironment
                    CloudEnvironment = $tmpCloudEnvironment
                    Arch             = Get-UcArch $newTeamsLocation.FullName
                    InstallDate      = $newTeamsLocation.CreationTime | Get-Date -Format $currentDateFormat
                }
                $TeamsVersion.PSObject.TypeNames.Insert(0, 'TeamsVersion')
                [void]$outTeamsVersion.Add($TeamsVersion)
                $newTeamsFound = $true
            }
        }
        #endregion
    }
    if ($Credential -and $PSDriveName) {
        try {
            Remove-PSDrive -Name $PSDriveName -ErrorAction SilentlyContinue
        }
        catch {}
    }
}

if (!(Test-UcElevatedPrivileges) -and !($Computer) -and !($newTeamsFound)) {
    Write-Warning "No New Teams versions found, please try again with elevated privileges (Run as Administrator)"
}
return $outTeamsVersion | Format-Table Computer, Profile, ProfilePath, Arch, Type, Version, Environment, Ring, InstallDate 
