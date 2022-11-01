<#
.DESCRIPTION
	This script returns the installed MS Teams Version for each user profile.

.NOTES
  Version      	   		: 1.3
  Author    			: David Paulino
  Info                  : https://uclobby.com/2018/08/23/teams-check-client-version-using-powershell

#>


# Funcion to get the Architecture from .exe file
#
# Based on PowerShell script Get-ExecutableType.ps1 by David Wyatt, please check the complete script in:
#
# Identify 16-bit, 32-bit and 64-bit executables with PowerShell
# https://gallery.technet.microsoft.com/scriptcenter/Identify-16-bit-32-bit-and-522eae75
    Param(
        [string]$Path,
        [string]$Computer
    )


function Get-UcArch([string]$sFilePath)
{
try
    {
        $stream = New-Object System.IO.FileStream(
        $sFilePath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read )
        $exeType = 'Unknown'
        $bytes = New-Object byte[](4)
        if ($stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin) -eq 0x3C -and $stream.Read($bytes, 0, 4) -eq 4)
        {
            if (-not [System.BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes, 0, 4) }
            $peHeaderOffset = [System.BitConverter]::ToUInt32($bytes, 0)

            if ($stream.Length -ge $peHeaderOffset + 6 -and
                $stream.Seek($peHeaderOffset, [System.IO.SeekOrigin]::Begin) -eq $peHeaderOffset -and
                $stream.Read($bytes, 0, 4) -eq 4 -and
                $bytes[0] -eq 0x50 -and $bytes[1] -eq 0x45 -and $bytes[2] -eq 0 -and $bytes[3] -eq 0)
            {
                $exeType = 'Unknown'
                if ($stream.Read($bytes, 0, 2) -eq 2)
                {
                    if (-not [System.BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes, 0, 2) }
                    $machineType = [System.BitConverter]::ToUInt16($bytes, 0)
                    switch ($machineType)
                    {
                        0x014C { $exeType = 'x86' }
                        0x8664 { $exeType = 'x64' }
                    }
                }
            }
        }
        return $exeType
    }
    catch
    {
        return "Unknown"
    }
    finally
    {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}
    $regexVersion = '("version":")([0-9.]*)'
    $regexRing = '("ring":")(\w*)'
    $regexEnv = '("environment":")(\w*)'
    $regexCloudEnv = '("cloudEnvironment":")(\w*)'
    $regexRegion = '("region":")([a-zA-Z0-9._-]*)'

    $regexWindowsUser = '("upnWindowUserUpn":")([a-zA-Z0-9@._-]*)'
    $regexTeamsUserName = '("userName":")([a-zA-Z0-9@._-]*)'

    $outTeamsVersion = [System.Collections.ArrayList]::new()

    if($Path){
        if (Test-Path $Path -ErrorAction SilentlyContinue) {
            $TeamsSettingsFiles = Get-ChildItem -Path $Path -Include "settings.json" -Recurse
            foreach ($TeamsSettingsFile in $TeamsSettingsFiles){
                $TeamsSettings = Get-Content -Path $TeamsSettingsFile.FullName
                $Version = ""
                $Ring = ""
                $Env = ""
                $CloudEnv = ""
                $Region = ""
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
                    $RegionTemp = [regex]::Match($TeamsSettings, $regexRegion).captures.groups
                    if ($RegionTemp.Count -ge 2) {
                        $Region = $RegionTemp[2].value
                    }
                }
                catch { }
                $TeamsDesktopSettingsFile = $TeamsSettingsFile.Directory.FullName + "\desktop-config.json"
                if (Test-Path $TeamsDesktopSettingsFile -ErrorAction SilentlyContinue) {
                    $TeamsDesktopSettings = Get-Content -Path $TeamsDesktopSettingsFile
                    $WindowsUser = ""
                    $TeamsUserName =""
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
                    WindowsUser             = $WindowsUser
                    TeamsUser               = $TeamsUserName
                    Version                 = $Version
                    Ring                    = $Ring
                    Environment             = $Env
                    CloudEnvironment        = $CloudEnv
                    Region                  = $Region
                    Path                    = $TeamsSettingsFile.Directory.FullName
                }
                $TeamsVersion.PSObject.TypeNAmes.Insert(0, 'TeamsVersionFromPath')
                $outTeamsVersion.Add($TeamsVersion) | Out-Null
            }
        } else {
            Write-Error -Message ("Invalid Path, please check if path: " + $path + " is correct and exists.")
        }

    } else {
        $currentDateFormat = [cultureinfo]::CurrentCulture.DateTimeFormat.ShortDatePattern
        if($Computer) {
            $RemotePath = "\\" + $Computer + "\C$\Users\"
            if(Test-Path -Path $RemotePath) {
                $Profiles = Get-ChildItem -Path $RemotePath -ErrorAction SilentlyContinue
            } else {
                Write-Error -Message ("Cannot get users on : " + $computer + " check if name is correct and permissions.")
            }
        } else {
            $Profiles = Get-childItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object { Get-ItemProperty $_.pspath } | Where-Object { $_.fullprofile -eq 1 }
        }
        
        foreach ($UserProfile in $Profiles) {
            if($Computer){
                $ProfilePath = $UserProfile.FullName
                $ProfileName = $UserProfile.Name
            } else {
                $ProfilePath = $UserProfile.ProfileImagePath
                $ProfileName  = (New-Object System.Security.Principal.SecurityIdentifier($UserProfile.PSChildName)).Translate( [System.Security.Principal.NTAccount]).Value
            }
            $TeamsSettingPath = $ProfilePath + "\AppData\Roaming\Microsoft\Teams\settings.json"
            if (Test-Path $TeamsSettingPath -ErrorAction SilentlyContinue) {
                $TeamsSettings = Get-Content -Path $TeamsSettingPath
                $Version = ""
                $Ring = ""
                $Env = ""
                $CloudEnv = ""
                $Region = ""
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
                    $RegionTemp = [regex]::Match($TeamsSettings, $regexRegion).captures.groups
                    if ($RegionTemp.Count -ge 2) {
                        $Region = $RegionTemp[2].value
                    }
                }
                catch { }
                $TeamsApp = $ProfilePath + "\AppData\Local\Microsoft\Teams\current\Teams.exe"
                $InstallDateStr = Get-Content ($ProfilePath + "\AppData\Roaming\Microsoft\Teams\installTime.txt")
                $TeamsVersion = New-Object -TypeName PSObject -Property @{
                    Profile          = $ProfileName
                    ProfilePath      = $ProfilePath
                    Version          = $Version
                    Ring             = $Ring
                    Environment      = $Env
                    CloudEnvironment = $CloudEnv
                    Region           = $Region
                    Arch             = Get-UcArch $TeamsApp
                    InstallDate      = [Datetime]::ParseExact($InstallDateStr, 'M/d/yyyy', $null) | Get-Date -Format $currentDateFormat
                }
                $TeamsVersion.PSObject.TypeNAmes.Insert(0, 'TeamsVersion')
                $outTeamsVersion.Add($TeamsVersion) | Out-Null
            }
        }
    }
    return $outTeamsVersion
