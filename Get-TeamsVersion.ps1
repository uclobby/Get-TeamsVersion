<#
.DESCRIPTION
	This script returns the installed MS Teams Version for each user profile.

.NOTES
  Version      	   		: 1.1
  Author    			: David Paulino 
  Info                  : https://uclobby.com/2018/08/23/teams-check-client-version-using-powershell
  

#>


# Funcion to get the Architecture from .exe file
#
# Based on PowerShell script Get-ExecutableType.ps1 by David Wyatt, please check the complete script in:
#
# Identify 16-bit, 32-bit and 64-bit executables with PowerShell
# https://gallery.technet.microsoft.com/scriptcenter/Identify-16-bit-32-bit-and-522eae75

function GetArch([string]$sFilePath)
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

$Profiles = (Get-childItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'  | % {Get-ItemProperty $_.pspath } | ?{$_.fullprofile -eq 1} )

foreach($Profile in $Profiles){

    $ProfilePath = $Profile.ProfileImagePath
    $TeamsSettings = $ProfilePath + "\AppData\Roaming\Microsoft\Teams\settings.json"
    if(Test-Path $TeamsSettings -ErrorAction SilentlyContinue) {
        $profileSID = New-Object System.Security.Principal.SecurityIdentifier($Profile.PSChildName)
        $ProfileName = $profileSID.Translate( [System.Security.Principal.NTAccount]).Value
        $Setting = Get-Content $TeamsSettings -ErrorAction Continue | ConvertFrom-Json | Select Version
        $TeamsApp = $ProfilePath + "\AppData\Local\Microsoft\Teams\current\Teams.exe" 
        $TeamsArch = GetArch $TeamsApp
        $InstallDate = Get-Content $ProfilePath"\AppData\Roaming\Microsoft\Teams\installTime.txt"
        $TeamsVersion = New-Object –TypeName PSObject
        $TeamsVersion | Add-Member –MemberType NoteProperty –Name Profile –Value $ProfileName
        $TeamsVersion | Add-Member –MemberType NoteProperty –Name ProfilePath –Value $ProfilePath
        $TeamsVersion | Add-Member –MemberType NoteProperty –Name Version –Value $Setting.Version
        $TeamsVersion | Add-Member –MemberType NoteProperty –Name Arch –Value $TeamsArch
        $TeamsVersion | Add-Member –MemberType NoteProperty –Name InstallDate –Value $InstallDate
        Write-Output $TeamsVersion
    } 
}