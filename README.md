# Get-TeamsVersion
This script returns the installed MS Teams Version for each user profile.

Teams: Check client version using PowerShell
http://uclobby.com/2018/08/23/teams-check-client-version-using-powershell

Usage:
Get-TeamsVersion.ps1

Currently the script doesn’t accept any parameter.

It's recommended to run the script with elevated privileges' 

Change Log

v1.2 - 2022/02/14
        Version is now extracted using Regular Expressions since ConvertFrom-Json was raising an exception in some scenarios.

v1.1 - 2020/02/26
        Added Architecture to the output.

v1.0 - 2018/09/04
        Initial release.
