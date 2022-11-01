# Get-TeamsVersion
This script returns the installed MS Teams Version for each user profile.

Teams: Check client version using PowerShell
http://uclobby.com/2018/08/23/teams-check-client-version-using-powershell


Please note that as of May 18th 2022 this script was added to https://github.com/uclobby/UCLobbyTeams

Usage:
Get-TeamsVersion.ps1

Currently the script doesn’t accept any parameter.

It's recommended to run the script with elevated privileges' 

<br/>Change Log:
<br/>2.0 - 2022/10/20
<ul>
  <li>Added Computer parameter to get Teams version on a remote machine.</li>
  <li>Added Path parameter to specify a path that contains Teams log files.</li>
</ul>
<br/>1.3 - 2022/06/10
<ul>
  <li>Fixed the issue where the version was limited to 4 digits.</li>
  <li>Added information for Ring, Environment, Region.</li>
</ul>
<br/>1.2 - 2022/02/11
<ul>
        <li>Version is now extracted using Regular Expressions since ConvertFrom-Json was raising an exception in some scenarios.</li>
</ul>
<br/>1.1 - 2020/02/26
<ul>
        <li>Added Architecture to the output.</li>
</ul>
<br/>1.0 - 2018/09/04
<ul>
    <li>Initial release.</li>
</ul>
