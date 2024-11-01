# Get-TeamsVersion
This script returns the installed MS Teams Version for each user profile.

Teams: Check client version using PowerShell
http://uclobby.com/2018/08/23/teams-check-client-version-using-powershell


Please note that as of May 18th 2022 this script was added to https://github.com/uclobby/UCLobbyTeams

Usage:
Get-TeamsVersion.ps1

Parameters
<ul>
  <li>Path - Get Teams Version from previously downloaded log files</li>
  <li>Computer – Specify the computer we want to collect the version from. Requires Admin Shares to be enabled.</li>
  <li>Credential – Credential to be used to connect to the remote computer.</li>
</ul>
It's recommended to run the script with elevated privileges' 

<br/>Change Log:

<br/>2.4 - 2024/11/01
<ul>
  <li>Fix: Teams Classic was include in the output if settings file was present after Teams Classic uninstallation.</li>
  <li>Fix: Running this in Windows 10 with PowerShell 7 an exception could be raised while importing the Appx PowerShell module. Thank you Steve Chupack for reporting this issue.</li>
</ul>
<br/>2.3 - 2024/10/25
<ul>
  <li>Fix: No output generated for New Teams if the tma_settings.json file was missing.</li>
</ul>
<br/>2.2 - 2024/03/15
<ul>
  <li>Feature: Add support for New Teams on a Remote Computer.</li>
  <li>Feature: Add suport for New Teams from Path</li>
  <li>Feature: Add column Type which will have New Teams or Classic Teams.</li>
  <li>Change: Removed column Region.</li>
  <li>Change: Use Get-AppPackage to determine MS Teams Instalation Path and remove the requirement of administative rights.</li>
  <li>Fix: In some scenarios the install date was missing and generating an error.</li>
</ul>
<br/>2.1 - 2023/12/04
<ul>
  <li>Feature: Add support for new Teams version.</li>
  <li>Feature: Added Credential parameter that will be used to connect to the remote computer.</li>
  <li>Fix: Exception handling for windows profiles that were created when the machine was joined to an another domain.</li>
</ul>
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
