# New-PSDriveAltCred
Uses PowerShell to persistently map a network share using an alternate smartcard credential.  This is not possible using the *Map Network Drive* GUI option as it only allows for a username and password to connect using different credentials.

## Examples
* Map a persistent share called <myshare> located on <server> using the default Z drive.
  * `.\New-PSDriveAltCred.ps1 '\\server\myshare\'`

* Map a persistent share located on <workstation.local.domain> to the built-in C$ share as the X drive.
  * `.\New-PSDriveAltCred.ps1 -UNCSharePath '\\worksation.local.domain\C$' -DriveLetter X`
