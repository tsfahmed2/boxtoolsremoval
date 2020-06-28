Param ([bool]$NoExecute = $false)

$PSHive = "Microsoft.PowerShell.Core\Registry::HKEY_USERS"

function Get-RegistryPathsForUser
{
	Param ([string]$SID)
	
	$PotentialItemsToRemove = @()
	
	If (Test-Path "$PSHive\$SID\Software\Microsoft\Installer\UpgradeCodes\381347AB2C29F8F42BE77B28C2DA0259")
	{
		$PotentialItemsToRemove += (Get-Item "$PSHive\$SID\Software\Microsoft\Installer\UpgradeCodes\381347AB2C29F8F42BE77B28C2DA0259").PSPath
		
		If ((Get-Item "$PSHive\$SID\Software\Microsoft\Installer\UpgradeCodes\381347AB2C29F8F42BE77B28C2DA0259").Property.Length -eq 1)
		{
			$ProductCode = (Get-Item "$PSHive\$SID\Software\Microsoft\Installer\UpgradeCodes\381347AB2C29F8F42BE77B28C2DA0259").Property[0]
			$ProductCodeGUID = "{" + $ProductCode[7] + $ProductCode[6] + $ProductCode[5] + $ProductCode[4] + $ProductCode[3] + $ProductCode[2] + $ProductCode[1] + $ProductCode[0] + "-" + $ProductCode[11] + $ProductCode[10] + $ProductCode[9] + $ProductCode[8] + "-" + $ProductCode[15] + $ProductCode[14] + $ProductCode[13] + $ProductCode[12] + "-" + $ProductCode[17] + $ProductCode[16] + $ProductCode[19] + $ProductCode[18] + "-" + $ProductCode[21] + $ProductCode[20] + $ProductCode[23] + $ProductCode[22] + $ProductCode[25] + $ProductCode[24] + $ProductCode[27] + $ProductCode[26] + $ProductCode[29] + $ProductCode[28] + $ProductCode[31] + $ProductCode[30] + "}"
			
			$PotentialItemsToRemove += "$PSHive\$SID\Software\Microsoft\Installer\Features\$ProductCode"
			
			$PotentialItemsToRemove += "$PSHive\$SID\Software\Microsoft\Installer\Products\$ProductCode"
			
			(Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\$SID\Components" | Where-Object { $_.Property -eq $ProductCode }) | % { $PotentialItemsToRemove += $_.PSPath }
			
			$PotentialItemsToRemove += "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\$SID\Products\$ProductCode"
			
			$PotentialItemsToRemove += "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCodeGUID"
			
			$PotentialItemsToRemove += "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCodeGUID"
		}
	}
	
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Classes\Box.BoxEdit"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Classes\Box.BoxEdit.1"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Classes\CLSID\{9e09c3e2-2106-5b93-a5f7-51f4d3eea53c}"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Classes\Wow6432Node\CLSID\{9e09c3e2-2106-5b93-a5f7-51f4d3eea53c}"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Classes\MIME\Database\Content Type\application/x-boxedit"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Microsoft\Windows\CurrentVersion\Ext\PreApproved\{9e09c3e2-2106-5b93-a5f7-51f4d3eea53c}"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Microsoft\Windows\CurrentVersion\Ext\Stats\{9e09c3e2-2106-5b93-a5f7-51f4d3eea53c}"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\MozillaPlugins\box.com/BoxEdit"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Classes\TypeLib\{62DDF3C0-A79E-5EB7-A672-7306B5EDCBF2}"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Classes\Wow6432Node\Interface\{7CAD4B37-32BD-5C92-A12D-68337E7E821B}"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Classes\Interface\{7CAD4B37-32BD-5C92-A12D-68337E7E821B}"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Classes\Wow6432Node\Interface\{7E7BE1F9-C9A4-58A6-978A-AD25CDF37FE2}"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Classes\Interface\{7E7BE1F9-C9A4-58A6-978A-AD25CDF37FE2}"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Classes\Wow6432Node\Interface\{21482872-D3D9-550A-86D0-480C3CE1043C}"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Classes\Interface\{21482872-D3D9-550A-86D0-480C3CE1043C}"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Classes\AppID\{B415CD14-B45D-4BCA-B552-B06175C38606}"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Classes\AppID\npBoxEdit.dll"
	
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Box\Box Edit"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Box\Box Local Com Service"
	
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Classes\Box.BoxTools"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Classes\Wow6432Node\Box.BoxTools"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Classes\CLSID\{BA58190A-A733-4982-8AE2-E2021F0DD503}"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Classes\Wow6432Node\CLSID\{BA58190A-A733-4982-8AE2-E2021F0DD503}"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Microsoft\Internet Explorer\Low Rights\ElevationPolicy\{C87A79FD-ADEB-418C-BECD-1B55AFF13DAE}"
	$PotentialItemsToRemove += "$PSHive\$SID\Software\Microsoft\Windows\CurrentVersion\Ext\Stats\{BA58190A-A733-4982-8AE2-E2021F0DD503}"
	
	return, $PotentialItemsToRemove
}

function Get-RegistryValuesForUser
{
	Param ([string]$SID, [string]$ProfileImagePath)
	
	$PropertiesToRemove = @()
	
	$PropertiesToRemove += New-Object PSObject -Property @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders";Name=(Join-Path $ProfileImagePath "AppData\Local\Box\Box Edit") + "\"}
	$PropertiesToRemove += New-Object PSObject -Property @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders";Name=(Join-Path $ProfileImagePath "AppData\Local\Box\Box Edit\x86") + "\"}
	$PropertiesToRemove += New-Object PSObject -Property @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders";Name=(Join-Path $ProfileImagePath "AppData\Local\Box\Box Local Com Server") + "\"}
	$PropertiesToRemove += New-Object PSObject -Property @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders";Name=(Join-Path $ProfileImagePath "AppData\Local\Box\Box Local Com Server\XML") + "\"}
	
	$PropertiesToRemove += New-Object PSObject -Property @{Path="$PSHive\$SID\Software\Microsoft\Windows\CurrentVersion\Run";Name="Box Edit"}
	$PropertiesToRemove += New-Object PSObject -Property @{Path="$PSHive\$SID\Software\Microsoft\Windows\CurrentVersion\Run";Name="Box Local Com Server"}

	return, $PropertiesToRemove
}

function Get-PathsForUser
{
	Param ([string]$ProfileImagePath)
	
	return @((Join-Path $ProfileImagePath "AppData\Local\Box\Box Edit"), (Join-Path $ProfileImagePath "AppData\Local\Box\Box Local Com Server"), (Join-Path $ProfileImagePath "AppData\Local\Box\ComServer"), (Join-Path $ProfileImagePath "AppData\Local\Box\Box Tools ActiveX Add-on"))
}

$ItemsToRemove = @()
$PotentialItemsToRemove = @()
$PropertiesToRemove = @()
$HivesToUnload = @()

$ProfileList = (Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Where-Object { $_.PSChildName.StartsWith("S-1-5-21") })

$ProfileList | % {
	$SID = $_.PSChildName
	$ProfileImagePath = (Get-ItemProperty -Path $_.PSPath).ProfileImagePath
	If ((Test-Path "$PSHive\$SID") -eq $false)
	{
		$ProfileRegistryFilePath = (Join-Path $ProfileImagePath "NTUSER.DAT")
		If (Test-Path $ProfileRegistryFilePath)
		{
			REG LOAD "HKEY_USERS\$SID" $ProfileRegistryFilePath
			$HivesToUnload += "HKEY_USERS\$SID"
		}
	}
	
	$PotentialItemsToRemove += Get-PathsForUser $ProfileImagePath
}

$ProfileList | % { $PotentialItemsToRemove += (Get-RegistryPathsForUser $_.PSChildName) }

$PotentialItemsToRemove += Get-PathsForUser (Join-Path ${Env:\SystemRoot} "System32\config\systemprofile")
$PotentialItemsToRemove += Get-PathsForUser (Join-Path ${Env:\SystemRoot} "SysWOW64\config\systemprofile")
$PotentialItemsToRemove += (Get-RegistryPathsForUser "S-1-5-18")

$PotentialItemsToRemove += "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\381347AB2C29F8F42BE77B28C2DA0259"

$PotentialItemsToRemove += Join-Path ${Env:\ProgramData} "Box\ComServer"
$PotentialItemsToRemove += Join-Path ${Env:\ProgramData} "Box\Box Local Com Server"

($PotentialItemsToRemove | Where-Object { Test-Path $_ }) | % { $ItemsToRemove += (Get-Item $_).PSPath }

$ProfileList | % { $PropertiesToRemove += (Get-RegistryValuesForUser $_.PSChildName (Get-ItemProperty -Path $_.PSPath).ProfileImagePath) }

If ($NoExecute -eq $false)
{
	Stop-Process -Name "Box Edit" -Force -ErrorAction SilentlyContinue
	Stop-Process -Name "PostureChecker" -Force -ErrorAction SilentlyContinue
	Stop-Process -Name "Box Device Trust" -Force -ErrorAction SilentlyContinue
	Stop-Process -Name "Box.DnsWarningSystem" -Force -ErrorAction SilentlyContinue
	Stop-Process -Name "Box Local Com Service" -Force -ErrorAction SilentlyContinue
	Stop-Process -Name "Box.Tools.ActiveX" -Force -ErrorAction SilentlyContinue
	
	$ItemsToRemove | % {
		Write-Host $_
		Remove-Item $_ -Recurse -ErrorAction SilentlyContinue
	}
	
	$PropertiesToRemove | % {
		Write-Host $_
		Remove-ItemProperty -Path $_.Path -Name $_.Name -ErrorAction SilentlyContinue
	}
}
Else
{
	$ItemsToRemove | % { Write-Host $_ }
	$PropertiesToRemove | % { Write-Host $_ }
}

$HivesToUnload | % { REG UNLOAD $_ }
# SIG # Begin signature block
# MIIL6gYJKoZIhvcNAQcCoIIL2zCCC9cCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUCW9u4i2uL2P15K7BPpcbMs5Y
# x76ggglTMIIEmTCCA4GgAwIBAgIQcaC3NpXdsa/COyuaGO5UyzANBgkqhkiG9w0B
# AQsFADCBqTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDHRoYXd0ZSwgSW5jLjEoMCYG
# A1UECxMfQ2VydGlmaWNhdGlvbiBTZXJ2aWNlcyBEaXZpc2lvbjE4MDYGA1UECxMv
# KGMpIDIwMDYgdGhhd3RlLCBJbmMuIC0gRm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkx
# HzAdBgNVBAMTFnRoYXd0ZSBQcmltYXJ5IFJvb3QgQ0EwHhcNMTMxMjEwMDAwMDAw
# WhcNMjMxMjA5MjM1OTU5WjBMMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMdGhhd3Rl
# LCBJbmMuMSYwJAYDVQQDEx10aGF3dGUgU0hBMjU2IENvZGUgU2lnbmluZyBDQTCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJtVAkwXBenQZsP8KK3TwP7v
# 4Ol+1B72qhuRRv31Fu2YB1P6uocbfZ4fASerudJnyrcQJVP0476bkLjtI1xC72Ql
# WOWIIhq+9ceu9b6KsRERkxoiqXRpwXS2aIengzD5ZPGx4zg+9NbB/BL+c1cXNVeK
# 3VCNA/hmzcp2gxPI1w5xHeRjyboX+NG55IjSLCjIISANQbcL4i/CgOaIe1Nsw0Rj
# gX9oR4wrKs9b9IxJYbpphf1rAHgFJmkTMIA4TvFaVcnFUNaqOIlHQ1z+TXOlScWT
# af53lpqv84wOV7oz2Q7GQtMDd8S7Oa2R+fP3llw6ZKbtJ1fB6EDzU/K+KTT+X/kC
# AwEAAaOCARcwggETMC8GCCsGAQUFBwEBBCMwITAfBggrBgEFBQcwAYYTaHR0cDov
# L3QyLnN5bWNiLmNvbTASBgNVHRMBAf8ECDAGAQH/AgEAMDIGA1UdHwQrMCkwJ6Al
# oCOGIWh0dHA6Ly90MS5zeW1jYi5jb20vVGhhd3RlUENBLmNybDAdBgNVHSUEFjAU
# BggrBgEFBQcDAgYIKwYBBQUHAwMwDgYDVR0PAQH/BAQDAgEGMCkGA1UdEQQiMCCk
# HjAcMRowGAYDVQQDExFTeW1hbnRlY1BLSS0xLTU2ODAdBgNVHQ4EFgQUV4abVLi+
# pimK5PbC4hMYiYXN3LcwHwYDVR0jBBgwFoAUe1tFz6/Oy3r9MZIaarbzRutXSFAw
# DQYJKoZIhvcNAQELBQADggEBACQ79degNhPHQ/7wCYdo0ZgxbhLkPx4flntrTB6H
# novFbKOxDHtQktWBnLGPLCm37vmRBbmOQfEs9tBZLZjgueqAAUdAlbg9nQO9ebs1
# tq2cTCf2Z0UQycW8h05Ve9KHu93cMO/G1GzMmTVtHOBg081ojylZS4mWCEbJjvx1
# T8XcCcxOJ4tEzQe8rATgtTOlh5/03XMMkeoSgW/jdfAetZNsRBfVPpfJvQcsVncf
# hd1G6L/eLIGUo/flt6fBN591ylV3TV42KcqF2EVBcld1wHlb+jQQBm1kIEK3Osgf
# HUZkAl/GR77wxDooVNr2Hk+aohlDpG9J+PxeQiAohItHIG4wggSyMIIDmqADAgEC
# AhAKc2ae2E2OExpI9AKT7kvPMA0GCSqGSIb3DQEBCwUAMEwxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwx0aGF3dGUsIEluYy4xJjAkBgNVBAMTHXRoYXd0ZSBTSEEyNTYg
# Q29kZSBTaWduaW5nIENBMB4XDTE2MDgxMDAwMDAwMFoXDTE4MTAwNjIzNTk1OVow
# cDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEjAQBgNVBAcMCVBh
# bG8gQWx0bzESMBAGA1UECgwJQm94LCBJbmMuMRAwDgYDVQQLDAdVbmtub3duMRIw
# EAYDVQQDDAlCb3gsIEluYy4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCCcpYU4aZwB5uqKzgG7s1+LxOasbyYFExbM38n8+HrMUSA6HPe4ikMvwpaKnah
# nBwBGT0LFcoPLXHo0cti9gJMRJqYAwOd5DFRwW6zJadrnJPArOFfoBI48hirwmd6
# RGYZSP5rUqj+8DNfcAGC5eYxiax933S+8svU0XX80G/6G97B9fSJkJP45Zxa7WUd
# XqMUuFZ/rED+h1VB0VC6kBo8kKGTBtjKrlthLEU3E+gnx/ReqlItGTUL7R5FpLxG
# rxLO9Y4WAIxlVoBpSEJQiH8zuIIb8BaVkFHbSbq125VFLlm8aJwkVkp8krWeCppT
# COwMCD1/+ZksrUZsgE7Werv7AgMBAAGjggFqMIIBZjAJBgNVHRMEAjAAMB8GA1Ud
# IwQYMBaAFFeGm1S4vqYpiuT2wuITGImFzdy3MB0GA1UdDgQWBBQfA4j0oZF7vF5b
# 8GVywP5LhHGy0TArBgNVHR8EJDAiMCCgHqAchhpodHRwOi8vdGwuc3ltY2IuY29t
# L3RsLmNybDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwbgYD
# VR0gBGcwZTBjBgZngQwBBAEwWTAmBggrBgEFBQcCARYaaHR0cHM6Ly93d3cudGhh
# d3RlLmNvbS9jcHMwLwYIKwYBBQUHAgIwIwwhaHR0cHM6Ly93d3cudGhhd3RlLmNv
# bS9yZXBvc2l0b3J5MFcGCCsGAQUFBwEBBEswSTAfBggrBgEFBQcwAYYTaHR0cDov
# L3RsLnN5bWNkLmNvbTAmBggrBgEFBQcwAoYaaHR0cDovL3RsLnN5bWNiLmNvbS90
# bC5jcnQwDQYJKoZIhvcNAQELBQADggEBAIjZoYWAMyJb5oV0RHf8ICwLo/zYSqyk
# FViL8mZUqczbz/petpC3SMEnwfdA0E3UE1suRn1/U2we/b9QZYhflX9mG/iFAcWr
# P8FPMgo8gxXEcUbgNs1+tJV9gs2MT3mbns4Xb6gV1Jnw66Xb+xyAR6ZqGnbfy3qJ
# yC4EBuoeSoKzX3ih8FQTF6yy+h+Sh5ikhHrLFtk4ee8Nfvz2GjFzbaQC2u1QVcm9
# wrSUCWvxKVjTS4RrYBdpBm4tM7F0rY6bMLe1FnpD+TdePMVpKyDL5xdgyJgszE3X
# d0NZ5qdti4wY5X7IXUN4Isl1u/BGy9qNC3Tl6i14oA05h79I/JBkegcxggIBMIIB
# /QIBATBgMEwxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwx0aGF3dGUsIEluYy4xJjAk
# BgNVBAMTHXRoYXd0ZSBTSEEyNTYgQ29kZSBTaWduaW5nIENBAhAKc2ae2E2OExpI
# 9AKT7kvPMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkG
# CSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEE
# AYI3AgEVMCMGCSqGSIb3DQEJBDEWBBSGH5VqfFK3SitKZPMuMrXGIVZ+XjANBgkq
# hkiG9w0BAQEFAASCAQBMpwbcShE3GbZgFhAneb2LDBe34+XmF3UgHDhYn4PWiiPJ
# +Qfu2Zwfmecs66liwIDLlWKrazoyK1qKQF2UnCkBFpzhka73UxhGL7YVaoZLv3yg
# zn2ZbFkFzfNat/VHs1N9l0DI9AQJM7Gt36ufaV9rEjYQSfEa5GUxjFD4FstAq56U
# Oab/T4fFx0uGSKw3cWxguAVBwvi47tnozaphar59hd1NMsKUTJ1tCLtL/jZprdQV
# T51oeNDHIvYTIOBxnG7ev1oLEiJjRUbt066ePcLD8Z8KFbaveGS5JPz4V8l1aul3
# 4eqMuaWWFjSgvlfBOtR0XQDn2T+z80AR+Zcu6goE
# SIG # End signature block
