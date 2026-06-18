#requires -Version 5.1
<#
.SYNOPSIS
    Defender Security Baseline Checker.
.DESCRIPTION
    Read-only Windows endpoint security posture checker for L1/L2 support.
#>
[CmdletBinding()]
param([string]$OutputPath)

$RunStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Security_Baseline_Reports' }
New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

function New-Check { param($Category,$Name,$Status,$Value,$Recommendation) [PSCustomObject]@{Category=$Category;Name=$Name;Status=$Status;Value=$Value;Recommendation=$Recommendation} }
$checks = @()

try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    $checks += New-Check 'Defender' 'Real-time protection' ($(if($mp.RealTimeProtectionEnabled){'OK'}else{'Warning'})) $mp.RealTimeProtectionEnabled 'Should normally be enabled unless managed by another AV.'
    $age = (Get-Date) - $mp.AntivirusSignatureLastUpdated
    $checks += New-Check 'Defender' 'Signature age' ($(if($age.TotalDays -gt 7){'Warning'}else{'OK'})) ("{0:N1} days" -f $age.TotalDays) 'Update signatures if old.'
    $checks += New-Check 'Defender' 'Antivirus enabled' ($(if($mp.AntivirusEnabled){'OK'}else{'Warning'})) $mp.AntivirusEnabled 'Confirm AV status.'
} catch { $checks += New-Check 'Defender' 'Defender query' 'Info' $_.Exception.Message 'Device may use third-party AV or restricted cmdlets.' }

try { Get-NetFirewallProfile | ForEach-Object { $checks += New-Check 'Firewall' $_.Name ($(if($_.Enabled){'OK'}else{'Warning'})) "Enabled: $($_.Enabled); Inbound: $($_.DefaultInboundAction); Outbound: $($_.DefaultOutboundAction)" 'Firewall should normally be enabled.' } } catch { $checks += New-Check 'Firewall' 'Firewall query' 'Warning' $_.Exception.Message 'Could not query firewall.' }
try { Get-BitLockerVolume | ForEach-Object { $checks += New-Check 'BitLocker' $_.MountPoint ($(if($_.ProtectionStatus -eq 'On'){'OK'}else{'Warning'})) "Protection: $($_.ProtectionStatus); Volume: $($_.VolumeStatus)" 'Review encryption policy.' } } catch { $checks += New-Check 'BitLocker' 'BitLocker query' 'Info' $_.Exception.Message 'May require supported edition or admin rights.' }
try { $sb = Confirm-SecureBootUEFI -ErrorAction Stop; $checks += New-Check 'Secure Boot' 'Secure Boot' ($(if($sb){'OK'}else{'Warning'})) $sb 'Secure Boot is recommended.' } catch { $checks += New-Check 'Secure Boot' 'Secure Boot query' 'Info' $_.Exception.Message 'May fail on legacy BIOS.' }
try { $admins = (Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name) -join '; '; $checks += New-Check 'Local Admins' 'Administrators group' 'Info' $admins 'Review privileged membership.' } catch { $checks += New-Check 'Local Admins' 'Administrators group' 'Warning' $_.Exception.Message 'Run as Administrator.' }
try { $rdp = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections; $enabled = -not [bool]$rdp.fDenyTSConnections; $checks += New-Check 'Remote Access' 'RDP enabled' ($(if($enabled){'Warning'}else{'OK'})) $enabled 'Confirm RDP exposure is approved.' } catch { $checks += New-Check 'Remote Access' 'RDP query' 'Info' $_.Exception.Message 'Could not query RDP setting.' }
try { $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA; $checks += New-Check 'UAC' 'UAC enabled' ($(if($uac.EnableLUA -eq 1){'OK'}else{'Warning'})) $uac.EnableLUA 'UAC should normally be enabled.' } catch { $checks += New-Check 'UAC' 'UAC query' 'Info' $_.Exception.Message 'Could not query UAC.' }
try { $shares = Get-SmbShare | Select-Object Name,Path,Description,Special; $checks += New-Check 'Shares' 'SMB share count' 'Info' (@($shares).Count) 'Review unexpected non-admin shares.'; $shares | Export-Csv (Join-Path $OutputPath "smb_shares_$RunStamp.csv") -NoTypeInformation -Encoding UTF8 } catch { $checks += New-Check 'Shares' 'SMB share query' 'Info' $_.Exception.Message 'Could not query shares.' }

$csv = Join-Path $OutputPath "security_baseline_$RunStamp.csv"
$json = Join-Path $OutputPath "security_baseline_$RunStamp.json"
$html = Join-Path $OutputPath "security_baseline_$RunStamp.html"
$checks | Export-Csv $csv -NoTypeInformation -Encoding UTF8
$checks | ConvertTo-Json -Depth 5 | Set-Content $json -Encoding UTF8
$checks | ConvertTo-Html -Title 'Defender Security Baseline' -PreContent "<h1>Defender Security Baseline - $env:COMPUTERNAME</h1><p>Generated $(Get-Date)</p>" | Set-Content $html -Encoding UTF8
$checks | Format-Table -AutoSize -Wrap
Write-Host "Reports saved to: $OutputPath" -ForegroundColor Green
Start-Process explorer.exe -ArgumentList "`"$OutputPath`"" -ErrorAction SilentlyContinue
