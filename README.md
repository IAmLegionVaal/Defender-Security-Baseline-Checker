# Defender Security Baseline Checker

A read-only PowerShell toolkit for checking basic Windows endpoint security posture.

## Features

- Microsoft Defender status
- Defender signature age
- Firewall profile status
- BitLocker protection summary
- Secure Boot status
- Local Administrators group summary
- RDP exposure check
- UAC setting check
- SMB share summary
- HTML, CSV, and JSON report output

## How to run

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Defender_Security_Baseline_Checker.ps1
```

## Safety

This script is diagnostic-only. It does not change Defender, firewall, BitLocker, users, shares, or registry settings.

## Suggested topics

```text
powershell
windows-security
defender
bitlocker
firewall
it-support
sysadmin
baseline
```
