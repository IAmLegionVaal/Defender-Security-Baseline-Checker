#requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$EnableRealtime,
    [switch]$EnableCloudProtection,
    [switch]$UpdateSignatures,
    [switch]$QuickScan,
    [switch]$RepairServices,

    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = "$env:USERPROFILE\Desktop\DefenderRepair"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$warnings = [System.Collections.Generic.List[string]]::new()
$logPath = $null

function Write-RepairLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )

    $entry = '[{0}] [{1}] {2}' -f (Get-Date -Format 's'), $Level, $Message
    Write-Host $entry
    if ($logPath) {
        Add-Content -LiteralPath $logPath -Value $entry -Encoding UTF8
    }
}

function Add-RepairWarning {
    param([Parameter(Mandatory)][string]$Message)

    $warnings.Add($Message)
    Write-RepairLog -Level WARN -Message $Message
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

try {
    if ($env:OS -ne 'Windows_NT') {
        throw 'This repair requires Windows.'
    }

    if (-not ($EnableRealtime -or $EnableCloudProtection -or $UpdateSignatures -or $QuickScan -or $RepairServices)) {
        throw 'Choose at least one repair action.'
    }

    if (-not (Test-IsAdministrator)) {
        throw 'Run PowerShell as Administrator.'
    }

    foreach ($commandName in 'Get-MpComputerStatus', 'Get-MpPreference', 'Set-MpPreference') {
        if (-not (Get-Command -Name $commandName -ErrorAction SilentlyContinue)) {
            throw "Required Microsoft Defender cmdlet '$commandName' is unavailable."
        }
    }

    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    $logPath = Join-Path $OutputPath ('repair-{0:yyyyMMdd-HHmmss}.log' -f (Get-Date))

    Get-MpComputerStatus | Export-Clixml (Join-Path $OutputPath 'before-status.xml')
    Get-MpPreference | Export-Clixml (Join-Path $OutputPath 'before-preferences.xml')

    if ($RepairServices) {
        foreach ($serviceName in 'WinDefend', 'WdNisSvc', 'SecurityHealthService') {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if (-not $service) {
                Add-RepairWarning "Service '$serviceName' is unavailable on this system."
                continue
            }

            if ($service.Status -ne 'Running' -and $PSCmdlet.ShouldProcess($serviceName, 'Start Microsoft Defender service')) {
                try {
                    Start-Service -Name $serviceName -ErrorAction Stop
                    (Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
                    Write-RepairLog "Started service '$serviceName'."
                }
                catch {
                    Add-RepairWarning "Could not start '$serviceName': $($_.Exception.Message)"
                }
            }
        }
    }

    if ($EnableRealtime -and $PSCmdlet.ShouldProcess('Microsoft Defender', 'Enable real-time monitoring')) {
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
        Write-RepairLog 'Real-time monitoring was enabled.'
    }

    if ($EnableCloudProtection -and $PSCmdlet.ShouldProcess('Microsoft Defender', 'Enable cloud-delivered protection')) {
        Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -ErrorAction Stop
        Write-RepairLog 'Cloud-delivered protection was enabled.'
    }

    if ($UpdateSignatures -and $PSCmdlet.ShouldProcess('Microsoft Defender', 'Update security intelligence')) {
        if (-not (Get-Command -Name 'Update-MpSignature' -ErrorAction SilentlyContinue)) {
            throw 'Update-MpSignature is unavailable.'
        }
        Update-MpSignature -ErrorAction Stop | Out-File (Join-Path $OutputPath 'signature-update.txt') -Encoding UTF8
        Write-RepairLog 'Security intelligence update completed.'
    }

    if ($QuickScan -and $PSCmdlet.ShouldProcess('Microsoft Defender', 'Run a quick antivirus scan')) {
        if (-not (Get-Command -Name 'Start-MpScan' -ErrorAction SilentlyContinue)) {
            throw 'Start-MpScan is unavailable.'
        }
        Start-MpScan -ScanType QuickScan -ErrorAction Stop
        Write-RepairLog 'Quick scan completed.'
    }

    $afterStatus = Get-MpComputerStatus
    $afterPreference = Get-MpPreference
    $afterStatus | Export-Clixml (Join-Path $OutputPath 'after-status.xml')
    $afterPreference | Export-Clixml (Join-Path $OutputPath 'after-preferences.xml')

    if ($EnableRealtime -and $afterPreference.DisableRealtimeMonitoring) {
        Add-RepairWarning 'Real-time monitoring remains disabled, possibly because of policy or tamper protection.'
    }

    if ($EnableCloudProtection -and [int]$afterPreference.MAPSReporting -eq 0) {
        Add-RepairWarning 'Cloud-delivered protection was not verified after repair.'
    }

    if ($RepairServices) {
        foreach ($serviceName in 'WinDefend', 'WdNisSvc') {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -ne 'Running') {
                Add-RepairWarning "Service '$serviceName' is not running after repair."
            }
        }
    }

    $warnings | Set-Content -LiteralPath (Join-Path $OutputPath 'warnings.txt') -Encoding UTF8

    if ($warnings.Count -gt 0) {
        Write-RepairLog -Level WARN -Message "Completed with $($warnings.Count) warning(s)."
        exit 2
    }

    Write-RepairLog 'Repair workflow completed and selected settings were verified.'
    exit 0
}
catch {
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction SilentlyContinue | Out-Null
    }
    Write-Error $_.Exception.Message
    exit 1
}
