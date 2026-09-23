# ==============================================================================
# SOAR AUTOMATED LATERAL CONTAINMENT: DYNAMIC ISOLATION & PROCESS AUDIT
# Component: Endpoint Containment Worker (C:\SOC_Lateral_Defense\isolate_attacker.ps1)
# Author: Hoang Lee (SOC Detection & Response Engineering)
# Target: Windows 10 / Windows Server (Active Directory Defense)
# ==============================================================================

param (
    [Parameter(Mandatory=$false)]
    [string]$TargetIP = "",

    [Parameter(Mandatory=$false)]
    [string]$TargetLogonId = ""
)

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogDir = "C:\SOC_Lateral_Defense"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
}
$LogFile = "$LogDir\lateral_containment.log"

Add-Content -Path $LogFile -Value "[$Timestamp] [TRIGGER] Lateral movement alert received. Initiating containment workflow..."

# Critical infrastructure whitelist: Never allow automated firewall blocking against DCs, gateways, or loopback
$CriticalWhitelist = @(
    "192.168.50.10", # Primary Domain Controller (DC01)
    "192.168.50.1",  # Network Gateway / Router
    "192.168.50.2",  # DNS / DHCP server
    "127.0.0.1",     # Loopback IPv4
    "::1",           # Loopback IPv6
    "-"
)

# ------------------------------------------------------------------------------
# 1. DYNAMIC ATTACKER IP RESOLUTION (Security Event 4624 Correlation)
# Telemetry Gap: Sysmon Event 1 logs process creation but lacks network IP.
# Solution: Query recent Security Event 4624 (LogonType 3) matching TargetLogonId or recent network logon.
# ------------------------------------------------------------------------------
$AttackerIP = $TargetIP

if (-not $AttackerIP) {
    try {
        # Fetch the most recent Network Logon (Type 3) events within the last 60 seconds
        $LogonEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4624
            StartTime = (Get-Date).AddSeconds(-60)
        } -ErrorAction SilentlyContinue

        if ($LogonEvents) {
            foreach ($evt in $LogonEvents) {
                $xml = [xml]$evt.ToXml()
                $logonType = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
                $srcIP     = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                $evtLogonId = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetLogonId' }).'#text'

                # If TargetLogonId was provided from Sysmon Event 1, require exact match
                if ($TargetLogonId -and $evtLogonId -ne $TargetLogonId) {
                    continue
                }

                # LogonType 3 = Network Logon; filter out unroutable addresses & critical infrastructure
                if ($logonType -eq '3' -and $srcIP -and ($srcIP -notin $CriticalWhitelist)) {
                    $AttackerIP = $srcIP
                    Add-Content -Path $LogFile -Value "[$Timestamp] [CORRELATION] Successfully extracted Attacker IP from Security Event 4624 (LogonType 3, LogonId: $evtLogonId): $AttackerIP"
                    break
                }
            }
        }
    } catch {
        Add-Content -Path $LogFile -Value "[$Timestamp] [WARN] Event 4624 correlation query encountered an error: $_"
    }
}

# Safe Containment Validation: Abort if Attacker IP could not be dynamically resolved
if (-not $AttackerIP) {
    Add-Content -Path $LogFile -Value "[$Timestamp] [ABORT] Correlation failed: Could not resolve valid remote Attacker IP from Event 4624 within time window. Containment halted to prevent blocking unintended hosts."
    exit 1
}

# Safeguard check against whitelist before applying block rule
if ($AttackerIP -in $CriticalWhitelist) {
    Add-Content -Path $LogFile -Value "[$Timestamp] [ABORT] Target IP $AttackerIP is in the critical infrastructure whitelist (DC/Gateway). Containment aborted to prevent self-DoS."
    exit 0
}

# ------------------------------------------------------------------------------
# 2. INBOUND HOST CONTAINMENT (Dynamic Windows Defender Firewall Rule)
# ------------------------------------------------------------------------------
$RuleName = "SOC_AUTO_BLOCK_$AttackerIP"

try {
    # Remove duplicate rules if previously created (Idempotent execution)
    Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue

    # Deploy high-priority Inbound Block rule
    New-NetFirewallRule -DisplayName $RuleName `
        -Direction Inbound `
        -Action Block `
        -RemoteAddress $AttackerIP `
        -Profile Any `
        -Description "Automated SOC Containment triggered at $Timestamp" | Out-Null

    Add-Content -Path $LogFile -Value "[$Timestamp] [FIREWALL_BLOCKED] Successfully applied inbound block rule against $AttackerIP"
} catch {
    # Fallback to netsh if NetSecurity module is restricted
    netsh advfirewall firewall add rule name="$RuleName" dir=in action=block remoteip=$AttackerIP | Out-Null
    Add-Content -Path $LogFile -Value "[$Timestamp] [FIREWALL_BLOCKED_NETSH] Applied block rule via netsh fallback against $AttackerIP"
}

# ------------------------------------------------------------------------------
# 3. CHILD PROCESS AUDIT & TERMINATION (WmiPrvSE Sub-tree)
# Note: Transient commands (cmd.exe /c) often exit within 50ms before AR triggers.
# This loop catches persistent interactive sessions, shells, or beacon payloads.
# ------------------------------------------------------------------------------
try {
    $WmiPids = (Get-Process -Name WmiPrvSE -ErrorAction SilentlyContinue).Id
    $KilledCount = 0

    if ($WmiPids) {
        Get-CimInstance Win32_Process | Where-Object { 
            $_.ParentProcessId -in $WmiPids -and 
            $_.Name -in @('cmd.exe', 'powershell.exe', 'powershell_ise.exe') 
        } | ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
            Add-Content -Path $LogFile -Value "[$Timestamp] [PROCESS_TERMINATED] Terminated active malicious child process: PID $($_.ProcessId) ($($_.Name))"
            $KilledCount++
        }
    }

    if ($KilledCount -eq 0) {
        Add-Content -Path $LogFile -Value "[$Timestamp] [PROCESS_INFO] No persistent child process alive under WmiPrvSE (transient execution exited prior to handler)."
    }
} catch {
    Add-Content -Path $LogFile -Value "[$Timestamp] [ERROR] Process audit error: $_"
}

Add-Content -Path $LogFile -Value "[$Timestamp] [CONTAINMENT_COMPLETE] Host isolation active for $AttackerIP. Threat neutralized."
