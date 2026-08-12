#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Removes Sentry DLP kernel driver and restores system security settings.
    Run as Administrator, then reboot.
#>

function Write-Step([string]$msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-OK  ([string]$msg) { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "[~] $msg" -ForegroundColor Yellow }

$ServiceName = "SentryDLP"
$DriverDest  = "$env:SystemRoot\System32\drivers\sentry_filter.sys"
$CertSubject = "Sentry DLP Test Cert"

# ── 1. minifilter unload + service delete ────────────────────────────────
Write-Step "Unloading and removing kernel driver service"
& fltMC unload $ServiceName 2>$null | Out-Null
& sc.exe stop   $ServiceName 2>$null | Out-Null
& sc.exe delete $ServiceName 2>$null | Out-Null
Start-Sleep -Seconds 1
Write-OK "Service removed"

# ── 2. remove driver file ────────────────────────────────────────────────
Write-Step "Removing driver file"
if (Test-Path $DriverDest) {
    Remove-Item $DriverDest -Force
    Write-OK "Removed: $DriverDest"
} else {
    Write-Warn "Already removed: $DriverDest"
}

# ── 3. disable testsigning ───────────────────────────────────────────────
Write-Step "Disabling testsigning"
bcdedit /set testsigning off | Out-Null
Write-OK "Testsigning OFF"

# ── 4. re-enable Memory Integrity (HVCI) ─────────────────────────────────
Write-Step "Re-enabling Memory Integrity (HVCI)"
$hvciPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
if (Test-Path $hvciPath) {
    Set-ItemProperty -Path $hvciPath -Name "Enabled" -Value 1 -Type DWord
    Write-OK "Memory Integrity re-enabled"
} else {
    Write-Warn "HVCI registry key not found - may already be managed by firmware/policy"
}

# ── 5. remove test certificates ──────────────────────────────────────────
Write-Step "Removing test certificates"
foreach ($storeName in @("My","Root","TrustedPublisher")) {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName,"LocalMachine")
    $store.Open("ReadWrite")
    $certs = $store.Certificates | Where-Object { $_.Subject -like "*$CertSubject*" }
    foreach ($c in $certs) {
        $store.Remove($c)
        Write-OK "Removed cert from LocalMachine\$storeName : $($c.Thumbprint)"
    }
    $store.Close()
}

# ── 6. summary ───────────────────────────────────────────────────────────
Write-Host ""
Write-Host "======================================================" -ForegroundColor Green
Write-Host "  Restore complete." -ForegroundColor Green
Write-Host "  REBOOT NOW to apply testsigning OFF + HVCI ON." -ForegroundColor Green
Write-Host "======================================================" -ForegroundColor Green
Write-Host ""
$reboot = Read-Host "Reboot now? (y/n)"
if ($reboot -eq "y") { Restart-Computer }
