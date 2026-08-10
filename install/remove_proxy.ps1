# Sentry Host Agent - HTTPS MITM proxy teardown
# 1) disable system proxy
# 2) remove mitmproxy CA from Root store (admin recommended)

$ErrorActionPreference = "Continue"

function Write-Step {
    param([int]$N, [string]$Msg)
    Write-Host ""
    Write-Host "[$N] $Msg" -ForegroundColor Cyan
}
function Write-OK {
    param([string]$Msg)
    Write-Host "    OK  $Msg" -ForegroundColor Green
}

function Notify-ProxyChange {
    $code = @'
using System;
using System.Runtime.InteropServices;
public class SentryWinINetRemove {
    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int lpdwBufferLength);
    public static void NotifyChange() {
        InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
    }
}
'@
    try {
        if (-not ([System.Management.Automation.PSTypeName]"SentryWinINetRemove").Type) {
            Add-Type -TypeDefinition $code
        }
        [SentryWinINetRemove]::NotifyChange()
    } catch {}
}

Write-Step 1 "Disable system proxy"
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty -Path $regPath -Name "ProxyEnable" -Value 0
Notify-ProxyChange
Write-OK "Proxy disabled"

Write-Step 2 "Remove mitmproxy CA from Root store"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    & certutil -delstore Root "mitmproxy" 2>&1 | Out-Null
    Write-OK "CA removed (if it was present)"
} else {
    Write-Host "    WARN  Not admin. Remove cert manually via certmgr.msc (Trusted Root)."
}

Write-Host ""
Write-OK "Teardown complete."
