#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sentry DLP 미니필터 드라이버를 언로드하고 제거합니다.
#>

$ServiceName = "SentryDLP"
$DriverDest  = "$env:SystemRoot\System32\drivers\sentry_filter.sys"

function Write-Step([string]$msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-OK  ([string]$msg) { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "[~] $msg" -ForegroundColor Yellow }

Write-Step "필터 언로드"
fltMC unload $ServiceName 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { Write-OK "fltMC unload 완료" } else { Write-Warn "이미 언로드된 상태" }

Write-Step "서비스 중지"
sc.exe stop $ServiceName 2>$null | Out-Null

Write-Step "서비스 제거"
sc.exe delete $ServiceName 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { Write-OK "서비스 제거 완료" } else { Write-Warn "서비스가 이미 없음" }

Write-Step "드라이버 파일 삭제"
if (Test-Path $DriverDest) {
    Remove-Item $DriverDest -Force
    Write-OK "삭제 완료: $DriverDest"
} else {
    Write-Warn "파일 없음: $DriverDest"
}

Write-OK "제거 완료"
