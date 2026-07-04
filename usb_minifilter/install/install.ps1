#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sentry DLP 미니필터 드라이버를 설치하고 시작합니다.

.DESCRIPTION
    sentry_filter.sys를 System32\drivers에 복사하고
    sc.exe + fltMC.exe를 통해 등록·로드합니다.
    테스트 서명 모드(Testsigning)를 활성화하는 옵션도 포함합니다.

.PARAMETER SysPath
    빌드된 sentry_filter.sys 파일 경로.
    기본값: 스크립트와 같은 디렉토리의 ..\driver\build\Release\sentry_filter.sys

.PARAMETER EnableTestSigning
    $true 시 bcdedit으로 Testsigning 활성화 (재부팅 필요).
    프로덕션 배포(EV 인증서 서명)에서는 사용하지 않음.

.EXAMPLE
    .\install.ps1 -SysPath "C:\build\sentry_filter.sys"
    .\install.ps1 -EnableTestSigning $true
#>

param(
    [string]$SysPath          = "",
    [bool]  $EnableTestSigning = $false
)

$ServiceName  = "SentryDLP"
$DriverDest   = "$env:SystemRoot\System32\drivers\sentry_filter.sys"
$Altitude     = "265000"

function Write-Step([string]$msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-OK  ([string]$msg) { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Err ([string]$msg) { Write-Host "[!] $msg" -ForegroundColor Red }

# ── sys 파일 경로 결정 ───────────────────────────────────────────────────

if (-not $SysPath) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $SysPath   = Join-Path $ScriptDir "..\driver\build\Release\sentry_filter.sys"
}

$SysPath = Resolve-Path $SysPath -ErrorAction SilentlyContinue
if (-not $SysPath -or -not (Test-Path $SysPath)) {
    Write-Err "sentry_filter.sys를 찾을 수 없습니다: $SysPath"
    Write-Err "먼저 driver/CMakeLists.txt로 빌드하세요."
    exit 1
}

Write-Step "드라이버 파일: $SysPath"

# ── (선택) 테스트 서명 모드 ──────────────────────────────────────────────

if ($EnableTestSigning) {
    Write-Step "Testsigning 모드 활성화 (재부팅 후 적용)"
    bcdedit /set testsigning on | Out-Null
    Write-OK "Testsigning ON"
}

# ── 기존 서비스 정리 ────────────────────────────────────────────────────

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Step "기존 서비스 중지 및 제거"
    fltMC unload $ServiceName 2>$null | Out-Null
    sc.exe stop  $ServiceName  2>$null | Out-Null
    sc.exe delete $ServiceName 2>$null | Out-Null
    Start-Sleep -Seconds 1
}

# ── sys 파일 복사 ────────────────────────────────────────────────────────

Write-Step "드라이버 복사: $DriverDest"
Copy-Item -Path $SysPath -Destination $DriverDest -Force
if (-not (Test-Path $DriverDest)) {
    Write-Err "파일 복사 실패"
    exit 1
}
Write-OK "복사 완료"

# ── 서비스 등록 (sc create) ─────────────────────────────────────────────

Write-Step "서비스 등록: $ServiceName"
sc.exe create $ServiceName `
    type= filesys `
    start= demand `
    error= normal `
    binPath= $DriverDest `
    DisplayName= "Sentry DLP File System Filter" | Out-Null

# Altitude 및 인스턴스 레지스트리 설정
$RegBase = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"

# SupportedFeatures
Set-ItemProperty -Path $RegBase -Name "SupportedFeatures" -Value 3 -Type DWord

# LoadOrderGroup
Set-ItemProperty -Path $RegBase -Name "Group" -Value "FSFilter Activity Monitor" -Type String

# Instances
$InstBase = "$RegBase\Instances"
if (-not (Test-Path $InstBase)) { New-Item -Path $InstBase -Force | Out-Null }
Set-ItemProperty -Path $InstBase -Name "DefaultInstance" -Value "SentryDLP Instance" -Type String

$InstPath = "$InstBase\SentryDLP Instance"
if (-not (Test-Path $InstPath)) { New-Item -Path $InstPath -Force | Out-Null }
Set-ItemProperty -Path $InstPath -Name "Altitude" -Value $Altitude     -Type String
Set-ItemProperty -Path $InstPath -Name "Flags"    -Value 0             -Type DWord

Write-OK "서비스 등록 완료"

# ── fltMC로 로드 ─────────────────────────────────────────────────────────

Write-Step "필터 드라이버 로드 (fltMC load $ServiceName)"
$result = fltMC load $ServiceName 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Err "fltMC load 실패: $result"
    Write-Err "이벤트 뷰어 → 시스템 로그에서 원인을 확인하세요"
    exit 1
}

Write-OK "드라이버 로드 성공"

# ── 확인 ─────────────────────────────────────────────────────────────────

fltMC filters | Select-String $ServiceName
Write-Host ""
Write-OK "설치 완료. 이제 Python 에이전트(main_agent.py)를 관리자 권한으로 실행하세요."
