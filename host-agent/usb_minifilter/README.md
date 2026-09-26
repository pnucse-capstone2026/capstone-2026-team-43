# usb_minifilter — 파일시스템 미니필터 DLP

USB 드라이브와 네트워크 공유(SMB)로의 파일 반출을 커널 수준에서 차단합니다.

## 아키텍처

```
파일 쓰기/생성/이동
     │
     ▼
┌─────────────────────────────┐
│  sentry_filter.sys (커널)   │  ← Filter Manager에 altitude 265000으로 등록
│  IRP_MJ_CREATE pre-op       │
│  IRP_MJ_WRITE  pre-op       │
│  IRP_MJ_SET_INFORMATION     │ (rename/move)
└────────────┬────────────────┘
             │ FltSendMessage (필터 통신 포트)
             ▼
┌─────────────────────────────┐
│  file_guard.py (유저모드)   │  ← main_agent.py에서 시작
│  FilterGetMessage 수신      │
│  FileInspector (내용 추출)  │
│  RuleFilter (정규식 1차)    │
│  PayloadBuilder + ApiClient │
│  FilterReplyMessage 응답    │
└─────────────────────────────┘
             │ SENTRY_BLOCK
             ▼
    STATUS_ACCESS_DENIED
```

## 탐지 대상

| 대상 | 플래그 | 설명 |
|------|--------|------|
| USB / 이동식 미디어 | `SENTRY_FLAG_USB` | `FILE_REMOVABLE_MEDIA` 볼륨 특성으로 감지 |
| 네트워크 공유 (SMB) | `SENTRY_FLAG_NETWORK` | `FILE_DEVICE_NETWORK_FILE_SYSTEM` 볼륨 유형으로 감지 |

## 빌드

### 사전 조건
- Windows Driver Kit (WDK) 10.0.26100 이상
- Visual Studio 2022 + WDK 확장
- CMake 3.25+

### 빌드 방법

```powershell
# Developer PowerShell for VS 2022
cd usb_minifilter\driver
mkdir build; cd build
cmake .. -G "Visual Studio 17 2022" -A x64 `
    -DCMAKE_SYSTEM_NAME=Windows `
    -DCMAKE_SYSTEM_VERSION=10.0
cmake --build . --config Release
# 결과: build\Release\sentry_filter.sys
```

> **테스트 환경**: 드라이버에 서명이 없으면 Testsigning 모드가 필요합니다.
> 프로덕션 배포 시에는 EV 코드 서명 인증서가 필요합니다.

## 설치

```powershell
# 관리자 PowerShell
# 테스트 환경에서 Testsigning 활성화 (한 번만, 재부팅 필요)
.\install\install.ps1 -EnableTestSigning $true

# 재부팅 후 드라이버 설치
.\install\install.ps1 -SysPath ".\driver\build\Release\sentry_filter.sys"
```

## 에이전트 활성화

`config/channel_policy.json`에서 `file_guard.enabled`를 `true`로 변경:

```json
"file_guard": {
  "enabled": true,
  "block_usb": true,
  "block_network_share": true
}
```

에이전트를 **관리자 권한**으로 실행해야 필터 포트에 연결됩니다:

```powershell
# 관리자 PowerShell
python main_agent.py
```

## 제거

```powershell
.\install\uninstall.ps1
```

## 설계 결정

| 항목 | 결정 | 이유 |
|------|------|------|
| Altitude | 265000 | FSFilter Activity Monitor / Content Screener 범위 |
| Fail-Open | 에이전트 미연결·타임아웃 시 허용 | 사용자 업무 차단 최소화 |
| 타임아웃 | 5초 | DLP 분석 최대 허용 시간 |
| 커널 모드 I/O | 건너뜀 | 시스템 안정성 (무결성 검사 제외) |
| HTTPS 검사 | 미지원 | TLS 종단간 암호화로 내용 접근 불가 |
