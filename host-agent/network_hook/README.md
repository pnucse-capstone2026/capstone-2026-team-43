# network_hook — 네트워크·메일 반출 탐지 설계

## 채널 분류 및 커버리지

```
반출 시도
  │
  ├─ [메일] ─────────────────────────────────────────────────────
  │    ├─ Outlook       → outlook_hook.py   (COM ItemSend 이벤트)
  │    └─ 그 외 SMTP   → smtp_proxy.py     (로컬 SMTP 프록시)
  │
  ├─ [HTTP/S 업로드] ─────────────────────────────────────────────
  │    ├─ HTTP(80/8080) → http_monitor.py  (WinDivert 패킷 가로채기)
  │    └─ HTTPS(443)   → [미구현] mitmproxy 또는 WinHTTP API 훅
  │
  ├─ [파일 복사] ─────────────────────────────────────────────────
  │    ├─ USB/이동식    → usb_minifilter/  (커널 미니필터, 3단계)
  │    └─ SMB 공유폴더 → usb_minifilter/  (커널 미니필터, 3단계)
  │
  └─ [기타] ──────────────────────────────────────────────────────
       ├─ FTP/SFTP      → http_monitor 확장 또는 소켓 훅
       └─ VM DnD/RDP    → 게스트 에이전트 또는 프록시 (4단계)
```

## 채널별 구현 현황

| 채널 | 파일 | 상태 | 사전 요구사항 |
|------|------|------|---------------|
| Outlook | `outlook_hook.py` | ✅ 구현 | pywin32, Outlook 설치 |
| SMTP 프록시 | `smtp_proxy.py` | ✅ 구현 | aiosmtpd, aiosmtplib, 클라이언트 설정 변경 |
| HTTP(plain) | `http_monitor.py` | 🔲 스켈레톤 | pydivert, WinDivert 드라이버, 관리자 권한 |
| HTTPS | — | ❌ 미구현 | mitmproxy + 루트 인증서 or WinHTTP DLL 훅 |
| USB/SMB | `usb_minifilter/` | 🔲 3단계 | WDK 커널 드라이버 |

## 공통 파이프라인

```
본문/첨부파일 수신
     │
     ▼ file_inspector.py
텍스트 추출 (.txt/.docx/.pdf/.xlsx)
     │
     ▼ core_comm.rule_filter
정규식 1차 검사
     │
     ├─ 미탐지 → 릴레이 / 전송 허용
     └─ 탐지   → [AI 서버 없을 때] 즉시 차단
                 [AI 서버 있을 때] AI 최종 판단 → 차단/허용
     │
     ▼ core_comm.event_logger
로컬 JSONL 기록 (→ 웹 대시보드 전송)
```

## 설정 파일

`config/channel_policy.json` — 채널별 활성화 여부, 내부 도메인, SMTP 릴레이 설정

```jsonc
{
  "internal_domains": ["company.com", "corp.local"],

  "outlook":  { "enabled": true },

  "smtp": {
    "enabled": true,
    "proxy_port": 2525,
    "relay": {
      "host": "smtp.company.com",
      "port": 587,
      "use_tls": true,
      "username": "...",
      "password": "..."
    }
  },

  "http": {
    "enabled": false,
    "inspect_ports": [80, 8080]
  }
}
```

## 각 채널 활성화 방법

### Outlook COM 훅

에이전트 실행 전 Outlook이 열려 있어야 합니다.  
`channel_policy.json` → `outlook.enabled: true` 후 에이전트 재시작.

### SMTP 프록시

1. `channel_policy.json` → `smtp.enabled: true`, `relay` 섹션에 실제 SMTP 정보 입력
2. 메일 클라이언트 발신 서버 변경:
   - 호스트: `127.0.0.1`
   - 포트: `2525` (또는 `proxy_port` 값)
   - 인증: 없음

> Outlook을 SMTP 프록시와 함께 쓰면 **이중 탐지**가 됩니다.
> COM 훅이 우선이므로, Outlook은 `smtp.enabled: false`로 두는 것을 권장합니다.

### HTTP 모니터

1. [WinDivert](https://reqrypt.org/windivert.html) 드라이버 설치 (관리자 권한)
2. `pip install pydivert`
3. `channel_policy.json` → `http.enabled: true`
4. **에이전트를 관리자 권한으로 실행**

> HTTPS(443)는 TLS 암호화로 패킷 내용 검사 불가.
> 향후 mitmproxy 방식 또는 WinHTTP API 훅(C++ DLL)으로 대응 예정.

## HTTPS 처리 방안 (미구현 — 설계 메모)

| 방안 | 장점 | 단점 |
|------|------|------|
| **mitmproxy 투명 프록시** | 범용, 브라우저 포함 | 루트 인증서 배포 필요, certificate pinning 앱 우회 불가 |
| **WinHTTP/WinInet API 훅** (C++ DLL) | 암호화 전 평문 접근 | 드라이버 서명, AV 경고 가능 |
| **네트워크 경계 DLP** | 인증서 걱정 없음 | 엔드포인트 외 추가 인프라 |
