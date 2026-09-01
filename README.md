# AI 기반 Host DLP 웹 대시보드

Host Agent가 전송한 민감정보 반출 탐지 로그를 저장하고, 관리자가 통계와 상세 탐지 근거를 확인할 수 있도록 만든 FastAPI 기반 웹 대시보드입니다.

현재 구현 범위는 다음과 같습니다.

- payload hash를 포함한 `event_id` 멱등 저장과 충돌 감사
- 필수 전역 Agent Token 또는 Agent별 분리 토큰 인증
- Agent 프로세스 heartbeat 저장과 90초 기준 생존 상태·버전 조회
- LAN에서 필수인 viewer/admin HTTPS Basic 접근 제어(`/docs` 포함)
- 탐지 로그 검색, 필터, 목록 및 상세 조회
- 최근 7일 KPI, 탐지 추이, 채널 분포, 부서별 탐지 건수 시각화
- 고위험 이벤트와 Evidence 상세 분석
- `log_id` 커서 기반 2초 주기 준실시간 위험 알림과 자동 활성화 경고음
- AI 성공·실패·미실행 상태 분리와 정상 AI 결과 전용 평균·실패율 KPI
- 명시적인 `confidence_score` 0~1 계약의 외부 AI 전달 구조
- 정책 조회·생성 API와 append-only 생성 감사 기록

## 1. 기술 구성

- Python 3.10 이상
- FastAPI 0.135.2
- Uvicorn 0.42.0
- SQLite
- HTML/CSS/JavaScript
- Chart.js CDN

## 2. 디렉터리 구조

```text
web/
├── backend/
│   ├── main.py                 # FastAPI 앱, API, DB 초기화
│   └── dlp_dashboard.db        # 실행 중 생성되는 로컬 SQLite DB
├── frontend/
│   └── index.html              # Dashboard/Logs 단일 페이지 UI
├── scripts/
│   ├── seed_demo_data.py       # 현재 날짜 기준 대시보드 데모 데이터 생성
│   └── send_sample_log.py      # Agent 로그 및 AI 분석 흐름 시연 스크립트
├── run_dashboard.py            # bind 주소·인증·HTTPS를 검증하는 실행 진입점
├── tests/
│   ├── conftest.py             # 임시 DB와 TestClient 공통 fixture
│   ├── test_api.py             # API·DB·AI 자동화 테스트
│   ├── test_e2e.py             # 실제 Chromium 핵심 사용자 흐름 테스트
│   └── test_send_sample_log.py # fixture 전송 스크립트 테스트
├── .env.example                # 환경변수 예시
├── pytest.ini                  # pytest 실행 설정
├── requirements.txt            # 실행 의존성
└── requirements-dev.txt        # 개발·테스트 의존성
```

`backend/dlp_dashboard.db`는 로컬 실행 데이터이므로 Git 병합 대상에서 제외합니다. 서버가 시작될 때 DB와 필수 테이블이 없으면 자동으로 생성됩니다.

## 3. 설치

프로젝트의 `web` 디렉터리에서 실행합니다.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Windows PowerShell에서는 가상환경을 다음과 같이 활성화합니다.

```powershell
.venv\Scripts\Activate.ps1
```

TestClient와 이후 자동화 테스트까지 실행할 개발 환경은 다음 의존성을 설치합니다.

```bash
python -m pip install -r requirements-dev.txt
python -m playwright install chromium
```

## 4. 환경변수

지원되는 환경변수는 다음과 같습니다.

| 이름 | 필수 여부 | 기본 동작 | 설명 |
| --- | --- | --- | --- |
| `AGENT_API_TOKEN` | 둘 중 하나 필수 | 없음 | 모든 Agent가 공유하는 32자 이상 ASCII 토큰 |
| `AGENT_API_TOKENS_JSON` | 둘 중 하나 필수 | 없음 | Agent별 토큰 JSON. 예: `{"agent-01":"32자 이상..."}`. 전역 토큰과 동시 사용 불가 |
| `AI_SERVER_URL` | 선택 | Web AI 중계 비활성 | Web의 `/api/v1/analyze`가 전달할 실제 AI 서버 주소 |
| `AI_SERVER_TOKEN` | 외부 AI 사용 시 필수 | 미사용 | 외부 AI 서버의 `AI_API_TOKEN`과 같은 32자 이상 ASCII Bearer 토큰 |
| `AI_SERVER_TIMEOUT_SECONDS` | 선택 | `5` | 외부 AI 서버 응답 대기 시간(초) |
| `HIGH_RISK_SCORE_THRESHOLD` | 선택 | `0.85` | Web 대시보드에서 고위험으로 표시할 AI 점수 임계값. `0.0`~`1.0` |
| `DASHBOARD_VIEWER_USERNAME` | 인증 활성 시 필수 | 인증 비활성 | 대시보드를 조회할 viewer ASCII 사용자명 |
| `DASHBOARD_VIEWER_PASSWORD` | 인증 활성 시 필수 | 인증 비활성 | viewer의 16자 이상 ASCII 비밀번호 |
| `DASHBOARD_ADMIN_USERNAME` | 인증 활성 시 필수 | 인증 비활성 | viewer와 다른 admin ASCII 사용자명 |
| `DASHBOARD_ADMIN_PASSWORD` | 인증 활성 시 필수 | 인증 비활성 | admin의 16자 이상 ASCII 비밀번호 |

팀 공유 또는 시연 환경에서는 예시 파일을 복사한 뒤 토큰을 반드시 교체합니다.

```bash
cp .env.example .env
```

`.env` 파일은 자동으로 Git에 포함되지 않습니다. 실제 토큰은 문서나 소스 코드에 기록하지 않습니다.

## 5. 서버 실행

### 5.1 로컬 실행

기본 토큰은 없습니다. `.env`에 최소 32자 임의 `AGENT_API_TOKEN`을 설정한 뒤 보안 검증 실행기를 사용합니다. `uvicorn backend.main:app` 직접 실행은 검증을 우회할 수 있으므로 서버 시작 단계에서 거부됩니다.

```bash
python run_dashboard.py --host 127.0.0.1 --port 8000 --env-file .env
```

실행 후 확인 URL은 다음과 같습니다.

| 화면 또는 API | URL |
| --- | --- |
| 대시보드 | `http://127.0.0.1:8000/dashboard` |
| 로그 상세 분석 | `http://127.0.0.1:8000/logs` |
| Swagger API 문서 | `http://127.0.0.1:8000/docs` |
| 상태 확인 | `http://127.0.0.1:8000/health` |

`/health`의 `analysis_mode`는 Web AI 중계가 설정되면 `external`, 아니면 `disabled`입니다. Host가 AI Server를 직접 호출하는 기본 통합 경로에는 영향을 주지 않습니다. `database_status` 값이 `ok`인지 확인해 SQLite 준비 상태를 점검할 수 있습니다.

### 5.3 두 컴퓨터 시연

두 컴퓨터가 같은 중앙 Web 서버를 사용해야 합니다. 비-loopback 주소는 대시보드 인증과 HTTPS 인증서·키가 모두 없으면 시작되지 않습니다.

```bash
python run_dashboard.py --host <SERVER_LAN_IP> --port 8443 --env-file .env \
  --ssl-certfile cert.pem --ssl-keyfile key.pem
```

대시보드 PC에서는 `https://<SERVER_LAN_IP>:8443/dashboard`를 엽니다. 경고음은 브라우저 자동 재생 정책에 따라 첫 클릭이나 키 입력 뒤 활성화될 수 있습니다. Host Agent의 Git 제외 로컬 설정은 다음 서버를 가리킵니다.

```yaml
server:
  dashboard_url: "https://<SERVER_LAN_IP>:8443"
  dashboard_token: "<AGENT_API_TOKEN과 동일한 값>"

logging:
  send_immediately: true
```

대시보드를 먼저 연 뒤 Host Agent에서 반출 시나리오를 실행하면 새 고위험 이벤트가 약 2초 안에 표시됩니다. TLS를 reverse proxy에서 종료하려면 Web 앱은 loopback에 바인딩하고 proxy만 LAN에 공개합니다.

### 5.4 대시보드 HTTP Basic 인증

loopback에서는 대시보드 인증을 생략할 수 있지만 LAN 바인딩에서는 필수입니다. 네 viewer/admin 값을 일부만 설정하거나 안전성 검증에 실패하면 시작이 중단됩니다. 인증이 활성화된 모든 요청은 HTTPS가 아니면 HTTP `426`으로 거부됩니다.

- viewer와 admin은 `/dashboard`, `/logs`, `/docs`, `/redoc`, `/openapi.json` 및 조회 API를 사용할 수 있습니다.
- `POST /api/v1/policies`는 인증 활성 시 admin만 호출할 수 있으며 viewer는 HTTP `403`을 받습니다. 인증 비활성 시에는 기존처럼 `X-Agent-Token`을 사용합니다.
- `GET /api/v1/policy-audit`도 인증 활성 시 admin만 조회할 수 있으며, 인증 비활성 시에는 `X-Agent-Token`을 사용합니다. 응답에는 실제 토큰이나 비밀번호가 아닌 `dashboard-admin` 또는 `agent-token` actor label만 포함됩니다.
- `GET /api/v1/ingest-conflicts`도 admin 전용이며 동일 event ID에 다른 payload가 들어온 충돌 기록을 조회합니다.
- `/api/v1/agent-check`, `POST /api/v1/analyze`, `POST /api/v1/logs`, `POST /api/v1/agents/heartbeat`는 대시보드 인증 여부와 관계없이 계속 `X-Agent-Token`만 사용합니다.
- `GET /api/v1/agents`는 다른 조회 API와 동일하게 인증 활성 시 viewer/admin Basic 자격 증명이 필요하며 `X-Agent-Token`으로 대신할 수 없습니다.
- `/health`는 공개 상태 확인용으로 유지되며 `dashboard_auth_enabled`만 노출하고 사용자명과 비밀번호는 노출하지 않습니다.

브라우저로 HTTPS `/dashboard`를 열면 HTTP `401` 응답의 Basic 인증 창이 나타납니다. 브라우저가 같은 origin의 `fetch` 요청에 자격 증명을 재사용하므로 JavaScript에 비밀번호를 저장하지 않습니다.

Host 통합 검증기가 저장 후 `GET /api/v1/logs`로 readback할 때도 인증이 활성화되어 있으면 Web 서버와 같은 `DASHBOARD_VIEWER_USERNAME`, `DASHBOARD_VIEWER_PASSWORD`를 HTTP Basic으로 전송해야 합니다. `X-Agent-Token`은 Agent 쓰기 API용이므로 인증이 활성화된 조회 API의 readback 자격 증명을 대신하지 않습니다.

## 6. 주요 API

| Method | Path | 인증 | 용도 |
| --- | --- | --- | --- |
| `GET` | `/health` | 불필요 | 서버·SQLite 준비 상태와 AI 분석 모드 확인 |
| `GET` | `/api/v1/agent-check` | `X-Agent-Token` | 로그를 남기지 않고 Host 인증·연결 확인 |
| `POST` | `/api/v1/agents/heartbeat` | `X-Agent-Token` | Agent 프로세스 생존 시각과 버전 upsert |
| `GET` | `/api/v1/agents` | HTTP Basic(활성 시) | Agent 프로세스별 online/stale 상태 조회 |
| `POST` | `/api/v1/analyze` | `X-Agent-Token` | 설정된 외부 AI 서버로 분석 요청 전달. 미설정 시 `503` |
| `POST` | `/api/v1/logs` | `X-Agent-Token` | Host Agent 탐지 로그 저장 |
| `GET` | `/api/v1/logs` | HTTP Basic(활성 시) | 로그 검색·필터와 서버 페이지 조회 |
| `GET` | `/api/v1/logs/filter-options` | HTTP Basic(활성 시) | 부서·사용자·Agent 필터 목록 조회 |
| `GET` | `/api/v1/logs/{log_id}` | HTTP Basic(활성 시) | 개별 로그 상세 조회 |
| `GET` | `/api/v1/dashboard/summary` | HTTP Basic(활성 시) | 최근 기간 KPI와 차트 데이터 조회 |
| `GET` | `/api/v1/alerts` | HTTP Basic(활성 시) | 고위험 신규 로그를 `log_id` 커서로 조회 |
| `GET` | `/api/v1/policies` | HTTP Basic(활성 시) | 정책 목록 조회 |
| `POST` | `/api/v1/policies` | admin Basic(활성) / `X-Agent-Token`(비활성) | 정책 생성 |
| `GET` | `/api/v1/policy-audit` | admin Basic(활성) / `X-Agent-Token`(비활성) | 최신 정책 생성 감사 기록 조회 |
| `GET` | `/api/v1/ingest-conflicts` | admin Basic(활성) / `X-Agent-Token`(비활성) | event ID payload 충돌 감사 기록 조회 |

정확한 요청 필드와 허용값은 실행 중인 서버의 `/docs`에서 확인할 수 있습니다.

`GET /api/v1/logs`는 기존 필터와 함께 `limit`(기본 50, 1~200) 및
`offset`(기본 0, 0 이상)을 받습니다. 응답의 `count`는 현재 페이지 건수,
`total`은 같은 필터에 맞는 전체 건수이며 적용된 `limit`과 `offset`도 함께
반환합니다. 로그 화면은 이 API를 10건씩 요청하므로 200건을 넘는 이력도
이전·다음 버튼으로 계속 조회할 수 있습니다.

### 6.1 준실시간 위험 알림

대시보드를 열면 현재 최신 `log_id`를 기준선으로 저장한 뒤 2초마다 신규 고위험 로그를 조회합니다. 기존 이력은 토스트로 재생하지 않고, 화면을 연 뒤 저장된 다음 조건의 이벤트만 알립니다.

- `action_taken == BLOCKED`
- `analysis_status == SUCCESS`이면서 `ai_score >= HIGH_RISK_SCORE_THRESHOLD` (기본값 `0.85`)

신규 이벤트가 있으면 우측 상단에 빨간 위험 알림이 표시되고, `상세 로그 보기`로 해당 `log_id`의 분석 화면을 열 수 있습니다. 경고음 토글은 없으며 페이지가 열릴 때 항상 활성화를 시도합니다. 브라우저가 자동 재생을 제한하면 첫 클릭 또는 키 입력에서 오디오 컨텍스트를 자동으로 재개합니다.

커서 API 동작:

- 첫 요청에서 `after_log_id`를 생략하면 `items` 없이 현재
  `next_cursor`와 SQLite 세대 ID인 `cursor_epoch`를 반환
- 이후 `after_log_id=<next_cursor>&cursor_epoch=<cursor_epoch>`로
  오름차순 신규 위험 이벤트 조회
- 한 번에 20건, 최대 100건을 반환하며 잔여 건은 다음 커서 요청에서 이어서 조회
- SQLite가 재생성되어 세대 ID가 달라지면 `cursor_reset: true`와 함께
  새 DB에 이미 저장된 고위험 이벤트부터 다시 전달
- 5초 타임아웃과 최대 30초 재시도 지연, 백그라운드 탭 중지로 불필요한 중복 요청 방지
- 탭이 다시 표시되면 저장한 커서 이후 이벤트를 즉시 조회

이 기능은 WebSocket이나 SSE가 아닌 HTTP 폴링 방식입니다. 화면에는 `실시간 알림`으로 표시하지만 정확한 기술 범위는 약 2초 지연의 시연용 준실시간 알림입니다.

`HIGH_RISK_SCORE_THRESHOLD`는 Web의 고위험 표시 기준만 바꾸며 Host Agent가 기록한 `action_taken`을 다시 계산하지 않습니다. 값을 바꾼 뒤에는 Web 서버를 재시작하고 `/health`의 `high_risk_score_threshold`로 적용값을 확인합니다.

### 6.2 Agent 프로세스 heartbeat

Host Agent는 `POST /api/v1/agents/heartbeat`에 다음 네 필드를 보내 프로세스 생존 상태를 보고할 수 있습니다. Web 서버는 클라이언트 시각을 받지 않고 수신 시각을 `last_seen_at`으로 기록하며, 같은 `(agent_id, mode)`는 새 행을 늘리지 않고 최신 hostname·버전·시각으로 갱신합니다.

| 필드 | 제약 및 설명 |
| --- | --- |
| `agent_id` | 1~100자. 장치를 구분하는 안정적인 Agent 식별자 |
| `hostname` | 1~100자. 보고한 Host 이름 |
| `agent_version` | 1~50자의 영문·숫자와 `.`, `_`, `+`, `-` 조합 |
| `mode` | `user`, `system`, `all` 중 하나. 같은 장치의 실행 프로세스를 구분 |

`GET /api/v1/agents`는 마지막 보고 후 90초 이내인 행을 `online`, 그보다 오래된 행을 `stale`로 계산하고 `online_count`, `stale_count`, `heartbeat_ttl_seconds`, 서버 확인 시각을 반환합니다. 대시보드 상단도 이 API를 처음 열 때와 이후 30초마다 조회해 프로세스 수와 보고된 버전을 표시합니다. 브라우저 탭이 숨겨지면 폴링을 멈추고 다시 보일 때 즉시 재개합니다.

이 상태는 **Agent 프로세스가 heartbeat를 보냈다는 사실만** 나타냅니다. Clipboard·USB·Outlook·WebProxy 등 개별 채널이 정상인지, 실제 Windows 훅이 동작했는지 또는 LAN 시연이 완료됐다는 증거가 아닙니다. 종료·장애 시 별도 offline 요청에 의존하지 않고 90초 후 `stale`로 전환됩니다.

### 6.3 Agent 로그 연동 규칙

- 요청 헤더: `X-Agent-Token: <AGENT_API_TOKEN>`
- Agent별 토큰 모드 요청 헤더: `X-Agent-ID: <agent_id>`도 필수이며 payload의 `agent_id`와 일치해야 함
- `timestamp`: UTC offset을 포함한 ISO 8601 형식 필수
- `event_id`: AI 요청부터 Web 저장까지 같은 이벤트를 증명하는 필수 ID
- `analysis_status`: `SUCCESS`, `FAILED`, `SKIPPED`
- `ai_score`: `SUCCESS`일 때만 `0.0`~`1.0`, 그 외에는 `null`
- `action_taken`: `BLOCKED`, `WARNED`, `ALLOWED`
- `leak_channel`: `USB_COPY`, `WEB_UPLOAD`, `EMAIL_ATTACHMENT`, `PRINT`, `MESSENGER`, `CLIPBOARD`, `CLOUD_DRIVE`
- 최초 저장: HTTP `201`, `duplicate: false`
- 같은 ID·같은 payload hash 재전송: HTTP `200`, `duplicate: true`
- 같은 ID·다른 payload hash: HTTP `409`, 충돌 감사 기록 추가

샘플 JSON은 실제 전송 없이 다음 명령으로 확인할 수 있습니다.

```bash
python scripts/send_sample_log.py --scenario web_upload --dry-run
```

### 6.4 로그 수집 요청 데이터 구조

Host Agent는 `POST /api/v1/logs`로 탐지 결과를 전송합니다. 요청 헤더에는 서버의 `AGENT_API_TOKEN`과 동일한 `X-Agent-Token`을 포함해야 합니다.

| 필드 | JSON 타입 | 필수 여부 | 제약 및 설명 |
| --- | --- | --- | --- |
| `event_id` | string | 필수 | 1~120자. AI 요청과 동일한 Agent 이벤트 ID이며 재전송 중복 방지 키 |
| `agent_id` | string | 선택 | 최대 100자. 이벤트를 전송한 Host Agent 식별자 |
| `timestamp` | string | 필수 | UTC offset을 포함한 ISO 8601 발생 시각 |
| `host_ip` | string | 필수 | 7~45자. 이벤트 발생 Host IP |
| `hostname` | string | 필수 | 1~100자. 이벤트 발생 Host 이름 |
| `user_id` | string | 필수 | 1~100자. 이벤트 발생 사용자 식별자 |
| `department` | string | 필수 | 1~100자. 사용자 소속 부서 |
| `file_name` | string | 필수 | 1~255자. 반출 대상 파일명 |
| `file_path` | string | 선택 | 최대 500자. 반출 대상 파일의 원본 경로 |
| `process_name` | string | 선택 | 최대 120자. 반출을 시도한 프로세스 |
| `leak_channel` | string | 필수 | `USB_COPY`, `WEB_UPLOAD`, `EMAIL_ATTACHMENT`, `PRINT`, `MESSENGER`, `CLIPBOARD`, `CLOUD_DRIVE` |
| `detection_type` | string | 필수 | `RULE_BASED`, `AI_MODEL`, `HYBRID` |
| `analysis_status` | string | 필수 | `SUCCESS`, `FAILED`, `SKIPPED` |
| `ai_score` | number/null | 조건부 | `SUCCESS`이면 `0.0`~`1.0` 필수, `FAILED`·`SKIPPED`이면 `null` 필수 |
| `model_version` | string | 선택 | 최대 100자. AI 판별에 사용된 모델 버전. 규칙 전용 판정이면 생략 가능 |
| `matched_keywords` | string[] | 선택 | 최대 100개, 각 1~100자. 탐지에 사용된 키워드. 생략 시 빈 배열 |
| `policy_id` | string | 선택 | 최대 100자. 적용된 Agent/서버 정책 식별자 |
| `action_taken` | string | 필수 | `BLOCKED`, `WARNED`, `ALLOWED` |
| `decision_reason` | string | 선택 | 최대 500자. Agent의 최종 조치 판단 사유 |
| `evidence_summary` | string | 선택 | 최대 500자. 관리자에게 표시할 탐지 근거 요약 |
| `latency_ms` | integer | 선택 | `0`~`600000`. 분석 및 조치 지연 시간(ms) |

전체 요청 예시:

```json
{
  "event_id": "agent-01-web-upload-20260813-001",
  "agent_id": "sentry-agent-01",
  "timestamp": "2026-08-13T11:21:00+00:00",
  "host_ip": "192.168.10.42",
  "hostname": "employee-pc-01",
  "user_id": "research_user",
  "department": "R&D",
  "file_name": "prototype_source_export.zip",
  "file_path": "C:\\Research\\prototype_source_export.zip",
  "process_name": "chrome.exe",
  "leak_channel": "WEB_UPLOAD",
  "detection_type": "HYBRID",
  "analysis_status": "SUCCESS",
  "ai_score": 0.96,
  "model_version": "koelectra-dlp-v7",
  "matched_keywords": ["source_code", "api_key", "prototype"],
  "policy_id": "DLP-WEB-001",
  "action_taken": "BLOCKED",
  "decision_reason": "AI score exceeded the web upload block threshold.",
  "evidence_summary": "Source code and API key patterns were detected.",
  "latency_ms": 132
}
```

최초 저장 응답은 HTTP `201`입니다.

```json
{
  "message": "Log saved successfully.",
  "log_id": 37,
  "event_id": "agent-01-web-upload-20260813-001",
  "duplicate": false
}
```

동일한 `event_id`와 동일한 canonical payload hash를 다시 전송하면 HTTP `200`으로 기존 `log_id`를 반환합니다. 내용이 하나라도 다르면 HTTP `409`이며 `dlp_ingest_conflicts`에 두 hash와 Agent ID를 기록합니다.

```json
{
  "message": "Log already exists.",
  "log_id": 37,
  "event_id": "agent-01-web-upload-20260813-001",
  "duplicate": true
}
```

### 6.5 AI 분석 요청·응답 구조

Host Agent의 기본 경로는 AI Server를 직접 호출합니다. Web의 `POST /api/v1/analyze`는 보조 중계 경로이며 `AI_SERVER_URL`이 설정된 경우에만 동작합니다. 내부 Mock 판정은 운영 경로에서 제거했습니다.

요청 필드:

| 필드 | JSON 타입 | 필수 여부 | 제약 및 설명 |
| --- | --- | --- | --- |
| `event_id` | string | 필수 | 1~120자. 이후 로그 저장 요청과 동일한 ID 사용 |
| `channel` | string | 필수 | `clipboard`, `outlook`, `http`, `usb`, `smtp`, `web_mail`, `file_guard`, `drive_upload`, `web_upload`, `email_attachment`, `print`, `messenger` |
| `user_id` | string | 필수 | 1~100자. 분석 대상 사용자 식별자 |
| `matched_patterns` | string[] | 선택 | 최대 100개, 각 1~100자. Agent 규칙 탐지 단계에서 찾은 패턴 목록 |
| `snippet` | string | 필수 | 1~4000자. AI가 분석할 텍스트 또는 요약 |
| `metadata` | object | 선택 | 최대 50개 항목. 키 1~100자, 문자열 값 최대 500자, 수치는 유한값만 허용. 앱, 목적지, 파일명, 심각도 등 추가 문맥 |

요청 예시:

```json
{
  "event_id": "agent-01-web-upload-20260813-001",
  "channel": "web_upload",
  "user_id": "research_user",
  "matched_patterns": ["source_code", "api_key"],
  "snippet": "Prototype source archive includes an internal API key.",
  "metadata": {
    "app": "chrome.exe",
    "dest": "external",
    "severity_hint": "high",
    "file_name": "prototype_source_export.zip"
  }
}
```

로그·분석·정책 생성 요청은 문서에 없는 추가 필드를 422로 거절해 필드명 오타가 조용히 누락되지 않게 합니다.

웹 서버가 Agent에 반환하는 정규화 응답:

| 필드 | JSON 타입 | 설명 |
| --- | --- | --- |
| `event_id` | string | 요청 이벤트 식별자 |
| `decision` | string | `allow`, `review`, `block` |
| `confidence_score` | number | AI Server가 명시적으로 반환한 `0.0`~`1.0` 점수 |
| `model_version` | string | 분석 모델 버전 |
| `latency_ms` | integer | 분석 응답 지연 시간(ms) |
| `reason` | string | Host Agent가 판정 로그와 알림에 사용하는 분석 사유 |
| `evidence_summary` | string | AI 분석 근거 요약 |

```json
{
  "event_id": "agent-01-web-upload-20260813-001",
  "decision": "block",
  "confidence_score": 0.96,
  "model_version": "team-ai-v1",
  "latency_ms": 132,
  "reason": "Source code and API key context was detected.",
  "evidence_summary": "Source code and API key context was detected."
}
```

`reason`은 Host Agent 응답 파서가 직접 읽는 필수 호환 필드입니다. 기존 대시보드·로그 연동을 위해 `evidence_summary`도 함께 반환하며, 외부 AI가 둘 중 하나만 반환하면 웹 서버가 다른 필드를 같은 내용으로 채웁니다.

Web 분석 fixture가 AI 판정을 로그 필드로 바꿀 때 사용하는 기본 규칙:

| AI `decision` | 로그 `action_taken` |
| --- | --- |
| `allow` | `ALLOWED` |
| `review` | `WARNED` |
| `block` | `BLOCKED` |

실제 Host Agent는 이 표를 그대로 확정 결과로 쓰지 않습니다. AI `block`이어도 USB 삭제 실패·파일 변경처럼 실제 차단을 확인하지 못하면 `WARNED`, AI `allow`·`review`여도 Clipboard 재발행에 실패하면 `WARNED`로 기록해 운영체제 조치 결과를 우선합니다.

외부 AI 서버는 `confidence_score`만 반환해야 합니다. `ai_score`, `score`, 문자열 점수, 0~100 척도는 추측하거나 환산하지 않고 HTTP `502`로 거절합니다.

### 6.6 SQLite 데이터 구조

SQLite 파일은 `backend/dlp_dashboard.db`에 생성되지만 Git에는 포함하지 않습니다. 팀원 간 데이터 연동은 DB 파일을 공유하지 않고 위 REST API 계약을 기준으로 합니다.

기존 DB는 시작 시 nullable AI 점수 구조로 이관됩니다. `model_version=unavailable`인 기존 사건은 `FAILED`, 모델 없는 순수 `RULE_BASED` 사건은 `SKIPPED`, 나머지는 `SUCCESS`로 이관하고 payload hash를 backfill합니다.

`dlp_logs` 테이블:

| 컬럼 | SQLite 타입 | 제약 및 설명 |
| --- | --- | --- |
| `log_id` | INTEGER | Primary Key, Auto Increment |
| `event_id` | TEXT | Agent 이벤트 ID. 값이 있을 때 Unique |
| `agent_id` | TEXT | Agent 식별자 |
| `timestamp` | TEXT | 이벤트 발생 시각, UTC ISO 8601 |
| `received_at` | TEXT | 웹 서버 수신 시각, UTC ISO 8601 |
| `host_ip` | TEXT | Host IP |
| `hostname` | TEXT | Host 이름 |
| `user_id` | TEXT | 사용자 식별자 |
| `department` | TEXT | 부서 |
| `file_name` | TEXT | 파일명 |
| `file_path` | TEXT | 파일 경로 |
| `process_name` | TEXT | 프로세스명 |
| `leak_channel` | TEXT | 반출 채널 |
| `detection_type` | TEXT | 탐지 방식 |
| `analysis_status` | TEXT | `SUCCESS`, `FAILED`, `SKIPPED` |
| `ai_score` | REAL | 정상 AI 결과만 0~1, 실패·미실행은 NULL |
| `model_version` | TEXT | AI 판별 모델 버전 |
| `matched_keywords` | TEXT | 키워드 배열을 JSON 문자열로 저장 |
| `policy_id` | TEXT | 적용 정책 식별자 |
| `action_taken` | TEXT | 최종 조치 결과 |
| `decision_reason` | TEXT | 조치 판단 사유 |
| `evidence_summary` | TEXT | 탐지 근거 요약 |
| `latency_ms` | INTEGER | 분석·조치 지연 시간 |
| `payload_hash` | TEXT | canonical 수집 payload의 SHA-256 |

인덱스:

- `idx_dlp_logs_event_id`: `event_id IS NOT NULL`인 행에 적용되는 Unique Index
- `idx_dlp_logs_timestamp`: 최신 로그 조회를 위한 `timestamp DESC` Index

`dlp_policies` 테이블:

| 컬럼 | SQLite 타입 | 제약 및 설명 |
| --- | --- | --- |
| `policy_id` | INTEGER | Primary Key, Auto Increment |
| `policy_name` | TEXT | 정책명 |
| `description` | TEXT | 정책 설명 |
| `ai_threshold` | REAL | 경고 기준 점수 |
| `block_threshold` | REAL | 차단 기준 점수. `ai_threshold` 이상이어야 함 |
| `is_active` | INTEGER | 활성 상태, `0` 또는 `1` |
| `exception_extensions` | TEXT | 최대 50개, 각 1~20자인 예외 확장자 배열을 쉼표로 연결해 저장 |

`dlp_policy_audit` 테이블은 성공한 정책 생성을 같은 SQLite transaction에서 기록하며 SQLite trigger가 UPDATE와 DELETE를 거부합니다. 감사 저장이 실패하면 정책 저장도 함께 rollback되며, 기본 정책 seed는 사용자 변경이 아니므로 기록하지 않습니다. `GET /api/v1/policy-audit`는 `limit`(기본 100, 최대 200)과 `offset`(기본 0)을 받고 전체 `total`을 함께 반환해 오래된 기록도 조회할 수 있습니다.

| 컬럼 | SQLite 타입 | 제약 및 설명 |
| --- | --- | --- |
| `audit_id` | INTEGER | Primary Key, Auto Increment |
| `occurred_at` | TEXT | Web 서버가 기록한 생성 시각, UTC ISO 8601 |
| `actor` | TEXT | 비밀값 없는 `dashboard-admin` 또는 `agent-token` label |
| `action` | TEXT | 현재 `POLICY_CREATED`만 기록 |
| `policy_id` | INTEGER | 생성된 정책 식별자 |
| `policy_name` | TEXT | 생성 당시 정책명 |
| `description` | TEXT | 생성 당시 정책 설명 |
| `ai_threshold` | REAL | 생성 당시 경고 기준 점수 |
| `block_threshold` | REAL | 생성 당시 차단 기준 점수 |
| `is_active` | INTEGER | 생성 당시 활성 상태 |
| `exception_extensions` | TEXT | 생성 당시 예외 확장자 목록 |

`dlp_ingest_conflicts`는 같은 `event_id`에 기존 payload와 다른 payload가 들어온 시도를 기록합니다. `occurred_at`, `event_id`, `agent_id`, `stored_payload_hash`, `received_payload_hash`를 보관하며 UPDATE와 DELETE는 SQLite trigger로 거부합니다. 자동 삭제는 하지 않으며, 운영 보존 기간과 백업 위치가 승인된 뒤 별도 보관 절차를 추가해야 합니다.

`dlp_metadata` 테이블:

| 컬럼 | SQLite 타입 | 제약 및 설명 |
| --- | --- | --- |
| `metadata_key` | TEXT | Primary Key. 현재 `database_epoch` 사용 |
| `metadata_value` | TEXT | DB 생성 시 발급한 UUID. 알림 커서의 DB 세대 식별자 |

`dlp_agent_heartbeats` 테이블:

| 컬럼 | SQLite 타입 | 제약 및 설명 |
| --- | --- | --- |
| `agent_id` | TEXT | mode와 함께 Primary Key를 구성하는 Agent 식별자 |
| `mode` | TEXT | `user`, `system`, `all` 중 하나 |
| `hostname` | TEXT | 가장 최근 heartbeat가 보고한 Host 이름 |
| `agent_version` | TEXT | 가장 최근 heartbeat가 보고한 Agent 버전 |
| `last_seen_at` | TEXT | Web 서버가 기록한 최근 수신 시각, UTC ISO 8601 |

기존 SQLite 파일에는 서버 시작 시 이 테이블만 비어 있는 상태로 추가됩니다. 기존 로그·정책·DB 세대 ID는 수정하거나 삭제하지 않으며 heartbeat 샘플 행도 자동 생성하지 않습니다.

### 6.7 주요 HTTP 상태 코드

| 상태 코드 | 발생 조건 |
| --- | --- |
| `200` | 조회·AI 분석·heartbeat 저장 성공 또는 중복 로그 재전송 |
| `201` | 신규 로그 또는 정책 저장 성공 |
| `400` | 정책의 차단 임계치가 AI 임계치보다 낮음 |
| `401` | `X-Agent-Token` 또는 활성화된 대시보드 Basic 자격 증명 누락·불일치 |
| `403` | viewer 자격 증명으로 정책 생성 시도 |
| `404` | 존재하지 않는 로그 또는 프론트 파일 조회 |
| `409` | 같은 `event_id`에 기존 저장 내용과 다른 payload 전송 |
| `422` | 필수 필드 누락, 허용값 위반 또는 타입 오류 |
| `426` | Basic 인증이 활성화된 서버에 평문 HTTP로 접근 |
| `502` | 외부 AI 서버 연결 실패 또는 잘못된 응답 |
| `503` | Agent 인증이 설정되지 않았거나 Web AI 중계가 비활성화됨 |

## 7. 샘플 로그 전송

`.env`로 서버 토큰을 변경했다면 샘플 스크립트를 실행하는 터미널에도 같은 값을 불러옵니다.

```bash
set -a
source .env
set +a
```

일반 로그 전송:

```bash
python scripts/send_sample_log.py --scenario usb_copy
```

Web 표시용 fixture 시나리오:

- `web_upload`
- `usb_copy`
- `email_attachment`
- `print`
- `messenger`
- `clipboard`
- `cloud_drive`

발표용으로 7개 시나리오를 위 순서대로 한 번씩 전송하려면 대시보드를 먼저 열고 다음을 실행합니다.

```bash
python scripts/send_sample_log.py --scenario all --interval 2.5
```

전송 순서는 `web_upload` → `usb_copy` → `email_attachment` → `print` → `messenger` → `clipboard` → `cloud_drive`입니다. `--interval`은 이벤트 간 대기 시간(초)이며, `--count 2`를 추가하면 전체 순서를 2회 반복합니다.

위 7개는 Web의 수집·필터·차트·상세 표시를 확인하는 fixture이며, Host Agent가 7개를 모두 독립적으로 탐지한다는 뜻이 아닙니다. 실제 Host 연동 대상은 `CLIPBOARD`, `USB_COPY`, `EMAIL_ATTACHMENT`, `WEB_UPLOAD`, `CLOUD_DRIVE` 5개입니다. 메신저 붙여넣기는 독립 `MESSENGER` 훅이 아니라 Clipboard 훅으로 검사하고 `CLIPBOARD` 채널로 기록합니다. `PRINT`는 Web 표시용 fixture만 있으며 현재 Host Agent에서 미지원입니다.

`--analyze-first`가 없는 샘플의 AI 점수와 조치는 실제 탐지나 모델 결과가 아닌 미리 정한 fixture입니다. 이 경우 `model_version`은 `demo-fixture-not-live`, 판단 근거는 `DEMO FIXTURE - NOT LIVE`로 표시됩니다. Web 분석 중계에 연결된 AI 결과를 사용하려면 `--analyze-first`를 추가하고 `/health`의 `analysis_mode`가 `external`인지 확인합니다. 이때 실제 모델 응답을 사용하더라도 입력과 채널 발생 자체는 Web fixture이므로 판단 근거에는 `WEB FIXTURE - NOT HOST LIVE`가 유지됩니다. `analysis_mode`가 `disabled`이면 중계 API는 HTTP `503`을 반환합니다. Host Agent가 AI 서버에 직접 연결한 이벤트의 실제 모델 여부는 로그 상세의 `analysis_status`, `model_version`, `detection_type`, 판단 근거를 함께 확인합니다.

모든 신규 이벤트는 KPI, 채널 차트와 최근 로그에 자동 반영됩니다. 경고 토스트와 경고음은 조치가 `BLOCKED`이거나 정상 AI 결과의 점수가 설정한 `HIGH_RISK_SCORE_THRESHOLD` 이상인 고위험 이벤트에만 발생합니다.

중복 방지 확인:

```bash
python scripts/send_sample_log.py --scenario web_upload --event-id merge-test-001
python scripts/send_sample_log.py --scenario web_upload --event-id merge-test-001
```

AI 분석 후 로그 저장:

```bash
python scripts/send_sample_log.py --scenario email_attachment --event-id ai-merge-test-001 --analyze-first
```

여러 건 전송:

```bash
python scripts/send_sample_log.py --scenario messenger --count 5
```

전체 옵션은 다음 명령으로 확인합니다.

```bash
python scripts/send_sample_log.py --help
```

### 7.1 현재 날짜 기준 데모 데이터 생성

서버를 실행하기 전에도 SQLite DB에 최근 7일 데모 로그 12건을 직접 생성할 수 있습니다. 기존 로그는 삭제하거나 수정하지 않습니다.

먼저 실제 DB를 변경하지 않고 생성 예정 데이터를 확인합니다.

```bash
python scripts/seed_demo_data.py --dry-run
```

기본 DB인 `backend/dlp_dashboard.db`에 적용합니다.

```bash
python scripts/seed_demo_data.py
```

생성 데이터는 차단 6건, 경고 3건, 허용 3건으로 구성되고 다섯 가지 유출 채널을 모두 포함합니다. `event_id`에 기준 날짜와 순번이 들어가므로 같은 날짜에 다시 실행하면 기존 12건을 건너뜁니다.

특정 날짜를 기준으로 생성하려면 다음과 같이 실행합니다.

```bash
python scripts/seed_demo_data.py --base-date 2026-08-13
```

별도 DB에 생성하려면 `--db`를 사용합니다.

```bash
python scripts/seed_demo_data.py --db /tmp/dlp-demo.db
```

기준 날짜의 기본값은 현재 UTC 날짜입니다. 전체 옵션은 `python scripts/seed_demo_data.py --help`로 확인할 수 있습니다.
같은 날짜의 이전 demo fixture가 이미 있으면 운영 로그는 건드리지 않고 해당 `demo-seed-*` 행의 모델 표기와 fixture 안내 문구만 최신 값으로 갱신합니다.

## 8. 외부 AI 서버 연결

외부 AI 서버 주소를 설정하면 웹 서버의 `/api/v1/analyze`가 분석 요청을 외부 서버로 전달합니다.

```dotenv
AI_SERVER_URL=http://127.0.0.1:9000
AI_SERVER_TOKEN=
AI_SERVER_TIMEOUT_SECONDS=5
```

`AI_SERVER_TOKEN`은 AI 서버와 동일한 32자 이상의 실제 ASCII 무작위 토큰을 입력해야 합니다.

`AI_SERVER_URL` 경로 처리 규칙은 다음과 같습니다.

- `/analyze`로 끝나면 입력 주소를 그대로 사용
- `/api/v1`로 끝나면 `/analyze` 추가
- 그 외 주소에는 `/api/v1/analyze` 추가

외부 AI 서버가 반환해야 하는 주요 필드는 다음과 같습니다.

```json
{
  "event_id": "agent-event-001",
  "decision": "review",
  "confidence_score": 0.73,
  "model_version": "team-ai-v1",
  "latency_ms": 120,
  "reason": "민감 패턴과 외부 전송 문맥이 함께 탐지됨",
  "evidence_summary": "민감 패턴과 외부 전송 문맥이 함께 탐지됨"
}
```

- `event_id`는 요청의 `event_id`와 일치해야 하며, 누락되거나 다르면 웹 서버가 HTTP `502`를 반환합니다.
- `decision`은 `allow`, `review`, `block` 중 하나여야 합니다.
- 점수 필드는 숫자형 `confidence_score`만 허용하며 범위는 `0.0`~`1.0`입니다.
- `ai_score`, `score`, 문자열 점수, 0~100 값은 추측하거나 변환하지 않고 HTTP `502`로 거절합니다.
- `model_version`은 비어 있지 않은 문자열이어야 하며, 누락되거나 공백이면 HTTP `502`를 반환합니다.
- `reason`은 `reason` → `evidence_summary` → `explanation`, `evidence_summary`는 `evidence_summary` → `reason` → `explanation` 순으로 정규화하여 두 필드를 모두 반환합니다.
- 연결 실패, 잘못된 JSON 또는 잘못된 응답 형식은 HTTP `502`로 반환합니다.

## 9. 자동화 테스트

개발·테스트 의존성을 설치한 뒤 프로젝트의 `web` 디렉터리에서 실행합니다.

```bash
python -m pytest
```

간단한 결과만 확인하려면 다음과 같이 실행합니다.

```bash
python -m pytest -q
```

현재 자동화 테스트는 API·DB·스크립트 129건과 실제 Chromium E2E 3건, 총 132건으로 다음 항목을 검증합니다.

- 테스트마다 `tmp_path` 아래 독립된 SQLite DB 생성
- 테이블 생성과 기본 정책 시드
- 대시보드·로그 화면과 SQLite 준비 상태 헬스체크
- Agent 토큰 인증 성공·실패
- Agent heartbeat 인증, strict payload, mode별 upsert, 90초 online/stale 집계와 기존 DB 호환
- 비-loopback 인증·TLS 설정 fail-fast, HTTPS 전용 Basic, viewer/admin 권한과 문서 API 보호
- 전역/Agent별 토큰 인증과 Agent ID 일치 검증
- 로그 저장, 상세 조회와 실제 SQLite 반영
- 동일 ID·동일 hash의 멱등 재전송과 동일 ID·다른 hash의 409·append-only 감사 기록
- AI 성공·실패·미실행 분리, nullable 점수, 정상 결과 평균과 실패율 KPI
- 로그 입력값 검증, 조합 필터와 200건 초과 서버 페이지 경계
- 최근 기간 KPI, 차트 데이터와 날짜 경계
- 고위험 알림 초기 기준선, 저위험 제외, 커서 페이징과 DB 세대 ID 기반 재생성 복구
- 고위험 점수 임계값의 설정 경계와 알림·대시보드 요약 간 일치
- 알림 UI·2초 폴링·전체 대시보드 반복 로드 금지 정적 계약
- 정책 생성과 임계치 검증
- 정책 생성·감사 기록 원자성, 기존 DB 보존과 admin 조회 권한
- 외부 AI 호출, 0~1 `confidence_score` 계약과 연결·응답 오류 처리
- 데모 seed 데이터 분포, 멱등성 및 대시보드 통계 반영
- Chromium에서 필터·검색·페이지 이동, 키보드 상세 열기와 API 오류 표시
- 느린 이전 요청의 최신 화면 덮어쓰기 방지, 경고 토스트와 경고음

fixture가 `backend.main.DB_PATH`를 pytest 임시 디렉터리로 교체하므로 테스트를 실행해도 `backend/dlp_dashboard.db`의 데이터는 변경되지 않습니다.

특정 테스트 파일만 실행하려면 다음 명령을 사용합니다.

```bash
python -m pytest tests/test_api.py -q
python -m pytest tests/test_e2e.py -q
```

## 10. 기본 수동 검증

서버 실행 전 문법과 샘플 payload를 확인합니다.

```bash
python -m py_compile backend/main.py scripts/send_sample_log.py scripts/seed_demo_data.py
python scripts/send_sample_log.py --scenario web_upload --dry-run
```

서버 실행 후 상태를 확인합니다.

```bash
python -c "from urllib.request import urlopen; print(urlopen('http://127.0.0.1:8000/health').read().decode())"
```

개발 의존성과 Chromium 설치 여부는 다음과 같이 확인할 수 있습니다.

```bash
python -m playwright install --dry-run chromium
```

준실시간 다중 시나리오 반영을 수동으로 확인하려면 다음 순서를 사용합니다.

1. 서버를 실행하고 `/dashboard`를 먼저 열어 초기 커서를 준비합니다.
2. 브라우저 자동 재생 제한을 해제하도록 화면을 한 번 클릭하거나 키를 누릅니다.
3. Host Agent에서 지원하는 5개 반출 경로를 실제로 시도하거나, 다음 Web 표시용 fixture 7건을 순차 전송합니다.

```bash
python scripts/send_sample_log.py --scenario all --interval 2.5
```

4. 정상이면 각 이벤트가 전송된 뒤 약 2초 안에 KPI, 채널 차트와 최근 로그에 반영됩니다. `--interval 2.5`로 7건을 보내는 전체 fixture 시연은 약 18초가 걸리며, 이 중 고위험 fixture에만 토스트와 경고음이 발생합니다.
5. `상세 로그 보기`로 해당 로그를 열고, `model_version`, 판단 근거와 반출 채널을 확인합니다.

같은 `event_id`를 다시 전송하면 서버가 기존 `log_id`를 반환하므로 새 알림이 반복되지 않습니다. 다시 시연하려면 고유한 `event_id`를 사용합니다.

다른 PC에서 실제 수신을 검수할 때는 서버 PC에서 HTTPS LAN 실행 후 Host PC의 `dashboard_url`, Agent 토큰과 CA 신뢰를 설정합니다. Host PC에서 실제 지원 채널을 발생시키고 서버 PC에서 해당 Host의 `agent_id`, `hostname`, `event_id`가 표시되는지 확인합니다. 이 항목은 단일 개발 PC의 브라우저 자동화가 대신할 수 없는 물리 환경 인수 테스트입니다.

## 11. 현재 제한사항

- 실제 Host Agent와 AI 서버의 최종 E2E 통합은 아직 진행 전입니다.
- viewer/admin HTTPS Basic만 제공하며 세션 기반 로그인과 세분화된 RBAC는 없습니다.
- 정책 UI는 제거된 상태이며 정책 수정·삭제 API는 없습니다.
- 정책 감사 기록은 append-only이며 자동 삭제·보관 이관은 구현하지 않았습니다.
- 데이터 저장소는 SQLite이며 운영 DB 전환은 진행 전입니다.
- 서버 배포에서 SQLite를 유지하려면 `backend/dlp_dashboard.db`가 있는 경로를 영구 볼륨에 보존하고 단일 Web 프로세스로 실행해야 합니다.
- 위험 알림은 WebSocket/SSE가 아닌 약 2초 주기 HTTP 폴링이며, 화면이 열려 있는 시연·프로토타입 범위입니다.
- Agent 표시는 30초 주기로 조회한 프로세스 heartbeat 생존 상태일 뿐 개별 탐지 채널 건강 상태가 아니며, 실제 Windows/LAN 물리 환경은 별도 인수 테스트가 필요합니다.
- `AGENT_API_TOKENS_JSON`으로 Agent별 토큰을 분리할 수 있지만 장치 인증서나 원격 폐기 기능까지 제공하지는 않습니다. `agent_id`는 장치마다 고유하게 설정해야 합니다.
- `send_sample_log.py --scenario all`은 `PRINT`·`MESSENGER`를 포함한 Web 표시용 fixture 7건을 전송할 뿐입니다. 실제 Host 연동은 5개 채널이며, 메신저는 `CLIPBOARD` 경로로 검사하고 `PRINT`는 미지원입니다.
- `send_sample_log.py`는 Windows의 USB·클립보드·이메일 등을 실제로 감지하거나 차단하지 않습니다.
- Host Agent의 USB `BLOCKED`는 대상 파일의 사후 삭제가 실제로 성공한 경우에만 기록합니다. 삭제 직전·도중 파일이 없어졌거나, 분석 뒤 파일 지문이 바뀌었거나, 권한·잠금·드라이브 이탈로 삭제를 확인할 수 없으면 다른 파일을 삭제하지 않고 `WARNED`와 실패 사유로 기록합니다.
- 로그 화면은 SQLite `offset` 기반 서버 페이지네이션을 사용합니다. 로그가 매우 커져 큰 `offset` 조회가 병목이 되면 운영 DB 전환 시 커서 방식으로 교체해야 합니다.
- 차트는 버전과 무결성 해시를 고정한 Chart.js CDN을 사용하므로 완전한 오프라인 환경에서는 차트만 표시되지 않습니다. CDN 로드가 실패해도 KPI·로그·실시간 알림·경고음은 계속 작동합니다.
