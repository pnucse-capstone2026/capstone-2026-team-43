# AI 기반 Host DLP 웹 대시보드

Host Agent가 전송한 민감정보 반출 탐지 로그를 저장하고, 관리자가 통계와 상세 탐지 근거를 확인할 수 있도록 만든 FastAPI 기반 웹 대시보드입니다.

현재 구현 범위는 다음과 같습니다.

- Host Agent 로그 수집과 `event_id` 기반 중복 저장 방지
- Agent 전용 토큰 인증
- 선택형 viewer/admin HTTP Basic 대시보드 접근 제어
- 탐지 로그 검색, 필터, 목록 및 상세 조회
- 최근 7일 KPI, 탐지 추이, 채널 분포, 부서별 탐지 건수 시각화
- 고위험 이벤트와 Evidence 상세 분석
- `log_id` 커서 기반 2초 주기 준실시간 위험 알림과 선택형 경고음
- Mock AI 분석 및 외부 AI 서버 전달 구조
- 정책 조회·생성 API

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
├── tests/
│   ├── conftest.py             # 임시 DB와 TestClient 공통 fixture
│   ├── test_api.py             # API·DB·AI 자동화 테스트
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
```

## 4. 환경변수

지원되는 환경변수는 다음과 같습니다.

| 이름 | 필수 여부 | 기본 동작 | 설명 |
| --- | --- | --- | --- |
| `AGENT_API_TOKEN` | 팀 연동 시 필수 | 로컬 데모 토큰 사용 | Agent가 분석·로그 수집 API를 호출할 때 보내는 32자 이상 ASCII 토큰 |
| `AI_SERVER_URL` | 선택 | 내부 Mock 분석 | 실제 AI 서버 주소 |
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

### 5.1 빠른 로컬 실행

환경변수를 설정하지 않으면 내부 Mock AI 분석과 로컬 데모 Agent 토큰을 사용합니다. 이 기본 토큰은 `127.0.0.1`의 개발 확인용이며 LAN 시연에서도 반드시 `.env`의 `AGENT_API_TOKEN`을 새 값으로 교체합니다.

```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

### 5.2 `.env`를 사용하는 팀 연동 실행

```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --env-file .env
```

실행 후 확인 URL은 다음과 같습니다.

| 화면 또는 API | URL |
| --- | --- |
| 대시보드 | `http://127.0.0.1:8000/dashboard` |
| 로그 상세 분석 | `http://127.0.0.1:8000/logs` |
| Swagger API 문서 | `http://127.0.0.1:8000/docs` |
| 상태 확인 | `http://127.0.0.1:8000/health` |

`/health`의 `analysis_mode`가 `mock`이면 내부 Mock 분석, `external`이면 외부 AI 서버 전달 모드입니다. `dashboard_auth_enabled`로 비밀값 노출 없이 대시보드 인증 활성 여부를 확인할 수 있습니다.

### 5.3 두 컴퓨터 시연

두 컴퓨터가 같은 중앙 Web 서버를 사용해야 합니다. 서버 PC에서는 해당 PC의 LAN IP에 바인딩해 실행합니다.

```bash
python -m uvicorn backend.main:app --host <SERVER_LAN_IP> --port 8000 --env-file .env
```

대시보드 PC에서는 `http://<SERVER_LAN_IP>:8000/dashboard`를 열고 `경고음 꺼` 버튼을 눌러 경고음을 켭니다. Host Agent PC의 `config/settings.yaml`은 다음 항목을 같은 서버로 맞춥니다.

```yaml
server:
  dashboard_url: "http://<SERVER_LAN_IP>:8000"
  dashboard_token: "<AGENT_API_TOKEN과 동일한 값>"

logging:
  send_immediately: true
```

대시보드를 먼저 연 뒤 Host Agent에서 반출 시나리오를 실행하면, 새 `BLOCKED` 이벤트 또는 설정한 고위험 AI 점수 임계값 이상 이벤트가 약 2초 안에 다른 컴퓨터의 대시보드에 표시됩니다. 두 컴퓨터 사이에서 TCP 8000 포트 접근이 가능해야 합니다. 본 앱은 브라우저 API를 same-origin으로만 사용하며 cross-origin 요청을 허용하지 않습니다. 통제된 LAN 밖에서 HTTP Basic을 사용할 때는 평문 HTTP로 자격 증명을 전송하지 않도록 반드시 HTTPS reverse proxy 뒤에 배치합니다.

### 5.4 대시보드 HTTP Basic 인증

기본은 기존 통제 LAN 시연과의 호환을 위해 인증을 비활성화합니다. `DASHBOARD_VIEWER_USERNAME`, `DASHBOARD_VIEWER_PASSWORD`, `DASHBOARD_ADMIN_USERNAME`, `DASHBOARD_ADMIN_PASSWORD` 네 값을 모두 설정하면 인증이 활성화됩니다. 일부만 설정하거나, 두 사용자명이 같거나, 비밀번호가 16자 미만이거나 non-ASCII면 서버가 즉시 시작을 중단합니다. HTTP Basic 호환을 위해 사용자명도 ASCII이며 `:`를 포함하지 않아야 합니다.

- viewer와 admin은 `/dashboard`, `/logs` 및 대시보드 조회 API를 사용할 수 있습니다.
- `POST /api/v1/policies`는 인증 활성 시 admin만 호출할 수 있으며 viewer는 HTTP `403`을 받습니다. 인증 비활성 시에는 기존처럼 `X-Agent-Token`을 사용합니다.
- `/api/v1/agent-check`, `POST /api/v1/analyze`, `POST /api/v1/logs`는 대시보드 인증 여부와 관계없이 계속 `X-Agent-Token`만 사용합니다.
- `/health`는 공개 상태 확인용으로 유지되며 `dashboard_auth_enabled`만 노출하고 사용자명과 비밀번호는 노출하지 않습니다.

브라우저로 `/dashboard`를 열면 HTTP `401` 응답의 Basic 인증 창이 나타납니다. 한 번 인증하면 브라우저가 같은 origin의 `fetch` 요청에 Basic 자격 증명을 자동으로 재사용하므로 별도 로그인 UI나 JavaScript 세션 저장이 필요하지 않습니다. HTTP Basic은 자격 증명을 암호화하지 않으므로 외부에 공개하는 서버에서는 반드시 HTTPS reverse proxy 뒤에서만 사용합니다.

Host 통합 검증기가 저장 후 `GET /api/v1/logs`로 readback할 때도 인증이 활성화되어 있으면 Web 서버와 같은 `DASHBOARD_VIEWER_USERNAME`, `DASHBOARD_VIEWER_PASSWORD`를 HTTP Basic으로 전송해야 합니다. `X-Agent-Token`은 Agent 쓰기 API용이므로 인증이 활성화된 조회 API의 readback 자격 증명을 대신하지 않습니다.

## 6. 주요 API

| Method | Path | 인증 | 용도 |
| --- | --- | --- | --- |
| `GET` | `/health` | 불필요 | 서버와 AI 분석 모드 확인 |
| `GET` | `/api/v1/agent-check` | `X-Agent-Token` | 로그를 남기지 않고 Host 인증·연결 확인 |
| `POST` | `/api/v1/analyze` | `X-Agent-Token` | Mock 또는 외부 AI 분석 요청 |
| `POST` | `/api/v1/logs` | `X-Agent-Token` | Host Agent 탐지 로그 저장 |
| `GET` | `/api/v1/logs` | HTTP Basic(활성 시) | 로그 검색 및 필터 조회 |
| `GET` | `/api/v1/logs/filter-options` | HTTP Basic(활성 시) | 부서·사용자·Agent 필터 목록 조회 |
| `GET` | `/api/v1/logs/{log_id}` | HTTP Basic(활성 시) | 개별 로그 상세 조회 |
| `GET` | `/api/v1/dashboard/summary` | HTTP Basic(활성 시) | 최근 기간 KPI와 차트 데이터 조회 |
| `GET` | `/api/v1/alerts` | HTTP Basic(활성 시) | 고위험 신규 로그를 `log_id` 커서로 조회 |
| `GET` | `/api/v1/policies` | HTTP Basic(활성 시) | 정책 목록 조회 |
| `POST` | `/api/v1/policies` | admin Basic(활성) / `X-Agent-Token`(비활성) | 정책 생성 |

정확한 요청 필드와 허용값은 실행 중인 서버의 `/docs`에서 확인할 수 있습니다.

### 6.1 준실시간 위험 알림

대시보드를 열면 현재 최신 `log_id`를 기준선으로 저장한 뒤 2초마다 신규 고위험 로그를 조회합니다. 기존 이력은 토스트로 재생하지 않고, 화면을 연 뒤 저장된 다음 조건의 이벤트만 알립니다.

- `action_taken == BLOCKED`
- `ai_score >= HIGH_RISK_SCORE_THRESHOLD` (기본값 `0.85`)

신규 이벤트가 있으면 우측 상단에 빨간 위험 알림이 표시되고, `상세 로그 보기`로 해당 `log_id`의 분석 화면을 열 수 있습니다. 경고음은 브라우저 자동 재생 정책 때문에 기본으로 꺼져 있으며, 상단의 `경고음 꺼` 버튼을 사용자가 한 번 눌러야 켜집니다.

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

### 6.2 Agent 로그 연동 규칙

- 요청 헤더: `X-Agent-Token: <AGENT_API_TOKEN>`
- `timestamp`: UTC offset을 포함한 ISO 8601 형식 필수
- `event_id`: AI 요청부터 Web 저장까지 같은 이벤트를 증명하는 필수 ID
- `ai_score`: `0.0` 이상 `1.0` 이하
- `action_taken`: `BLOCKED`, `WARNED`, `ALLOWED`
- `leak_channel`: `USB_COPY`, `WEB_UPLOAD`, `EMAIL_ATTACHMENT`, `PRINT`, `MESSENGER`, `CLIPBOARD`, `CLOUD_DRIVE`
- 최초 저장: HTTP `201`, `duplicate: false`
- 동일한 `event_id` 재전송: HTTP `200`, `duplicate: true`

샘플 JSON은 실제 전송 없이 다음 명령으로 확인할 수 있습니다.

```bash
python scripts/send_sample_log.py --scenario web_upload --dry-run
```

### 6.3 로그 수집 요청 데이터 구조

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
| `ai_score` | number | 필수 | `0.0`~`1.0` 범위의 민감도 점수 |
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

동일한 `event_id`를 다시 전송하면 새 행을 만들지 않고 HTTP `200`으로 기존 `log_id`를 반환합니다.

```json
{
  "message": "Log already exists.",
  "log_id": 37,
  "event_id": "agent-01-web-upload-20260813-001",
  "duplicate": true
}
```

### 6.4 AI 분석 요청·응답 구조

Host Agent가 웹 서버의 분석 중계 API를 사용할 경우 `POST /api/v1/analyze`를 호출합니다. `AI_SERVER_URL`이 비어 있으면 Mock 분석 결과를 반환하고, 값이 있으면 동일 요청을 외부 AI 서버로 전달합니다.

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
| `confidence_score` | number | `0.0`~`1.0` 범위로 정규화된 점수 |
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

외부 AI 서버는 `confidence_score` 대신 `ai_score` 또는 `score`를 반환할 수 있습니다. `1` 초과 `100` 이하의 점수는 웹 서버가 `0.0`~`1.0` 범위로 변환합니다.

### 6.5 SQLite 데이터 구조

SQLite 파일은 `backend/dlp_dashboard.db`에 생성되지만 Git에는 포함하지 않습니다. 팀원 간 데이터 연동은 DB 파일을 공유하지 않고 위 REST API 계약을 기준으로 합니다.

기존 DB로 서버를 시작하면 누락된 `model_version` 컬럼을 자동으로 추가합니다. 기존 로그는 유지되며, 이전 로그의 `model_version`은 `null`로 조회됩니다.

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
| `ai_score` | REAL | AI 민감도 점수 |
| `model_version` | TEXT | AI 판별 모델 버전 |
| `matched_keywords` | TEXT | 키워드 배열을 쉼표로 연결해 저장 |
| `policy_id` | TEXT | 적용 정책 식별자 |
| `action_taken` | TEXT | 최종 조치 결과 |
| `decision_reason` | TEXT | 조치 판단 사유 |
| `evidence_summary` | TEXT | 탐지 근거 요약 |
| `latency_ms` | INTEGER | 분석·조치 지연 시간 |

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

`dlp_metadata` 테이블:

| 컬럼 | SQLite 타입 | 제약 및 설명 |
| --- | --- | --- |
| `metadata_key` | TEXT | Primary Key. 현재 `database_epoch` 사용 |
| `metadata_value` | TEXT | DB 생성 시 발급한 UUID. 알림 커서의 DB 세대 식별자 |

### 6.6 주요 HTTP 상태 코드

| 상태 코드 | 발생 조건 |
| --- | --- |
| `200` | 조회 성공, AI 분석 성공 또는 중복 로그 재전송 |
| `201` | 신규 로그 또는 정책 저장 성공 |
| `400` | 정책의 차단 임계치가 AI 임계치보다 낮음 |
| `401` | `X-Agent-Token` 또는 활성화된 대시보드 Basic 자격 증명 누락·불일치 |
| `403` | viewer 자격 증명으로 정책 생성 시도 |
| `404` | 존재하지 않는 로그 또는 프론트 파일 조회 |
| `422` | 필수 필드 누락, 허용값 위반 또는 타입 오류 |
| `502` | 외부 AI 서버 연결 실패 또는 잘못된 응답 |

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

`--analyze-first`가 없는 샘플의 AI 점수와 조치는 실제 탐지나 모델 결과가 아닌 미리 정한 fixture입니다. 이 경우 `model_version`은 `demo-fixture-not-live`, 판단 근거는 `DEMO FIXTURE - NOT LIVE`로 표시됩니다. Web 분석 중계에 연결된 AI 결과를 사용하려면 `--analyze-first`를 추가하고, 대시보드 상단의 `Web 분석` 모드가 `EXTERNAL`인지 확인합니다. 이때 실제 모델 응답을 사용하더라도 입력과 채널 발생 자체는 Web fixture이므로 판단 근거에는 `WEB FIXTURE - NOT HOST LIVE`가 유지됩니다. `MOCK`이면 Web 내부 목 분석입니다. 이 표시는 Web의 `/api/v1/analyze`에만 해당하며, Host Agent가 AI 서버에 직접 연결한 이벤트의 실제 모델 여부는 로그 상세의 `model_version`, `detection_type`, 판단 근거를 함께 확인합니다.

모든 신규 이벤트는 KPI, 채널 차트와 최근 로그에 자동 반영됩니다. 경고 토스트와 경고음은 조치가 `BLOCKED`이거나 AI 점수가 설정한 `HIGH_RISK_SCORE_THRESHOLD` 이상인 고위험 이벤트에만 발생합니다.

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
- 점수 필드는 `confidence_score`, `ai_score`, `score`를 받을 수 있습니다.
- `1` 초과 `100` 이하의 점수는 웹 서버에서 `0.0`~`1.0` 범위로 변환합니다.
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

현재 자동화 테스트는 다음 항목을 검증합니다.

- 테스트마다 `tmp_path` 아래 독립된 SQLite DB 생성
- 테이블 생성과 기본 정책 시드
- 대시보드·로그 화면과 헬스체크
- Agent 토큰 인증 성공·실패
- 대시보드 인증 설정 fail-fast, viewer/admin 조회 권한과 정책 쓰기 403
- Mock AI 분석
- 로그 저장, 상세 조회와 실제 SQLite 반영
- 동일 `event_id` 재전송 중복 방지
- 로그 입력값 검증과 조합 필터
- 최근 기간 KPI, 차트 데이터와 날짜 경계
- 고위험 알림 초기 기준선, 저위험 제외, 커서 페이징과 DB 세대 ID 기반 재생성 복구
- 고위험 점수 임계값의 설정 경계와 알림·대시보드 요약 간 일치
- 알림 UI·2초 폴링·전체 대시보드 반복 로드 금지 정적 계약
- 정책 생성과 임계치 검증
- 외부 AI 호출, 응답 정규화와 연결 실패 처리
- 데모 seed 데이터 분포, 멱등성 및 대시보드 통계 반영

fixture가 `backend.main.DB_PATH`를 pytest 임시 디렉터리로 교체하므로 테스트를 실행해도 `backend/dlp_dashboard.db`의 데이터는 변경되지 않습니다.

특정 테스트 파일만 실행하려면 다음 명령을 사용합니다.

```bash
python -m pytest tests/test_api.py -q
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

개발 의존성 설치 여부는 다음과 같이 확인할 수 있습니다.

```bash
python -c "from fastapi.testclient import TestClient; print('TestClient ready')"
```

준실시간 다중 시나리오 반영을 수동으로 확인하려면 다음 순서를 사용합니다.

1. 서버를 실행하고 `/dashboard`를 먼저 열어 초기 커서를 준비합니다.
2. 소리가 필요하면 상단 `경고음 꺼`를 눌러 `켬`으로 바꿉니다.
3. Host Agent에서 지원하는 5개 반출 경로를 실제로 시도하거나, 다음 Web 표시용 fixture 7건을 순차 전송합니다.

```bash
python scripts/send_sample_log.py --scenario all --interval 2.5
```

4. 정상이면 각 이벤트가 전송된 뒤 약 2초 안에 KPI, 채널 차트와 최근 로그에 반영됩니다. `--interval 2.5`로 7건을 보내는 전체 fixture 시연은 약 18초가 걸리며, 이 중 고위험 fixture에만 토스트와 경고음이 발생합니다.
5. `상세 로그 보기`로 해당 로그를 열고, `model_version`, 판단 근거와 반출 채널을 확인합니다.

같은 `event_id`를 다시 전송하면 서버가 기존 `log_id`를 반환하므로 새 알림이 반복되지 않습니다. 다시 시연하려면 고유한 `event_id`를 사용합니다.

## 11. 현재 제한사항

- 실제 Host Agent와 AI 서버의 최종 E2E 통합은 아직 진행 전입니다.
- 선택형 viewer/admin HTTP Basic만 제공하며 세션 기반 로그인과 세분화된 RBAC는 없습니다.
- 정책 UI는 제거된 상태이며 정책 수정·삭제 API는 없습니다.
- 데이터 저장소는 SQLite이며 운영 DB 전환은 진행 전입니다.
- 서버 배포에서 SQLite를 유지하려면 `backend/dlp_dashboard.db`가 있는 경로를 영구 볼륨에 보존하고 단일 Web 프로세스로 실행해야 합니다.
- 위험 알림은 WebSocket/SSE가 아닌 약 2초 주기 HTTP 폴링이며, 화면이 열려 있는 시연·프로토타입 범위입니다.
- `send_sample_log.py --scenario all`은 `PRINT`·`MESSENGER`를 포함한 Web 표시용 fixture 7건을 전송할 뿐입니다. 실제 Host 연동은 5개 채널이며, 메신저는 `CLIPBOARD` 경로로 검사하고 `PRINT`는 미지원입니다.
- `send_sample_log.py`는 Windows의 USB·클립보드·이메일 등을 실제로 감지하거나 차단하지 않습니다.
- Host Agent의 USB `BLOCKED`는 대상 파일의 사후 삭제가 실제로 성공한 경우에만 기록합니다. 삭제 직전·도중 파일이 없어졌거나, 분석 뒤 파일 지문이 바뀌었거나, 권한·잠금·드라이브 이탈로 삭제를 확인할 수 없으면 다른 파일을 삭제하지 않고 `WARNED`와 실패 사유로 기록합니다.
- 로그 페이지네이션은 프론트에서 최대 200건을 받아 10건씩 표시하는 방식입니다.
- 차트는 버전과 무결성 해시를 고정한 Chart.js CDN을 사용하므로 완전한 오프라인 환경에서는 차트만 표시되지 않습니다. CDN 로드가 실패해도 KPI·로그·실시간 알림·경고음은 계속 작동합니다.
