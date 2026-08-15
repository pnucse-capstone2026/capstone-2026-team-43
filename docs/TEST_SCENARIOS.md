# Sentry AI 서버 테스트 시나리오

작성: 박동화 (AI 모델 / 판별 서버)
목적: Host Agent(김진우) 통합 테스트 시, AI 서버(`/api/v1/analyze`) 단독 검증용 입력값 및 기대 결과 제공

착수보고서 1.3절의 3가지 반출 시나리오를 기준으로, 각 채널별로 block / review / allow가
모두 나오는 예시를 준비했습니다.

> 대시보드(`/api/v1/logs`) 로그 연동 및 표시 검증은 아래 **웹 대시보드 연동 체크리스트 (이상호)** 절을 참고합니다.

---

## 시나리오 1: 웹메일/클라우드 첨부를 통한 문서 유출 시도

**채널**: `http` (착수보고서 시나리오 1 대응)

| # | 입력 텍스트 | 채널 | 기대 decision | 비고 |
|---|---|---|---|---|
| 1-A | "A전자向 반도체 부품 납품 단가는 개당 12,400원으로 최종 협상되었습니다." | http | **block** | 미공개 단가 정보, 트리거 단어 없음 |
| 1-B | "정보보호 인증(ISMS) 심사 관련 부서별 자료 제출을 요청드립니다." | http | **review** (또는 block, 경계값) | 임계값 근처 애매 케이스 |
| 1-C | "이번 신제품 카탈로그를 첨부하니 확인 부탁드립니다." | http | **allow** | 일반 공개 자료 |

## 시나리오 2: 변형된 민감정보의 클립보드 복사

**채널**: `clipboard` (착수보고서 시나리오 2 대응)

| # | 입력 텍스트 | 채널 | 기대 decision | 비고 |
|---|---|---|---|---|
| 2-A | "이OO 부장 외 4명에게 1인당 5천만 원 상당의 특별 스톡옵션을 배정하기로 결정했습니다." | clipboard | **block** | 인사 기밀, 문맥 기반 판별 |
| 2-B | "3분기 수주 잔고는 총 2조 1천억 원이며 B건설 프로젝트가 40%를 차지합니다." | clipboard | **block** | 영업 기밀, 수치 기반 |
| 2-C | "이번 주 금요일 오후 2시에 신규 입사자 환영회가 예정되어 있습니다." | clipboard | **allow** | 완전 무해한 공지문 |

## 시나리오 3: USB 등 이동식 매체로의 파일 복사

**채널**: `usb` (착수보고서 시나리오 3 대응)

| # | 입력 텍스트 | 채널 | 기대 decision | 비고 |
|---|---|---|---|---|
| 3-A | "차세대 배터리 소재 배합비는 리튬 62%, 실리콘 23%, 첨가제 15%입니다." | usb | **block** | R&D 핵심 기술, 특허출원 전 |
| 3-B | "정보보안팀 주관으로 전 직원 대상 보안 교육이 진행됩니다." | usb | **allow** | '보안' 단어 포함되지만 비기밀 (키워드 함정 케이스) |

---

## AI 서버 단독 체크리스트

- [ ] Host Agent가 위 텍스트로 AI 서버(`/api/v1/analyze`)에 정상적으로 요청을 보낸다
- [ ] AI 서버가 위 표의 기대 `decision`과 일치하는 응답을 반환한다
- [ ] `confidence_score`, `model_version`, `latency_ms` 필드가 정상적으로 채워져 있다

## 웹 대시보드 연동 체크리스트 (이상호)

### 판정 및 채널 변환 기준

통합 완료 시 Host Agent는 AI 서버의 요청·응답 값을 다음과 같이 대시보드 로그 필드로
변환해 `POST /api/v1/logs`에 전송해야 합니다.

| 연동 원본 값 | 대시보드 로그 값 |
|---|---|
| AI 요청 `event_id` | `event_id` |
| `decision=block` | `action_taken=BLOCKED` |
| `decision=review` | `action_taken=WARNED` |
| `decision=allow` | `action_taken=ALLOWED` |
| `confidence_score` | `ai_score` |
| AI 요청 `matched_patterns`의 패턴 ID | `matched_keywords` |
| AI 응답 `reason` | `evidence_summary` |
| Host Agent의 최종 조치 사유 | `decision_reason` |
| AI 응답 `latency_ms` | `latency_ms` |

대시보드 API 기준 채널 변환안은 다음과 같습니다.

| AI 요청 `channel` | 대시보드 `leak_channel` |
|---|---|
| `http` | `WEB_UPLOAD` |
| `outlook` | `EMAIL_ATTACHMENT` |
| `usb` | `USB_COPY` |
| `clipboard` | 미확정 — 현재 로그 API 허용값에 `CLIPBOARD`가 없어 팀 합의 필요 |

> 아래 항목은 현재 통합 완료 사실이 아니라 세 저장소 연동 시 충족해야 할 검증 기준입니다.
> 현재 Host Agent의 `request_id` / `risk_score` / `action` 스키마와 대시보드 전송 경로는
> 최신 AI·대시보드 API 계약에 맞게 정리해야 합니다.

### 통합 전 API 계약 확인

- [ ] Host Agent의 AI 요청 필드를 `event_id`, `channel`, `user_id`, `matched_patterns`, `snippet`, `metadata` 형식에 맞춘다
- [ ] Host Agent의 AI 응답 파서를 `decision`, `confidence_score`, `model_version`, `latency_ms`, `reason` 형식에 맞춘다
- [ ] 대시보드 전송 경로를 `/api/v1/events`가 아닌 `POST /api/v1/logs`로 맞춘다
- [ ] 로컬 통합 테스트 시 대시보드 주소를 `http://127.0.0.1:8000` 또는 팀에서 정한 주소로 설정한다
- [ ] 로그 전송 시 `X-Agent-Token`을 포함하고 대시보드의 로그 요청 스키마를 사용한다

### 로그 수집 API 검증

- [ ] AI 분석 요청과 로그 저장 요청에 동일한 `event_id`가 사용된다
- [ ] Host Agent가 `X-Agent-Token` 헤더를 포함해 `POST /api/v1/logs`를 호출한다
- [ ] 최초 전송 시 HTTP 201과 `duplicate=false`가 반환된다
- [ ] `ai_score`, `action_taken`, `leak_channel`, `matched_keywords`, `evidence_summary`, `latency_ms`가 Agent 전송값과 동일하게 저장된다
- [ ] 동일한 `event_id`를 재전송하면 HTTP 200과 `duplicate=true`가 반환되고 로그가 중복 생성되지 않는다

### 로그 및 대시보드 화면 검증

- [ ] `GET /api/v1/logs` 목록에서 신규 이벤트를 `event_id`로 확인할 수 있다
- [ ] `GET /api/v1/logs/{log_id}` 상세 응답에 사용자·Host·파일·프로세스·정책·탐지 근거가 표시된다
- [ ] `/logs` 화면에서 `BLOCKED` / `WARNED` / `ALLOWED` 상태, AI 점수, 매칭 키워드와 판단 사유가 정상 표시된다
- [ ] 부서, 사용자, Agent, 조치 결과, 반출 채널, 날짜 및 검색어 필터가 신규 이벤트에 적용된다
- [ ] `GET /api/v1/dashboard/summary?days=7`의 KPI와 타임라인에 신규 이벤트가 1건 반영된다
- [ ] 차단 이벤트는 채널 분포·부서 통계·고위험 이벤트 목록에 반영된다

### 예외 상황 검증

- [ ] `X-Agent-Token`이 없거나 올바르지 않으면 로그 저장 요청이 HTTP 401로 거절된다
- [ ] `ai_score` 범위 또는 `action_taken`, `leak_channel` 값이 유효하지 않으면 HTTP 422가 반환된다
- [ ] 존재하지 않는 `log_id` 상세 조회는 HTTP 404를 반환한다
- [ ] AI 서버 장애로 Host Agent가 Fail-Open 처리한 이벤트도 `ALLOWED`와 장애 사유를 포함해 로그로 남는지 확인한다

## 장애 상황 테스트 (Fail-Open 정책 확인용)

> 현재 Host Agent는 AI 서버 타임아웃·오류 시 `block`을 반환하므로, 아래 Fail-Open 목표 정책과
> 일치시키려면 Host Agent의 오류 처리 로직 변경이 필요합니다.

- [ ] AI 서버가 응답하지 않을 때(타임아웃) Host Agent가 기본 허용(Fail-Open)으로 동작하는지 확인
- [ ] AI 서버가 500 에러를 반환할 때도 Host Agent가 정상적으로 처리(차단 없이 통과)하는지 확인

---

## TODO (다른 파트와 합쳐서 보완 필요)

- [x] 대시보드(`/api/v1/logs`) 로그 기록 및 상세 화면 표시 체크리스트 작성 — 이상호 파트
- [ ] `channel=clipboard`를 대시보드 `leak_channel`에 저장하는 방식 확정 — 김진우·이상호 파트, 팀 합의 필요
- [ ] `decision=review` 정책 최종 확정 — 현재 Host Agent는 허용 후 `review` 기록, 팀 합의 필요
- [ ] AI `model_version`을 대시보드 로그에 저장할지 확정 — 박동화·이상호 파트, 팀 합의 필요

> 참고: 위 텍스트들은 AI 서버 재학습 시 사용된 검증 데이터(train_dataset_v5.csv, hard_test_set_v1.csv)에서
> 대표성 있는 케이스를 발췌한 것입니다. 실제 confidence_score 수치는 서버 버전에 따라 소수점 단위로
> 달라질 수 있으나, decision(block/review/allow) 결과는 위와 동일하게 나와야 합니다.
