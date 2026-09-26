# Sentry AI 판별 서버 (ai-server)

Sentry(민감정보 파일 반출 탐지를 위한 AI 기반 Host DLP)의 2차 판별 모듈입니다.
Host Agent가 1차 정규식 필터로 걸러낸 텍스트를 받아, KoELECTRA 기반 문맥 분류 모델로
기밀 여부를 판정하고 `allow` / `review` / `block`을 반환합니다.

```
Host Agent (1차 정규식) ──POST /api/v1/analyze──▶ AI 서버 (KoELECTRA v7) ──decision──▶ Host Agent ──로그──▶ Web Dashboard
```

- 모델: `monologg/koelectra-base-v3-discriminator` 파인튜닝 (`koelectra-dlp-v7`)
- 서빙: FastAPI + Uvicorn, 외부 공개는 Cloudflare Quick Tunnel
- 담당: 박동화

---

## 1. 폴더 구조

```
ai-server/
├── server/
│   ├── server_colab.ipynb     # Colab(GPU)에서 서버 기동 (시연에 사용한 방식)
│   └── server_local.py        # 로컬 PC(Windows)에서 서버 기동
├── training/
│   └── train_koelectra_v7.py  # 최종 모델 학습
├── evaluation/
│   ├── eval_v7_full.py            # 격식체·구어체 하드케이스 평가
│   ├── threshold_analysis_v7.py   # ROC/PR 기반 threshold 도출
│   └── batch_test_live_api.py     # 실행 중인 서버에 대한 라이브 배치 테스트
├── legacy/                    # v6 단계 스크립트 (개발 이력 보존용)
├── data/                      # 학습·평가 데이터 (전량 LLM 기반 합성 데이터)
└── docs/
    ├── AI모델_최종보고서_핵심결과.md  # 개발 과정과 검증 결과 요약
    └── TEST_SCENARIOS.md             # Host Agent·대시보드 통합 테스트 시나리오
```

### 데이터

| 파일 | 건수 | 용도 |
|---|---|---|
| `train_dataset_v5.csv` | 183 | v6 학습 데이터 (HR/영업/R&D 3도메인, 격식체) |
| `register_augment_v1.csv` | 40 | 구어체 보강분 (v6 데이터셋에 병합됨) |
| `train_dataset_v6.csv` | 223 | **v7 최종 학습 데이터** (= v5 183 + 구어체 40) |
| `hard_test_set_v1.csv` | 50 | 격식체 하드케이스 (트리거 단어 없는 기밀 / 트리거 단어 있는 비기밀) |
| `hard_test_casual_v2.csv` | 34 | 구어체 하드케이스 |
| `final_holdout_v1.csv` | 60 | 최종 홀드아웃 (3도메인 × 격식체·구어체) |
| `evasion_test_v1.csv` | 37 | 탐지 회피(간격 삽입 등 변형 표현) 검증 |

평가용 4개 세트는 v7 학습 데이터(`train_dataset_v6.csv`)와 중복 0건입니다.

---

## 2. 설치

- Python 3.10 이상
- GPU 권장 (CPU에서도 추론은 동작하지만 지연시간 증가)

```bash
pip install -r requirements.txt
```

### 모델 가중치

모델 가중치(`koelectra-dlp-v7/final`, 약 400MB+)는 GitHub 용량 제한으로 레포에 포함하지 않습니다.

- 다운로드: [Google Drive `koelectra-dlp-v7/final`](https://drive.google.com/drive/folders/1o48Awf-g_iJ3j3oKHQWRZblHkoUyivIk?usp=sharing)
  - 폴더 전체를 다운로드하면 zip으로 받아집니다. 압축을 풀어 `config.json`, `model.safetensors`, 토크나이저 파일이 한 폴더 바로 아래에 오도록 두세요.
- 직접 학습으로 재생성: 아래 4절 참고 (`training/train_koelectra_v7.py`, Colab T4 기준 수 분)

---

## 3. 서버 실행

### 방법 A. 로컬 PC (Windows)

1. `server/model/` 폴더를 만들고 가중치 파일(`config.json`, `model.safetensors`, 토크나이저 파일 등)을 폴더 바로 아래에 넣습니다.
2. 실행합니다.
   ```bash
   cd server
   python server_local.py
   ```
3. 최초 실행 시 `cloudflared.exe`를 자동으로 내려받고, 터널 URL을 출력합니다.
   ```
   에이전트 연동 엔드포인트: https://xxxx.trycloudflare.com/api/v1/analyze
   Swagger UI 웹 테스트  : https://xxxx.trycloudflare.com/docs
   ```

### 방법 B. Google Colab

1. 가중치 폴더를 Google Drive에 업로드합니다.
2. `server/server_colab.ipynb`를 Colab에서 열고 런타임을 GPU로 설정합니다.
3. 셀 3의 `MODEL_PATH`를 업로드한 경로로 수정한 뒤 셀 1~3을 순서대로 실행합니다.

### 공통 주의사항

- Cloudflare Quick Tunnel URL은 **실행할 때마다 바뀝니다.** 새 URL을 Host Agent 설정 파일의 AI 서버 주소에 반영해야 합니다.
- 상태 확인: `GET {BASE_URL}/` → 모델 로드 여부, 적용 중인 threshold 반환
- 요청 로그는 `logs/analyze_log.jsonl`에 기록되며 입력 텍스트 앞 200자가 포함되므로 외부에 공유하지 않습니다.

---

## 4. 학습 및 평가 재현

모든 스크립트는 `ai-server/` 루트에서 실행합니다. (Colab 권장)

```bash
python training/train_koelectra_v7.py          # → ./koelectra-dlp-v7/final, test_predictions_v7.csv
python evaluation/eval_v7_full.py              # → eval_v7_full_results.csv
python evaluation/threshold_analysis_v7.py     # → threshold_analysis_v7.png, threshold_candidates_v7.csv
```

라이브 배치 테스트는 서버 실행 후 `evaluation/batch_test_live_api.py`의 `BASE_URL`을 수정하고 실행합니다.

학습 시드는 42로 고정했지만, GPU 연산의 비결정성 때문에 재학습 시 확률값은 소수점 단위로 달라질 수 있습니다.

---

## 5. API 명세

`POST {BASE_URL}/api/v1/analyze`

### Request

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `event_id` | string | O | Host Agent가 발급하는 이벤트 고유 ID |
| `channel` | string | O | `clipboard` / `outlook` / `http` / `usb` 등 반출 채널 |
| `user_id` | string | O | 사용자/디바이스 식별자 |
| `matched_patterns` | string[] | X | 1차 Rule 필터에서 매칭된 패턴명 (없으면 빈 배열) |
| `snippet` | string | O | 분석할 텍스트 (PII는 사전에 마스킹 권장) |
| `metadata` | object | X | `app`, `dest`, `severity_hint` 포함 가능 |

#### Request 예시
```json
{
  "event_id": "evt-20260813-00123",
  "channel": "clipboard",
  "user_id": "device-12345",
  "matched_patterns": ["rrn"],
  "snippet": "이OO 부장 외 4명에게 1인당 5천만 원 상당의 특별 스톡옵션을 배정하기로 결정했습니다.",
  "metadata": {
    "app": "chrome.exe",
    "dest": "external",
    "severity_hint": "high"
  }
}
```

### Response

| 필드 | 타입 | 설명 |
|---|---|---|
| `event_id` | string | Request에서 받은 값 그대로 반환 |
| `decision` | string | `allow` / `review` / `block` |
| `confidence_score` | float | 0.0 ~ 1.0, 기밀일 확률 |
| `model_version` | string | 현재: `koelectra-dlp-v7` |
| `latency_ms` | float | AI 서버 내부 추론 소요 시간(ms) |
| `reason` | string | 확장 필드 (공식 스키마엔 없음), 판정 사유 요약 |

#### Response 예시
```json
{
  "event_id": "evt-20260813-00123",
  "decision": "block",
  "confidence_score": 0.5584,
  "model_version": "koelectra-dlp-v7",
  "latency_ms": 49.72,
  "reason": "AI 문맥 분석 결과 기밀 가능성이 높아 차단 조치"
}
```


### decision 판정 기준 (threshold)

| confidence_score | decision |
|---|---|
| >= 0.41 | block |
| 0.20 ~ 0.41 | review |
| < 0.20 | allow |

v7 기준 ROC/PR 분석(`evaluation/threshold_analysis_v7.py`, AUC 0.9949)에서 Youden's J, F1 최적, F2 최적 기준이 0.41 부근에 수렴해 BLOCK 값으로 채택했습니다. 평가 데이터는 정식 Test셋 + 격식체 하드케이스 50건 + 구어체 하드케이스 34건(총 129건)입니다. 모델을 재학습하면 threshold도 다시 산정해야 합니다.

### 에러 응답

| status code | 상황 |
|---|---|
| 400 | `snippet`이 비어있음 |
| 503 | AI 모델이 로드되지 않은 상태 (서버 기동 직후 등) |
| 500 | 추론 중 내부 에러 (`detail` 필드 참고) |

Host Agent는 착수보고서 3.5절 Fail-Open 정책(AI 서버 무응답/에러 시 기본 허용)을 따르므로, 위 에러 상황에서도 서비스가 멈추지 않도록 타임아웃/재시도 로직 권장.

### curl 테스트 예시

```bash
curl -X POST {BASE_URL}/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "event_id": "test-001",
    "channel": "clipboard",
    "user_id": "test-device",
    "matched_patterns": [],
    "snippet": "이번 주 금요일 오후 2시에 신규 입사자 환영회가 예정되어 있습니다.",
    "metadata": {"app": "test", "dest": "external", "severity_hint": "low"}
  }'
```

Swagger UI: `{BASE_URL}/docs`

---

## 6. 검증 결과 요약

> **해석 시 주의**: 아래 수치는 개발 과정에서 수행한 **보조 검증** 결과이며 최종 성능 지표가 아닙니다.
> 평가셋이 수십 건 규모의 LLM 합성 데이터이고, 하드케이스 세트는 threshold 선정에도 사용되었습니다.
> 모델과 threshold를 고정한 뒤 사전에 잠근 독립 평가 세트로 측정하는 최종 성능 평가는 후속 과제입니다
> (최종보고서 4.4절 참고).

| 검증 항목 | 규모 | 결과 |
|---|---|---|
| 최종 홀드아웃 (학습 미사용) | 60건 | 기밀 Recall 100% (30/30), 비기밀 오탐 0% (0/30) |
| 구어체 하드케이스 (학습 미사용, threshold 선정에 사용) | 34건 | 기밀 Recall 100%, 오탐 0% |
| 격식체 하드케이스 (threshold 선정에 사용) | 50건 | 기밀 Recall 93.3% (28/30) |
| 탐지 회피 (변형 표현) | 37건 | 간격 삽입 Recall 90%, 원본 대비 confidence 하락 0/6쌍 |
| 라이브 서버 배치 | 233건 | 평균 응답 17~30ms (Colab T4). 정확도 수치는 학습 데이터 중복(80.9%)으로 참고치 |

상세 과정은 [`docs/AI모델_최종보고서_핵심결과.md`](docs/AI모델_최종보고서_핵심결과.md)를 참고하세요.

### 한계

- 학습·평가 데이터 전량이 LLM 기반 합성 데이터이며, 평가셋 규모가 수십 건 단위라 수치의 신뢰구간이 넓습니다. 실제 기업 문서 기반 대규모 검증은 수행하지 않았습니다.
- 트리거 단어 없이 사실관계(인사이동, 미발표 일정 등)만으로 민감도를 추론해야 하는 케이스의 탐지율이 낮습니다(약 33%).
- confidence_score가 비기밀 0.1~0.25, 기밀 0.4~0.9에 몰려 있어 세밀한 위험도 차등보다는 이진 판별에 가깝게 동작합니다.
- 서버 자동화 테스트가 없고, 무료 터널 특성상 고정 주소를 제공하지 않습니다.
