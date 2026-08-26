# =====================================================================
# Sentry AI DLP 서버 (v8 - Colab 셀 붙여넣기 최종본)
# =====================================================================
print("⏳ 1. 필수 패키지 및 Cloudflare 터널링 도구 설치 중...")
!pip install -q fastapi uvicorn pydantic torch transformers

import os
import time
import re
import threading
import subprocess
import traceback
from typing import Optional, Literal, List

# 드라이브(FUSE 마운트)는 chmod +x가 제대로 안 먹으므로 /content에 받습니다
CLOUDFLARED_PATH = "/content/cloudflared-linux-amd64"
if not os.path.exists(CLOUDFLARED_PATH):
    !wget -q -O {CLOUDFLARED_PATH} https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
!chmod +x {CLOUDFLARED_PATH}

import torch
import torch.nn.functional as F
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# =====================================================================
# 2. 설정값
# =====================================================================
MODEL_PATH = "/content/drive/MyDrive/2026_졸업과제/도메인편향개선2/koelectra-dlp-v7/final"
MODEL_VERSION = "koelectra-dlp-v7"
BLOCK_THRESHOLD = 0.41   # v7 재검증: Youden's J / F1 공통 최적값 (precision 유지하며 recall 0.939->0.970 개선)
REVIEW_THRESHOLD = 0.20  # v7 재검증: 비기밀 allow율 손해 없이 기밀 recall 개선 확인된 값

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

# =====================================================================
# 3. 요청/응답 스키마 (중간보고서 2.2절 공식 스키마 기준)
# =====================================================================
class Metadata(BaseModel):
    app: Optional[str] = None
    dest: Optional[str] = None
    severity_hint: Optional[str] = None

class AgentRequest(BaseModel):
    event_id: str
    channel: str
    user_id: str
    matched_patterns: List[str] = Field(default_factory=list)
    snippet: str
    metadata: Optional[Metadata] = None

class AgentResponse(BaseModel):
    event_id: str
    decision: Literal["allow", "review", "block"]
    confidence_score: float
    model_version: str
    latency_ms: float
    reason: Optional[str] = None

def to_decision(confidence_score: float) -> Literal["allow", "review", "block"]:
    if confidence_score >= BLOCK_THRESHOLD:
        return "block"
    elif confidence_score >= REVIEW_THRESHOLD:
        return "review"
    return "allow"

# =====================================================================
# 4. FastAPI 앱 초기화 및 모델 로드
# =====================================================================
app = FastAPI(title="Sentry AI DLP Server", version=MODEL_VERSION)

print(f"\n=======================================================")
print(f"🔥 현재 AI 연산 환경: [{DEVICE.upper()}] 🔥")
print(f"=======================================================\n")
print(f"⏳ 2. AI 판별 엔진 가중치 로드 중... ({MODEL_PATH})")

model_loaded = False
model = None
tokenizer = None

try:
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH).to(DEVICE)
    model.eval()
    model_loaded = True
    print("✅ 분석 엔진 탑재 성공! 실시간 탐지 대기 중입니다.")
except Exception as e:
    print(f"❌ 모델 로드 실패: {e}\n경로 또는 모델 파일을 다시 확인해주세요.")
    traceback.print_exc()

# =====================================================================
# 5. 실시간 판별 API 핵심 로직
# =====================================================================
@app.post("/api/v1/analyze", response_model=AgentResponse)
def analyze_text(request: AgentRequest):
    if not model_loaded:
        raise HTTPException(status_code=503, detail="AI 모델이 로드되지 않았습니다. 서버 로그를 확인하세요.")
    if not request.snippet.strip():
        raise HTTPException(status_code=400, detail="분석할 콘텐츠(snippet)가 비어 있습니다.")

    try:
        start_time = time.time()
        inputs = tokenizer(
            request.snippet,
            return_tensors="pt",
            truncation=True,
            max_length=128,   # 학습 시 MAX_LENGTH(128)와 통일
            padding="max_length",
        ).to(DEVICE)

        with torch.no_grad():
            outputs = model(**inputs)
            probs = F.softmax(outputs.logits, dim=-1)
            confidence_score = probs[0][1].item()

        latency_ms = round((time.time() - start_time) * 1000, 2)
        decision = to_decision(confidence_score)

        reason_map = {
            "block": "AI 문맥 분석 결과 기밀 가능성이 높아 차단 조치",
            "review": "기밀 여부가 애매하여 검토(review) 대상으로 분류",
            "allow": "정상 비즈니스 문맥으로 판정",
        }

        return AgentResponse(
            event_id=request.event_id,
            decision=decision,
            confidence_score=round(confidence_score, 4),
            model_version=MODEL_VERSION,
            latency_ms=latency_ms,
            reason=reason_map[decision],
        )
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"AI 추론 엔진 내부 에러: {str(e)}")

@app.get("/")
def health_check():
    return {
        "status": "running" if model_loaded else "model_load_failed",
        "engine": MODEL_VERSION,
        "device": DEVICE,
        "block_threshold": BLOCK_THRESHOLD,
        "review_threshold": REVIEW_THRESHOLD,
    }

# =====================================================================
# 6. Cloudflare 백그라운드 서버 가동
# =====================================================================
def run_server(server_obj):
    server_obj.run()

# 같은 커널에서 셀을 재실행해도 이전 서버(스레드)를 확실히 종료하고 재시작
if "_server_thread" in globals() and _server_thread is not None and _server_thread.is_alive():
    print("♻️  이전 서버 인스턴스를 종료합니다...")
    _server.should_exit = True
    _server_thread.join(timeout=5)

os.system("pkill -9 -f cloudflared")
time.sleep(1)

_config = uvicorn.Config(app, host="127.0.0.1", port=8000, log_level="error")
_server = uvicorn.Server(_config)
_server_thread = threading.Thread(target=run_server, args=(_server,), daemon=True)
_server_thread.start()
time.sleep(2)

print("\n🌐 Cloudflare 안전 터널을 뚫고 있습니다...")
process = subprocess.Popen(
    [CLOUDFLARED_PATH, "tunnel", "--url", "http://127.0.0.1:8000"],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
)

public_url = None
start_wait = time.time()
TUNNEL_TIMEOUT_SEC = 30
for line in process.stdout:
    if public_url or (time.time() - start_wait) > TUNNEL_TIMEOUT_SEC:
        break
    match = re.search(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com", line)
    if match:
        public_url = match.group()
        break

if public_url:
    print(f"\n=======================================================")
    print(f"🎉 [최종 성공] Cloudflare 터널 연결 완료!")
    print(f"🔗 에이전트 연동 엔드포인트: {public_url}/api/v1/analyze")
    print(f"🔗 Swagger UI 웹 테스트  : {public_url}/docs")
    print(f"=======================================================\n")
    print(f"⚙️  현재 적용된 threshold: block>={BLOCK_THRESHOLD}, review>={REVIEW_THRESHOLD}")
    print("👉 위 Swagger UI 주소를 클릭해서 새 스키마로 테스트해보세요! (이 셀은 여기서 끝나도 서버는 계속 돌아갑니다)")
else:
    print("❌ 터널 생성에 실패했거나 시간이 초과되었습니다. 코랩 세션을 다시 시작해주세요.")