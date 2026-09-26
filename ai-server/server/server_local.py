# -*- coding: utf-8 -*-
"""
server_local.py

Colab 없이 내 컴퓨터에서 직접 돌리는 Sentry AI DLP 서버.

사전 준비:
1. pip install fastapi uvicorn pydantic torch transformers
2. 이 파일과 같은 폴더에 "model" 폴더를 만들고, 그 안에
   koelectra-dlp-v7/final 폴더 내용물(config.json, model.safetensors 등)을
   그대로 복사해두세요.

실행: 이 폴더에서 명령 프롬프트 열고
   python server_local.py
"""

import os
import sys
import time
import re
import json
import threading
import subprocess
import traceback
import urllib.request
from datetime import datetime, timezone
from typing import Optional, Literal, List

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model")
MODEL_VERSION = "koelectra-dlp-v7"
BLOCK_THRESHOLD = 0.41
REVIEW_THRESHOLD = 0.20

LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_PATH = os.path.join(LOG_DIR, "analyze_log.jsonl")
os.makedirs(LOG_DIR, exist_ok=True)

CLOUDFLARED_PATH = os.path.join(BASE_DIR, "cloudflared.exe")
CLOUDFLARED_URL = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"


def ensure_cloudflared() -> None:
    if not os.path.exists(CLOUDFLARED_PATH):
        print("cloudflared 다운로드 중... (최초 1회만)")
        urllib.request.urlretrieve(CLOUDFLARED_URL, CLOUDFLARED_PATH)
        print("다운로드 완료")


def log_event(record: dict) -> None:
    record["logged_at"] = datetime.now(timezone.utc).isoformat()
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        traceback.print_exc()


def read_recent_logs(limit: int = 20) -> list:
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()
    recent = lines[-limit:]
    logs = []
    for line in reversed(recent):
        try:
            logs.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return logs


def main() -> None:
    ensure_cloudflared()

    print("필요한 라이브러리를 불러오는 중...")
    import torch
    import torch.nn.functional as F
    import uvicorn
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel, Field
    from transformers import AutoTokenizer, AutoModelForSequenceClassification

    DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"현재 연산 환경: [{DEVICE.upper()}]")

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

    def to_decision(confidence_score: float) -> str:
        if confidence_score >= BLOCK_THRESHOLD:
            return "block"
        elif confidence_score >= REVIEW_THRESHOLD:
            return "review"
        return "allow"

    print(f"모델 로드 중... ({MODEL_PATH})")
    if not os.path.exists(os.path.join(MODEL_PATH, "config.json")):
        print(f"오류: {MODEL_PATH} 안에 config.json이 없습니다.")
        print("model 폴더 안에 config.json, model.safetensors 등이 바로 보이는지 확인하세요.")
        sys.exit(1)

    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH).to(DEVICE)
    model.eval()
    print("모델 로드 완료.")

    app = FastAPI(title="Sentry AI DLP Server", version=MODEL_VERSION)

    @app.post("/api/v1/analyze", response_model=AgentResponse)
    def analyze_text(request: AgentRequest):
        if not request.snippet.strip():
            log_event({
                "event_id": request.event_id, "channel": request.channel,
                "user_id": request.user_id, "status": "error",
                "error": "empty_snippet",
            })
            raise HTTPException(status_code=400, detail="분석할 콘텐츠(snippet)가 비어 있습니다.")
        try:
            start_time = time.time()
            inputs = tokenizer(
                request.snippet, return_tensors="pt", truncation=True,
                max_length=128, padding="max_length",
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

            log_event({
                "event_id": request.event_id, "channel": request.channel,
                "user_id": request.user_id,
                "snippet_preview": request.snippet[:200],
                "matched_patterns": request.matched_patterns,
                "status": "ok", "decision": decision,
                "confidence_score": round(confidence_score, 4),
                "latency_ms": latency_ms,
            })

            return AgentResponse(
                event_id=request.event_id, decision=decision,
                confidence_score=round(confidence_score, 4),
                model_version=MODEL_VERSION, latency_ms=latency_ms,
                reason=reason_map[decision],
            )
        except HTTPException:
            raise
        except Exception as e:
            traceback.print_exc()
            log_event({
                "event_id": request.event_id, "channel": request.channel,
                "user_id": request.user_id, "status": "error", "error": str(e),
            })
            raise HTTPException(status_code=500, detail=f"AI 추론 엔진 내부 에러: {str(e)}")

    @app.get("/")
    def health_check():
        return {
            "status": "running", "engine": MODEL_VERSION, "device": DEVICE,
            "block_threshold": BLOCK_THRESHOLD, "review_threshold": REVIEW_THRESHOLD,
        }

    @app.get("/api/v1/debug/logs")
    def get_recent_logs(limit: int = 20):
        return {"count": min(limit, 200), "logs": read_recent_logs(min(limit, 200))}

    def run_uvicorn():
        uvicorn.run(app, host="127.0.0.1", port=8000, log_level="error")

    server_thread = threading.Thread(target=run_uvicorn, daemon=True)
    server_thread.start()
    time.sleep(2)

    print("\nCloudflare 터널 연결 중...")
    process = subprocess.Popen(
        [CLOUDFLARED_PATH, "tunnel", "--url", "http://127.0.0.1:8000"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    public_url = None
    start_wait = time.time()
    for line in process.stdout:
        if public_url or (time.time() - start_wait) > 30:
            break
        match = re.search(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com", line)
        if match:
            public_url = match.group()
            break

    if public_url:
        print("\n=======================================================")
        print("[최종 성공] Cloudflare 터널 연결 완료!")
        print(f"에이전트 연동 엔드포인트: {public_url}/api/v1/analyze")
        print(f"Swagger UI 웹 테스트  : {public_url}/docs")
        print(f"로그 조회           : {public_url}/api/v1/debug/logs")
        print("=======================================================")
        print(f"현재 적용된 threshold: block>={BLOCK_THRESHOLD}, review>={REVIEW_THRESHOLD}")
        print("\n서버가 계속 실행 중입니다. 종료하려면 이 창에서 Ctrl+C를 누르세요.\n")
    else:
        print("터널 생성에 실패했습니다. 인터넷 연결을 확인하고 다시 실행해주세요.")
        sys.exit(1)

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\n서버를 종료합니다...")


if __name__ == "__main__":
    main()
