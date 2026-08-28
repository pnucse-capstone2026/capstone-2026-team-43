from __future__ import annotations

import json
import os
import sqlite3
from collections import Counter
from contextlib import asynccontextmanager, closing
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from secrets import compare_digest
from time import perf_counter
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field


BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "backend" / "dlp_dashboard.db"
FRONTEND_PATH = BASE_DIR / "frontend" / "index.html"
DEFAULT_AGENT_API_TOKEN = "sentry-agent-demo-token"
AGENT_API_TOKEN = os.getenv("AGENT_API_TOKEN", DEFAULT_AGENT_API_TOKEN)
MOCK_MODEL_VERSION = "koelectra-v0.1-mock"
AI_SERVER_URL = os.getenv("AI_SERVER_URL", "").strip()
AI_SERVER_TOKEN = os.getenv("AI_SERVER_TOKEN", "").strip()
AI_SERVER_TIMEOUT_SECONDS = float(os.getenv("AI_SERVER_TIMEOUT_SECONDS", "5"))
HIGH_RISK_SCORE_THRESHOLD = 0.85
DATABASE_EPOCH_KEY = "database_epoch"

LEAK_CHANNELS = [
    "USB_COPY",
    "WEB_UPLOAD",
    "EMAIL_ATTACHMENT",
    "PRINT",
    "MESSENGER",
    "CLIPBOARD",
    "CLOUD_DRIVE",
]


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield

app = FastAPI(
    title="민감정보 파일 반출 탐지를 위한 AI 기반 Host DLP 시스템",
    version="0.1.0",
    description="Host DLP events collection and dashboard API.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LogCreate(BaseModel):
    event_id: str | None = Field(default=None, min_length=1, max_length=120)
    agent_id: str | None = Field(default=None, min_length=1, max_length=100)
    timestamp: datetime
    host_ip: str = Field(..., min_length=7, max_length=45)
    hostname: str = Field(..., min_length=1, max_length=100)
    user_id: str = Field(..., min_length=1, max_length=100)
    department: str = Field(..., min_length=1, max_length=100)
    file_name: str = Field(..., min_length=1, max_length=255)
    file_path: str | None = Field(default=None, max_length=500)
    process_name: str | None = Field(default=None, max_length=120)
    leak_channel: Literal[
        "USB_COPY",
        "WEB_UPLOAD",
        "EMAIL_ATTACHMENT",
        "PRINT",
        "MESSENGER",
        "CLIPBOARD",
        "CLOUD_DRIVE",
    ]
    detection_type: Literal["RULE_BASED", "AI_MODEL", "HYBRID"]
    ai_score: float = Field(..., ge=0.0, le=1.0)
    model_version: str | None = Field(default=None, max_length=100)
    matched_keywords: list[str] = Field(default_factory=list)
    policy_id: str | None = Field(default=None, max_length=100)
    action_taken: Literal["BLOCKED", "WARNED", "ALLOWED"]
    decision_reason: str | None = Field(default=None, max_length=500)
    evidence_summary: str = Field(default="", max_length=500)
    latency_ms: int | None = Field(default=None, ge=0, le=600000)


class AnalyzeRequest(BaseModel):
    event_id: str = Field(..., min_length=1, max_length=120)
    channel: Literal[
        "clipboard",
        "outlook",
        "http",
        "usb",
        "smtp",
        "web_mail",
        "file_guard",
        "drive_upload",
        "web_upload",
        "email_attachment",
        "print",
        "messenger",
    ]
    user_id: str = Field(..., min_length=1, max_length=100)
    matched_patterns: list[str] = Field(default_factory=list)
    snippet: str = Field(..., min_length=1, max_length=4000)
    metadata: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class AnalyzeResponse(BaseModel):
    event_id: str = Field(..., min_length=1, max_length=120)
    decision: Literal["allow", "review", "block"]
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    model_version: str = Field(..., min_length=1, max_length=100)
    latency_ms: int = Field(..., ge=0, le=600000)
    reason: str = Field(..., max_length=500)
    evidence_summary: str = Field(..., max_length=500)


class PolicyCreate(BaseModel):
    policy_name: str = Field(..., min_length=1, max_length=100)
    description: str = Field(default="", max_length=300)
    ai_threshold: float = Field(..., ge=0.0, le=1.0)
    block_threshold: float = Field(..., ge=0.0, le=1.0)
    is_active: bool = True
    exception_extensions: list[str] = Field(default_factory=list)


def verify_agent_token(
    x_agent_token: str | None = Header(default=None, alias="X-Agent-Token"),
) -> None:
    if not x_agent_token or not compare_digest(x_agent_token, AGENT_API_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid or missing agent token.")


def normalize_text_items(items: list[str]) -> set[str]:
    return {item.strip().lower() for item in items if item.strip()}


def mock_analyze(payload: AnalyzeRequest) -> dict:
    started_at = perf_counter()
    snippet = payload.snippet.lower()
    matched_patterns = normalize_text_items(payload.matched_patterns)
    severity_hint = str(payload.metadata.get("severity_hint", "") or "").lower()
    destination = str(payload.metadata.get("dest", "") or "").lower()

    sensitive_weights = {
        "rrn": 0.22,
        "resident_registration_number": 0.22,
        "api_key": 0.20,
        "secret": 0.18,
        "password": 0.18,
        "source_code": 0.18,
        "confidential": 0.18,
        "nda": 0.14,
        "contract": 0.12,
        "salary": 0.12,
        "revenue": 0.12,
        "forecast": 0.12,
        "prototype": 0.10,
        "internal": 0.08,
        "roadmap": 0.08,
    }
    severity_weights = {
        "critical": 0.30,
        "high": 0.22,
        "medium": 0.12,
        "low": 0.04,
    }

    score = 0.18
    evidence: list[str] = []

    for keyword, weight in sensitive_weights.items():
        if keyword in matched_patterns or keyword in snippet:
            score += weight
            evidence.append(keyword)

    if severity_hint in severity_weights:
        score += severity_weights[severity_hint]
        evidence.append(f"severity:{severity_hint}")

    if destination in {"external", "outside", "internet", "removable"}:
        score += 0.10
        evidence.append(f"dest:{destination}")

    if payload.channel in {
        "usb",
        "file_guard",
        "web_upload",
        "web_mail",
        "drive_upload",
        "email_attachment",
        "outlook",
        "smtp",
        "http",
    }:
        score += 0.06
        evidence.append(f"channel:{payload.channel}")

    confidence_score = round(min(score, 0.99), 2)
    if confidence_score >= 0.85:
        decision = "block"
    elif confidence_score >= 0.60:
        decision = "review"
    else:
        decision = "allow"

    latency_ms = max(1, round((perf_counter() - started_at) * 1000))
    evidence_summary = ", ".join(dict.fromkeys(evidence[:8])) or "no sensitive signal"

    reason = f"Mock AI analysis matched: {evidence_summary}."
    return {
        "event_id": payload.event_id,
        "decision": decision,
        "confidence_score": confidence_score,
        "model_version": MOCK_MODEL_VERSION,
        "latency_ms": latency_ms,
        "reason": reason,
        "evidence_summary": reason,
    }


def get_external_analyze_url() -> str | None:
    if not AI_SERVER_URL:
        return None

    base_url = AI_SERVER_URL.rstrip("/")
    if base_url.endswith("/analyze"):
        return base_url
    if base_url.endswith("/api/v1"):
        return f"{base_url}/analyze"
    return f"{base_url}/api/v1/analyze"


def normalize_external_analyze_response(payload: AnalyzeRequest, raw_response: Any, latency_ms: int) -> dict:
    if not isinstance(raw_response, dict):
        raise HTTPException(status_code=502, detail="AI server response must be a JSON object.")

    raw_event_id = raw_response.get("event_id")
    if not isinstance(raw_event_id, str) or not raw_event_id.strip():
        raise HTTPException(status_code=502, detail="AI server response has no valid event_id.")
    if raw_event_id != payload.event_id:
        raise HTTPException(status_code=502, detail="AI server response event_id does not match the request.")

    decision = str(raw_response.get("decision", "")).lower()
    if decision not in {"allow", "review", "block"}:
        raise HTTPException(status_code=502, detail="AI server response has an invalid decision.")

    raw_score = raw_response.get(
        "confidence_score",
        raw_response.get("ai_score", raw_response.get("score")),
    )
    try:
        confidence_score = float(raw_score)
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=502, detail="AI server response has an invalid score.") from error

    if 1.0 < confidence_score <= 100.0:
        confidence_score = confidence_score / 100.0
    if not 0.0 <= confidence_score <= 1.0:
        raise HTTPException(status_code=502, detail="AI server score must be between 0 and 1.")

    returned_latency = raw_response.get("latency_ms", latency_ms)
    try:
        normalized_latency = max(1, int(returned_latency))
    except (TypeError, ValueError):
        normalized_latency = latency_ms

    raw_model_version = raw_response.get("model_version")
    if not isinstance(raw_model_version, str) or not raw_model_version.strip():
        raise HTTPException(status_code=502, detail="AI server response has no valid model_version.")

    fallback_reason = "External AI server returned no analysis reason."
    reason = str(
        raw_response.get("reason")
        or raw_response.get("evidence_summary")
        or raw_response.get("explanation")
        or fallback_reason
    )
    evidence_summary = str(
        raw_response.get("evidence_summary")
        or raw_response.get("reason")
        or raw_response.get("explanation")
        or fallback_reason
    )

    return {
        "event_id": raw_event_id,
        "decision": decision,
        "confidence_score": round(confidence_score, 2),
        "model_version": raw_model_version,
        "latency_ms": normalized_latency,
        "reason": reason,
        "evidence_summary": evidence_summary,
    }


def call_external_ai_server(payload: AnalyzeRequest) -> dict:
    analyze_url = get_external_analyze_url()
    if analyze_url is None:
        return mock_analyze(payload)

    started_at = perf_counter()
    body = json.dumps(payload.model_dump()).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if AI_SERVER_TOKEN:
        headers["Authorization"] = f"Bearer {AI_SERVER_TOKEN}"

    request = Request(analyze_url, data=body, headers=headers, method="POST")

    try:
        with urlopen(request, timeout=AI_SERVER_TIMEOUT_SECONDS) as response:
            raw_body = response.read().decode("utf-8")
    except HTTPError as error:
        error_body = error.read().decode("utf-8", errors="replace")
        raise HTTPException(
            status_code=502,
            detail=f"AI server returned HTTP {error.code}: {error_body}",
        ) from error
    except URLError as error:
        raise HTTPException(
            status_code=502,
            detail=f"Could not connect to AI server: {error.reason}",
        ) from error

    latency_ms = max(1, round((perf_counter() - started_at) * 1000))
    try:
        raw_response = json.loads(raw_body)
    except json.JSONDecodeError as error:
        raise HTTPException(status_code=502, detail="AI server response is not valid JSON.") from error

    return normalize_external_analyze_response(payload, raw_response, latency_ms)


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def ensure_log_schema(cursor: sqlite3.Cursor) -> None:
    columns = {row["name"] for row in cursor.execute("PRAGMA table_info(dlp_logs)").fetchall()}
    column_definitions = {
        "event_id": "TEXT",
        "agent_id": "TEXT",
        "file_path": "TEXT",
        "process_name": "TEXT",
        "policy_id": "TEXT",
        "decision_reason": "TEXT",
        "latency_ms": "INTEGER",
        "received_at": "TEXT",
        "model_version": "TEXT",
    }

    for column_name, column_type in column_definitions.items():
        if column_name not in columns:
            cursor.execute(f"ALTER TABLE dlp_logs ADD COLUMN {column_name} {column_type}")

    cursor.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_dlp_logs_event_id
        ON dlp_logs(event_id)
        WHERE event_id IS NOT NULL
        """
    )
    cursor.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_dlp_logs_timestamp
        ON dlp_logs(timestamp DESC)
        """
    )


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(get_connection()) as connection:
        cursor = connection.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS dlp_metadata (
                metadata_key TEXT PRIMARY KEY,
                metadata_value TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            INSERT OR IGNORE INTO dlp_metadata (metadata_key, metadata_value)
            VALUES (?, ?)
            """,
            (DATABASE_EPOCH_KEY, str(uuid4())),
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS dlp_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT,
                agent_id TEXT,
                timestamp TEXT NOT NULL,
                received_at TEXT,
                host_ip TEXT NOT NULL,
                hostname TEXT NOT NULL,
                user_id TEXT NOT NULL,
                department TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_path TEXT,
                process_name TEXT,
                leak_channel TEXT NOT NULL,
                detection_type TEXT NOT NULL,
                ai_score REAL NOT NULL,
                model_version TEXT,
                matched_keywords TEXT NOT NULL,
                policy_id TEXT,
                action_taken TEXT NOT NULL,
                decision_reason TEXT,
                evidence_summary TEXT NOT NULL,
                latency_ms INTEGER
            )
            """
        )
        ensure_log_schema(cursor)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS dlp_policies (
                policy_id INTEGER PRIMARY KEY AUTOINCREMENT,
                policy_name TEXT NOT NULL,
                description TEXT NOT NULL,
                ai_threshold REAL NOT NULL,
                block_threshold REAL NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                exception_extensions TEXT NOT NULL
            )
            """
        )

        policy_count = cursor.execute("SELECT COUNT(*) FROM dlp_policies").fetchone()[0]
        if policy_count == 0:
            cursor.executemany(
                """
                INSERT INTO dlp_policies
                    (policy_name, description, ai_threshold, block_threshold, is_active, exception_extensions)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        "기본 민감문서 차단 정책",
                        "AI 점수와 키워드 기반 탐지를 함께 사용합니다.",
                        0.70,
                        0.85,
                        1,
                        ".tmp,.log",
                    ),
                    (
                        "인쇄 경고 정책",
                        "고위험 문서 인쇄 시 관리자 검토가 필요합니다.",
                        0.60,
                        0.80,
                        1,
                        ".png,.jpg",
                    ),
                ],
            )

        connection.commit()


def serialize_log(row: sqlite3.Row) -> dict:
    matched_keywords = row["matched_keywords"] or ""

    return {
        "log_id": row["log_id"],
        "event_id": row["event_id"],
        "agent_id": row["agent_id"],
        "timestamp": row["timestamp"],
        "received_at": row["received_at"],
        "host_ip": row["host_ip"],
        "hostname": row["hostname"],
        "user_id": row["user_id"],
        "department": row["department"],
        "file_name": row["file_name"],
        "file_path": row["file_path"],
        "process_name": row["process_name"],
        "leak_channel": row["leak_channel"],
        "detection_type": row["detection_type"],
        "ai_score": row["ai_score"],
        "model_version": row["model_version"],
        "matched_keywords": [item for item in matched_keywords.split(",") if item],
        "policy_id": row["policy_id"],
        "action_taken": row["action_taken"],
        "decision_reason": row["decision_reason"],
        "evidence_summary": row["evidence_summary"],
        "latency_ms": row["latency_ms"],
    }


def serialize_policy(row: sqlite3.Row) -> dict:
    return {
        "policy_id": row["policy_id"],
        "policy_name": row["policy_name"],
        "description": row["description"],
        "ai_threshold": row["ai_threshold"],
        "block_threshold": row["block_threshold"],
        "is_active": bool(row["is_active"]),
        "exception_extensions": [item for item in row["exception_extensions"].split(",") if item],
    }


@app.get("/")
async def read_root() -> dict:
    return {
        "message": "민감정보 파일 반출 탐지를 위한 AI 기반 Host DLP 시스템 API",
        "dashboard_url": "/dashboard",
        "logs_url": "/logs",
        "docs_url": "/docs",
    }


@app.get("/health")
async def health_check() -> dict:
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "analysis_mode": "external" if get_external_analyze_url() else "mock",
        "ai_server_url_configured": bool(get_external_analyze_url()),
    }


@app.get("/dashboard")
async def dashboard() -> FileResponse:
    if not FRONTEND_PATH.exists():
        raise HTTPException(status_code=404, detail="Dashboard file not found.")
    return FileResponse(FRONTEND_PATH)


@app.get("/logs")
async def logs_page() -> FileResponse:
    if not FRONTEND_PATH.exists():
        raise HTTPException(status_code=404, detail="Dashboard file not found.")
    return FileResponse(FRONTEND_PATH)


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze_event(
    payload: AnalyzeRequest,
    _: None = Depends(verify_agent_token),
) -> dict:
    return call_external_ai_server(payload)


@app.post("/api/v1/logs", status_code=201)
async def create_log(
    payload: LogCreate,
    _: None = Depends(verify_agent_token),
) -> JSONResponse:
    received_at = datetime.now(timezone.utc).isoformat()

    with closing(get_connection()) as connection:
        cursor = connection.cursor()
        if payload.event_id:
            existing_log = cursor.execute(
                "SELECT log_id FROM dlp_logs WHERE event_id = ?",
                (payload.event_id,),
            ).fetchone()
            if existing_log is not None:
                return JSONResponse(
                    status_code=200,
                    content={
                        "message": "Log already exists.",
                        "log_id": existing_log["log_id"],
                        "event_id": payload.event_id,
                        "duplicate": True,
                    },
                )

        try:
            cursor.execute(
                """
                INSERT INTO dlp_logs (
                    event_id, agent_id, timestamp, received_at, host_ip, hostname,
                    user_id, department, file_name, file_path, process_name,
                    leak_channel, detection_type, ai_score, matched_keywords,
                    model_version, policy_id, action_taken, decision_reason,
                    evidence_summary, latency_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.event_id,
                    payload.agent_id,
                    payload.timestamp.astimezone(timezone.utc).isoformat(),
                    received_at,
                    payload.host_ip,
                    payload.hostname,
                    payload.user_id,
                    payload.department,
                    payload.file_name,
                    payload.file_path,
                    payload.process_name,
                    payload.leak_channel,
                    payload.detection_type,
                    payload.ai_score,
                    ",".join(payload.matched_keywords),
                    payload.model_version,
                    payload.policy_id,
                    payload.action_taken,
                    payload.decision_reason,
                    payload.evidence_summary,
                    payload.latency_ms,
                ),
            )
        except sqlite3.IntegrityError:
            if not payload.event_id:
                raise

            existing_log = cursor.execute(
                "SELECT log_id FROM dlp_logs WHERE event_id = ?",
                (payload.event_id,),
            ).fetchone()
            if existing_log is None:
                raise

            return JSONResponse(
                status_code=200,
                content={
                    "message": "Log already exists.",
                    "log_id": existing_log["log_id"],
                    "event_id": payload.event_id,
                    "duplicate": True,
                },
            )

        connection.commit()
        log_id = cursor.lastrowid

    return JSONResponse(
        status_code=201,
        content={
            "message": "Log saved successfully.",
            "log_id": log_id,
            "event_id": payload.event_id,
            "duplicate": False,
        },
    )


@app.get("/api/v1/logs")
async def list_logs(
    limit: int = Query(default=50, ge=1, le=200),
    action: str | None = Query(default=None),
    leak_channel: str | None = Query(default=None),
    department: str | None = Query(default=None),
    user_id: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    start_date: str | None = Query(default=None),
    end_date: str | None = Query(default=None),
    q: str | None = Query(default=None),
) -> dict:
    query = """
        SELECT * FROM dlp_logs
        WHERE 1=1
    """
    params: list[str | int] = []

    if action:
        query += " AND action_taken = ?"
        params.append(action)
    if leak_channel:
        query += " AND leak_channel = ?"
        params.append(leak_channel)
    if department:
        query += " AND department = ?"
        params.append(department)
    if user_id:
        query += " AND user_id = ?"
        params.append(user_id)
    if agent_id:
        query += " AND agent_id = ?"
        params.append(agent_id)
    if start_date:
        query += " AND timestamp >= ?"
        params.append(f"{start_date}T00:00:00+00:00")
    if end_date:
        query += " AND timestamp <= ?"
        params.append(f"{end_date}T23:59:59+00:00")
    if q:
        query += """
            AND (
                file_name LIKE ? OR file_path LIKE ? OR user_id LIKE ? OR
                hostname LIKE ? OR department LIKE ? OR agent_id LIKE ? OR event_id LIKE ?
            )
        """
        search = f"%{q}%"
        params.extend([search, search, search, search, search, search, search])

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with closing(get_connection()) as connection:
        rows = connection.execute(query, params).fetchall()

    return {"items": [serialize_log(row) for row in rows], "count": len(rows)}


@app.get("/api/v1/alerts")
async def list_realtime_alerts(
    after_log_id: int | None = Query(default=None, ge=0),
    cursor_epoch: str | None = Query(default=None, min_length=1, max_length=64),
    limit: int = Query(default=20, ge=1, le=100),
) -> dict:
    """Return new high-risk logs using the DB epoch and server-issued log_id.

    The first request omits ``after_log_id`` and only receives the current cursor,
    so opening the dashboard never raises alerts for historical rows. A changed
    ``cursor_epoch`` replays high-risk rows from the replacement database.
    """
    with closing(get_connection()) as connection:
        database_epoch = connection.execute(
            """
            SELECT metadata_value
            FROM dlp_metadata
            WHERE metadata_key = ?
            """,
            (DATABASE_EPOCH_KEY,),
        ).fetchone()["metadata_value"]
        latest_log_id = connection.execute(
            "SELECT COALESCE(MAX(log_id), 0) AS latest_log_id FROM dlp_logs"
        ).fetchone()["latest_log_id"]

        if after_log_id is None:
            return {
                "items": [],
                "count": 0,
                "next_cursor": latest_log_id,
                "cursor_epoch": database_epoch,
                "cursor_reset": False,
            }

        cursor_reset = (
            (cursor_epoch is not None and cursor_epoch != database_epoch)
            or after_log_id > latest_log_id
        )
        effective_after_log_id = 0 if cursor_reset else after_log_id

        rows = connection.execute(
            """
            SELECT * FROM dlp_logs
            WHERE log_id > ?
              AND (action_taken = 'BLOCKED' OR ai_score >= ?)
            ORDER BY log_id ASC
            LIMIT ?
            """,
            (effective_after_log_id, HIGH_RISK_SCORE_THRESHOLD, limit),
        ).fetchall()

    last_returned_id = (
        rows[-1]["log_id"] if rows else effective_after_log_id
    )
    next_cursor = (
        last_returned_id
        if len(rows) == limit
        else max(latest_log_id, last_returned_id)
    )
    return {
        "items": [serialize_log(row) for row in rows],
        "count": len(rows),
        "next_cursor": next_cursor,
        "cursor_epoch": database_epoch,
        "cursor_reset": cursor_reset,
    }


@app.get("/api/v1/logs/filter-options")
async def log_filter_options() -> dict:
    with closing(get_connection()) as connection:
        departments = connection.execute(
            """
            SELECT DISTINCT department
            FROM dlp_logs
            WHERE department != ''
            ORDER BY department ASC
            """
        ).fetchall()
        users = connection.execute(
            """
            SELECT DISTINCT user_id
            FROM dlp_logs
            WHERE user_id != ''
            ORDER BY user_id ASC
            """
        ).fetchall()
        agents = connection.execute(
            """
            SELECT DISTINCT agent_id
            FROM dlp_logs
            WHERE agent_id IS NOT NULL AND agent_id != ''
            ORDER BY agent_id ASC
            """
        ).fetchall()

    return {
        "departments": [row["department"] for row in departments],
        "users": [row["user_id"] for row in users],
        "agents": [row["agent_id"] for row in agents],
        "actions": ["BLOCKED", "WARNED", "ALLOWED"],
        "leak_channels": LEAK_CHANNELS,
    }


@app.get("/api/v1/logs/{log_id}")
async def get_log(log_id: int) -> dict:
    with closing(get_connection()) as connection:
        row = connection.execute("SELECT * FROM dlp_logs WHERE log_id = ?", (log_id,)).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Log not found.")
    return serialize_log(row)


@app.get("/api/v1/policies")
async def list_policies() -> dict:
    with closing(get_connection()) as connection:
        rows = connection.execute(
            "SELECT * FROM dlp_policies ORDER BY is_active DESC, policy_id ASC"
        ).fetchall()
    return {"items": [serialize_policy(row) for row in rows], "count": len(rows)}


@app.post("/api/v1/policies", status_code=201)
async def create_policy(payload: PolicyCreate) -> dict:
    if payload.block_threshold < payload.ai_threshold:
        raise HTTPException(
            status_code=400,
            detail="block_threshold must be greater than or equal to ai_threshold.",
        )

    with closing(get_connection()) as connection:
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO dlp_policies
                (policy_name, description, ai_threshold, block_threshold, is_active, exception_extensions)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                payload.policy_name,
                payload.description,
                payload.ai_threshold,
                payload.block_threshold,
                int(payload.is_active),
                ",".join(payload.exception_extensions),
            ),
        )
        connection.commit()
        policy_id = cursor.lastrowid

    return {"message": "Policy saved successfully.", "policy_id": policy_id}


@app.get("/api/v1/dashboard/summary")
async def dashboard_summary(days: int = Query(default=7, ge=1, le=30)) -> dict:
    today = datetime.now(timezone.utc).date()
    since = datetime.combine(
        today - timedelta(days=days - 1),
        time.min,
        tzinfo=timezone.utc,
    )

    with closing(get_connection()) as connection:
        rows = connection.execute(
            "SELECT * FROM dlp_logs WHERE timestamp >= ? ORDER BY timestamp DESC",
            (since.isoformat(),),
        ).fetchall()

    logs = [serialize_log(row) for row in rows]
    total_events = len(logs)
    blocked_count = sum(1 for item in logs if item["action_taken"] == "BLOCKED")
    warned_count = sum(1 for item in logs if item["action_taken"] == "WARNED")
    allowed_count = sum(1 for item in logs if item["action_taken"] == "ALLOWED")
    average_score = round(
        sum(item["ai_score"] for item in logs) / total_events,
        2,
    ) if total_events else 0.0

    channel_counter = Counter(item["leak_channel"] for item in logs)
    department_counter = Counter(item["department"] for item in logs)
    timeline_counter = Counter(item["timestamp"][:10] for item in logs)

    timeline = []
    for offset in range(days):
        day = (since + timedelta(days=offset)).date().isoformat()
        timeline.append({"date": day, "count": timeline_counter.get(day, 0)})

    top_departments = [
        {"department": department, "count": count}
        for department, count in department_counter.most_common(5)
    ]
    high_risk_events = sorted(
        [
            item
            for item in logs
            if item["action_taken"] == "BLOCKED"
            or item["ai_score"] >= HIGH_RISK_SCORE_THRESHOLD
        ],
        key=lambda item: item["timestamp"],
        reverse=True,
    )[:20]

    return {
        "period_days": days,
        "kpis": {
            "total_events": total_events,
            "blocked_count": blocked_count,
            "warned_count": warned_count,
            "allowed_count": allowed_count,
            "average_score": average_score,
        },
        "channel_breakdown": [
            {"channel": channel, "count": count}
            for channel, count in channel_counter.most_common()
        ],
        "top_departments": top_departments,
        "high_risk_events": [
            {
                "log_id": item["log_id"],
                "event_id": item["event_id"],
                "agent_id": item["agent_id"],
                "timestamp": item["timestamp"],
                "department": item["department"],
                "user_id": item["user_id"],
                "file_name": item["file_name"],
                "file_path": item["file_path"],
                "leak_channel": item["leak_channel"],
                "ai_score": item["ai_score"],
                "model_version": item["model_version"],
                "action_taken": item["action_taken"],
                "decision_reason": item["decision_reason"],
                "evidence_summary": item["evidence_summary"],
            }
            for item in high_risk_events
        ],
        "timeline": timeline,
    }
