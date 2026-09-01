from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import sqlite3
from collections import Counter
from contextlib import asynccontextmanager, closing
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from secrets import compare_digest
from time import perf_counter
from typing import Annotated, Any, Literal
from urllib.error import HTTPError, URLError
from urllib.request import Request as URLRequest, urlopen
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "backend" / "dlp_dashboard.db"
FRONTEND_PATH = BASE_DIR / "frontend" / "index.html"
NO_STORE_HEADERS = {"Cache-Control": "no-store"}
AGENT_API_TOKEN = os.getenv("AGENT_API_TOKEN", "").strip()
AGENT_API_TOKENS_JSON = os.getenv("AGENT_API_TOKENS_JSON", "").strip()
AI_SERVER_URL = os.getenv("AI_SERVER_URL", "").strip()
AI_SERVER_TOKEN = os.getenv("AI_SERVER_TOKEN", "").strip()
AI_SERVER_TIMEOUT_SECONDS = float(os.getenv("AI_SERVER_TIMEOUT_SECONDS", "5"))
DATABASE_EPOCH_KEY = "database_epoch"
AGENT_HEARTBEAT_TTL_SECONDS = 90
MAX_AI_RESPONSE_BYTES = 64 * 1024
UNSAFE_TOKEN_VALUES = {
    "replace-with-a-long-random-token",
    "replace-with-ai-server-random-token",
}
MIN_DASHBOARD_PASSWORD_LENGTH = 16
DASHBOARD_VIEWER_USERNAME = os.getenv("DASHBOARD_VIEWER_USERNAME", "").strip()
DASHBOARD_VIEWER_PASSWORD = os.getenv("DASHBOARD_VIEWER_PASSWORD", "")
DASHBOARD_ADMIN_USERNAME = os.getenv("DASHBOARD_ADMIN_USERNAME", "").strip()
DASHBOARD_ADMIN_PASSWORD = os.getenv("DASHBOARD_ADMIN_PASSWORD", "")


def parse_high_risk_score_threshold(raw_value: str) -> float:
    try:
        threshold = float(raw_value)
    except ValueError as error:
        raise RuntimeError(
            "HIGH_RISK_SCORE_THRESHOLD must be a finite number between 0 and 1."
        ) from error
    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise RuntimeError(
            "HIGH_RISK_SCORE_THRESHOLD must be a finite number between 0 and 1."
        )
    return threshold


HIGH_RISK_SCORE_THRESHOLD = parse_high_risk_score_threshold(
    os.getenv("HIGH_RISK_SCORE_THRESHOLD", "0.85")
)


def require_ascii_token(name: str, value: str) -> None:
    try:
        token_bytes = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise RuntimeError(f"{name} must be an ASCII random token.") from error
    if len(token_bytes) < 32 or value in UNSAFE_TOKEN_VALUES:
        raise RuntimeError(f"{name} must contain at least 32 ASCII characters.")


def parse_agent_api_tokens(raw_value: str) -> dict[str, str]:
    if not raw_value:
        return {}
    try:
        parsed = json.loads(raw_value)
    except json.JSONDecodeError as error:
        raise RuntimeError("AGENT_API_TOKENS_JSON must be a JSON object.") from error
    if not isinstance(parsed, dict) or not parsed:
        raise RuntimeError("AGENT_API_TOKENS_JSON must be a non-empty JSON object.")

    tokens: dict[str, str] = {}
    for raw_agent_id, raw_token in parsed.items():
        if not isinstance(raw_agent_id, str) or not 1 <= len(raw_agent_id.strip()) <= 100:
            raise RuntimeError("AGENT_API_TOKENS_JSON keys must be 1-100 character agent IDs.")
        if not isinstance(raw_token, str):
            raise RuntimeError("AGENT_API_TOKENS_JSON values must be ASCII tokens.")
        agent_id = raw_agent_id.strip()
        if agent_id in tokens:
            raise RuntimeError("AGENT_API_TOKENS_JSON agent IDs must be unique after trimming.")
        require_ascii_token(f"AGENT_API_TOKENS_JSON[{agent_id!r}]", raw_token)
        if raw_token in tokens.values():
            raise RuntimeError("AGENT_API_TOKENS_JSON tokens must be unique per agent.")
        tokens[agent_id] = raw_token
    return tokens


def validate_dashboard_auth_configuration(
    viewer_username: str,
    viewer_password: str,
    admin_username: str,
    admin_password: str,
) -> bool:
    values = (viewer_username, viewer_password, admin_username, admin_password)
    if not any(values):
        return False
    if not all(values):
        raise RuntimeError(
            "Configure all dashboard viewer/admin usernames and passwords, or leave all four empty."
        )
    if viewer_username == admin_username:
        raise RuntimeError("Dashboard viewer and admin usernames must be different.")

    for name, username in (
        ("DASHBOARD_VIEWER_USERNAME", viewer_username),
        ("DASHBOARD_ADMIN_USERNAME", admin_username),
    ):
        try:
            username.encode("ascii")
        except UnicodeEncodeError as error:
            raise RuntimeError(f"{name} must be ASCII for HTTP Basic authentication.") from error
        if ":" in username:
            raise RuntimeError(f"{name} must not contain a colon.")

    for name, password in (
        ("DASHBOARD_VIEWER_PASSWORD", viewer_password),
        ("DASHBOARD_ADMIN_PASSWORD", admin_password),
    ):
        try:
            password_bytes = password.encode("ascii")
        except UnicodeEncodeError as error:
            raise RuntimeError(f"{name} must be an ASCII password.") from error
        if len(password_bytes) < MIN_DASHBOARD_PASSWORD_LENGTH:
            raise RuntimeError(
                f"{name} must contain at least {MIN_DASHBOARD_PASSWORD_LENGTH} ASCII characters."
            )

    return True


if AGENT_API_TOKEN:
    require_ascii_token("AGENT_API_TOKEN", AGENT_API_TOKEN)
AGENT_API_TOKENS = parse_agent_api_tokens(AGENT_API_TOKENS_JSON)
if AGENT_API_TOKEN and AGENT_API_TOKENS:
    raise RuntimeError("Configure AGENT_API_TOKEN or AGENT_API_TOKENS_JSON, not both.")
if AI_SERVER_URL:
    require_ascii_token("AI_SERVER_TOKEN", AI_SERVER_TOKEN)
if not math.isfinite(AI_SERVER_TIMEOUT_SECONDS) or AI_SERVER_TIMEOUT_SECONDS <= 0:
    raise RuntimeError("AI_SERVER_TIMEOUT_SECONDS must be a positive finite number.")
DASHBOARD_AUTH_ENABLED = validate_dashboard_auth_configuration(
    DASHBOARD_VIEWER_USERNAME,
    DASHBOARD_VIEWER_PASSWORD,
    DASHBOARD_ADMIN_USERNAME,
    DASHBOARD_ADMIN_PASSWORD,
)

LEAK_CHANNELS = [
    "USB_COPY",
    "WEB_UPLOAD",
    "EMAIL_ATTACHMENT",
    "PRINT",
    "MESSENGER",
    "CLIPBOARD",
    "CLOUD_DRIVE",
]

MatchedItem = Annotated[str, Field(min_length=1, max_length=100)]
ExtensionItem = Annotated[str, Field(min_length=1, max_length=20)]
MetadataKey = Annotated[str, Field(min_length=1, max_length=100)]
MetadataString = Annotated[str, Field(max_length=500)]


@asynccontextmanager
async def lifespan(dashboard_app: FastAPI):
    if not getattr(dashboard_app.state, "security_validated", False):
        raise RuntimeError("Start the dashboard with: python run_dashboard.py")
    init_db()
    yield

app = FastAPI(
    title="민감정보 파일 반출 탐지를 위한 AI 기반 Host DLP 시스템",
    version="0.1.0",
    description="Host DLP events collection and dashboard API.",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.state.security_validated = False
dashboard_basic = HTTPBasic(auto_error=False)

class LogCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    event_id: str = Field(..., min_length=1, max_length=120)
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
    analysis_status: Literal["SUCCESS", "FAILED", "SKIPPED"]
    ai_score: float | None = Field(default=None, ge=0.0, le=1.0)
    model_version: str | None = Field(default=None, max_length=100)
    matched_keywords: list[MatchedItem] = Field(default_factory=list, max_length=100)
    policy_id: str | None = Field(default=None, max_length=100)
    action_taken: Literal["BLOCKED", "WARNED", "ALLOWED"]
    decision_reason: str | None = Field(default=None, max_length=500)
    evidence_summary: str = Field(default="", max_length=500)
    latency_ms: int | None = Field(default=None, ge=0, le=600000)

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_include_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a UTC offset")
        return value

    @model_validator(mode="after")
    def analysis_result_must_be_consistent(self) -> LogCreate:
        if self.analysis_status == "SUCCESS" and self.ai_score is None:
            raise ValueError("ai_score is required when analysis_status is SUCCESS")
        if self.analysis_status != "SUCCESS" and self.ai_score is not None:
            raise ValueError("ai_score must be null unless analysis_status is SUCCESS")
        return self


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

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
    matched_patterns: list[MatchedItem] = Field(default_factory=list, max_length=100)
    snippet: str = Field(..., min_length=1, max_length=4000)
    metadata: dict[
        MetadataKey,
        MetadataString | int | float | bool | None,
    ] = Field(default_factory=dict, max_length=50)


class AnalyzeResponse(BaseModel):
    event_id: str = Field(..., min_length=1, max_length=120)
    decision: Literal["allow", "review", "block"]
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    model_version: str = Field(..., min_length=1, max_length=100)
    latency_ms: int = Field(..., ge=0, le=600000)
    reason: str = Field(..., max_length=500)
    evidence_summary: str = Field(..., max_length=500)


class AgentHeartbeat(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    agent_id: str = Field(..., min_length=1, max_length=100)
    hostname: str = Field(..., min_length=1, max_length=100)
    agent_version: str = Field(
        ...,
        min_length=1,
        max_length=50,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._+-]*$",
    )
    mode: Literal["user", "system", "all"]


class PolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    policy_name: str = Field(..., min_length=1, max_length=100)
    description: str = Field(default="", max_length=300)
    ai_threshold: float = Field(..., ge=0.0, le=1.0)
    block_threshold: float = Field(..., ge=0.0, le=1.0)
    is_active: bool = True
    exception_extensions: list[ExtensionItem] = Field(default_factory=list, max_length=50)


def verify_agent_token(
    x_agent_token: str | None = Header(default=None, alias="X-Agent-Token"),
    x_agent_id: str | None = Header(default=None, alias="X-Agent-ID"),
) -> str | None:
    try:
        provided_token = (x_agent_token or "").encode("ascii")
    except UnicodeEncodeError:
        provided_token = b""

    if AGENT_API_TOKENS:
        expected_token = AGENT_API_TOKENS.get((x_agent_id or "").strip())
        if expected_token and provided_token and compare_digest(
            provided_token,
            expected_token.encode("ascii"),
        ):
            return x_agent_id.strip()
    elif AGENT_API_TOKEN and provided_token and compare_digest(
        provided_token,
        AGENT_API_TOKEN.encode("ascii"),
    ):
        return None

    if not AGENT_API_TOKEN and not AGENT_API_TOKENS:
        raise HTTPException(status_code=503, detail="Agent authentication is not configured.")
    else:
        raise HTTPException(status_code=401, detail="Invalid or missing agent token.")


def require_secure_dashboard_transport(request: Request) -> None:
    if DASHBOARD_AUTH_ENABLED and request.url.scheme != "https":
        raise HTTPException(
            status_code=426,
            detail="Dashboard Basic authentication requires HTTPS.",
            headers={"Upgrade": "TLS/1.2"},
        )


def dashboard_role(
    credentials: HTTPBasicCredentials | None,
) -> Literal["viewer", "admin"]:
    if credentials is not None:
        try:
            provided_username = credentials.username.encode("ascii")
            provided_password = credentials.password.encode("ascii")
        except UnicodeEncodeError:
            pass
        else:
            for role, username, password in (
                ("admin", DASHBOARD_ADMIN_USERNAME, DASHBOARD_ADMIN_PASSWORD),
                ("viewer", DASHBOARD_VIEWER_USERNAME, DASHBOARD_VIEWER_PASSWORD),
            ):
                username_matches = compare_digest(
                    provided_username,
                    username.encode("ascii"),
                )
                password_matches = compare_digest(
                    provided_password,
                    password.encode("ascii"),
                )
                if username_matches and password_matches:
                    return role
    raise HTTPException(
        status_code=401,
        detail="Invalid or missing dashboard credentials.",
        headers={"WWW-Authenticate": 'Basic realm="Host DLP Dashboard"'},
    )


def verify_dashboard_viewer(
    request: Request,
    credentials: Annotated[
        HTTPBasicCredentials | None,
        Depends(dashboard_basic),
    ],
) -> None:
    if DASHBOARD_AUTH_ENABLED:
        require_secure_dashboard_transport(request)
        dashboard_role(credentials)


def verify_policy_admin_access(
    request: Request,
    credentials: Annotated[
        HTTPBasicCredentials | None,
        Depends(dashboard_basic),
    ],
    x_agent_token: str | None = Header(default=None, alias="X-Agent-Token"),
    x_agent_id: str | None = Header(default=None, alias="X-Agent-ID"),
) -> str:
    if not DASHBOARD_AUTH_ENABLED:
        verify_agent_token(x_agent_token, x_agent_id)
        return "agent-token"
    require_secure_dashboard_transport(request)
    if dashboard_role(credentials) != "admin":
        raise HTTPException(
            status_code=403,
            detail="Dashboard admin credentials are required.",
        )
    return "dashboard-admin"


def require_matching_agent_id(authenticated_agent_id: str | None, payload_agent_id: str) -> None:
    if authenticated_agent_id is not None and authenticated_agent_id != payload_agent_id:
        raise HTTPException(
            status_code=403,
            detail="Authenticated agent ID does not match the payload.",
        )


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

    raw_score = raw_response.get("confidence_score")
    if isinstance(raw_score, bool) or not isinstance(raw_score, (int, float)):
        raise HTTPException(
            status_code=502,
            detail="AI server confidence_score must be a number between 0 and 1.",
        )
    confidence_score = float(raw_score)
    if not math.isfinite(confidence_score) or not 0.0 <= confidence_score <= 1.0:
        raise HTTPException(
            status_code=502,
            detail="AI server confidence_score must be between 0 and 1.",
        )

    returned_latency = raw_response.get("latency_ms", latency_ms)
    if isinstance(returned_latency, bool):
        raise HTTPException(status_code=502, detail="AI server response has an invalid latency_ms.")
    try:
        returned_latency_number = float(returned_latency)
    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=502,
            detail="AI server response has an invalid latency_ms.",
        ) from error
    if (
        not math.isfinite(returned_latency_number)
        or not 0.0 <= returned_latency_number <= 600000.0
    ):
        raise HTTPException(
            status_code=502,
            detail="AI server latency_ms must be between 0 and 600000.",
        )
    normalized_latency = round(returned_latency_number)

    raw_model_version = raw_response.get("model_version")
    if not isinstance(raw_model_version, str) or not raw_model_version.strip():
        raise HTTPException(status_code=502, detail="AI server response has no valid model_version.")
    model_version = raw_model_version.strip()
    if len(model_version) > 100:
        raise HTTPException(status_code=502, detail="AI server model_version is too long.")

    fallback_reason = "External AI server returned no analysis reason."
    reason = (
        raw_response.get("reason")
        or raw_response.get("evidence_summary")
        or raw_response.get("explanation")
        or fallback_reason
    )
    evidence_summary = (
        raw_response.get("evidence_summary")
        or raw_response.get("reason")
        or raw_response.get("explanation")
        or fallback_reason
    )
    if not isinstance(reason, str) or len(reason) > 500:
        raise HTTPException(status_code=502, detail="AI server response has an invalid reason.")
    if not isinstance(evidence_summary, str) or len(evidence_summary) > 500:
        raise HTTPException(
            status_code=502,
            detail="AI server response has an invalid evidence_summary.",
        )

    return {
        "event_id": raw_event_id,
        "decision": decision,
        "confidence_score": round(confidence_score, 4),
        "model_version": model_version,
        "latency_ms": normalized_latency,
        "reason": reason,
        "evidence_summary": evidence_summary,
    }


def call_external_ai_server(payload: AnalyzeRequest) -> dict:
    analyze_url = get_external_analyze_url()
    if analyze_url is None:
        raise HTTPException(status_code=503, detail="AI proxy is not configured.")

    started_at = perf_counter()
    body = json.dumps(payload.model_dump()).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if AI_SERVER_TOKEN:
        headers["Authorization"] = f"Bearer {AI_SERVER_TOKEN}"

    request = URLRequest(analyze_url, data=body, headers=headers, method="POST")

    try:
        with urlopen(request, timeout=AI_SERVER_TIMEOUT_SECONDS) as response:
            response_body = response.read(MAX_AI_RESPONSE_BYTES + 1)
            if len(response_body) > MAX_AI_RESPONSE_BYTES:
                raise HTTPException(status_code=502, detail="AI server response is too large.")
            raw_body = response_body.decode("utf-8")
    except HTTPError as error:
        raise HTTPException(
            status_code=502,
            detail=f"AI server returned HTTP {error.code}.",
        ) from error
    except (URLError, TimeoutError) as error:
        raise HTTPException(
            status_code=502,
            detail="Could not connect to AI server.",
        ) from error
    except UnicodeDecodeError as error:
        raise HTTPException(status_code=502, detail="AI server response is not UTF-8.") from error

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


def decode_matched_keywords(raw_value: str | None) -> list[str]:
    raw_value = raw_value or ""
    try:
        decoded = json.loads(raw_value)
        if not isinstance(decoded, list) or not all(isinstance(item, str) for item in decoded):
            raise ValueError
        return decoded
    except (json.JSONDecodeError, TypeError, ValueError):
        return [item for item in raw_value.split(",") if item]


def log_payload_hash(payload: LogCreate) -> str:
    canonical = payload.model_dump(mode="json")
    canonical["timestamp"] = payload.timestamp.astimezone(timezone.utc).isoformat()
    serialized = json.dumps(
        canonical,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def create_log_table(cursor: sqlite3.Cursor) -> None:
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
            analysis_status TEXT NOT NULL
                CHECK (analysis_status IN ('SUCCESS', 'FAILED', 'SKIPPED')),
            ai_score REAL,
            model_version TEXT,
            matched_keywords TEXT NOT NULL,
            policy_id TEXT,
            action_taken TEXT NOT NULL,
            decision_reason TEXT,
            evidence_summary TEXT NOT NULL,
            latency_ms INTEGER,
            payload_hash TEXT,
            CHECK (
                (analysis_status = 'SUCCESS' AND ai_score BETWEEN 0.0 AND 1.0)
                OR (analysis_status IN ('FAILED', 'SKIPPED') AND ai_score IS NULL)
            )
        )
        """
    )


def ensure_log_schema(cursor: sqlite3.Cursor) -> None:
    table_info = cursor.execute("PRAGMA table_info(dlp_logs)").fetchall()
    columns = {row["name"]: row for row in table_info}
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

    table_info = cursor.execute("PRAGMA table_info(dlp_logs)").fetchall()
    columns = {row["name"]: row for row in table_info}
    if (
        "analysis_status" not in columns
        or "payload_hash" not in columns
        or columns["ai_score"]["notnull"]
    ):
        cursor.execute("ALTER TABLE dlp_logs RENAME TO dlp_logs_legacy")
        create_log_table(cursor)
        cursor.execute(
            """
            INSERT INTO dlp_logs (
                log_id, event_id, agent_id, timestamp, received_at, host_ip,
                hostname, user_id, department, file_name, file_path,
                process_name, leak_channel, detection_type, analysis_status,
                ai_score, model_version, matched_keywords, policy_id,
                action_taken, decision_reason, evidence_summary, latency_ms
            )
            SELECT
                log_id, event_id, agent_id, timestamp, received_at, host_ip,
                hostname, user_id, department, file_name, file_path,
                process_name, leak_channel, detection_type,
                CASE
                    WHEN model_version = 'unavailable' THEN 'FAILED'
                    WHEN detection_type = 'RULE_BASED' AND model_version IS NULL THEN 'SKIPPED'
                    ELSE 'SUCCESS'
                END,
                CASE
                    WHEN model_version = 'unavailable' THEN NULL
                    WHEN detection_type = 'RULE_BASED' AND model_version IS NULL THEN NULL
                    ELSE ai_score
                END,
                model_version, matched_keywords, policy_id, action_taken,
                decision_reason, evidence_summary, latency_ms
            FROM dlp_logs_legacy
            """
        )
        cursor.execute("DROP TABLE dlp_logs_legacy")

    rows_without_hash = cursor.execute(
        "SELECT * FROM dlp_logs WHERE event_id IS NOT NULL AND payload_hash IS NULL"
    ).fetchall()
    for row in rows_without_hash:
        payload = LogCreate.model_validate(
            {
                key: row[key]
                for key in (
                    "event_id", "agent_id", "timestamp", "host_ip", "hostname",
                    "user_id", "department", "file_name", "file_path",
                    "process_name", "leak_channel", "detection_type",
                    "analysis_status", "ai_score", "model_version", "policy_id",
                    "action_taken", "decision_reason", "evidence_summary",
                    "latency_ms",
                )
            }
            | {"matched_keywords": decode_matched_keywords(row["matched_keywords"])}
        )
        cursor.execute(
            "UPDATE dlp_logs SET payload_hash = ? WHERE log_id = ?",
            (log_payload_hash(payload), row["log_id"]),
        )

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
        create_log_table(cursor)
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
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS dlp_agent_heartbeats (
                agent_id TEXT NOT NULL,
                mode TEXT NOT NULL CHECK (mode IN ('user', 'system', 'all')),
                hostname TEXT NOT NULL,
                agent_version TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                PRIMARY KEY (agent_id, mode)
            )
            """
        )
        # ponytail: append-only; add approved archival when audit volume requires it.
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS dlp_policy_audit (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at TEXT NOT NULL,
                actor TEXT NOT NULL CHECK (actor IN ('dashboard-admin', 'agent-token')),
                action TEXT NOT NULL CHECK (action = 'POLICY_CREATED'),
                policy_id INTEGER NOT NULL,
                policy_name TEXT NOT NULL,
                description TEXT NOT NULL,
                ai_threshold REAL NOT NULL,
                block_threshold REAL NOT NULL,
                is_active INTEGER NOT NULL,
                exception_extensions TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_dlp_policy_audit_occurred_at
            ON dlp_policy_audit(occurred_at DESC, audit_id DESC)
            """
        )
        for operation in ("UPDATE", "DELETE"):
            cursor.execute(
                f"""
                CREATE TRIGGER IF NOT EXISTS reject_dlp_policy_audit_{operation.lower()}
                BEFORE {operation} ON dlp_policy_audit
                BEGIN
                    SELECT RAISE(ABORT, 'policy audit is append-only');
                END
                """
            )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS dlp_ingest_conflicts (
                conflict_id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at TEXT NOT NULL,
                event_id TEXT NOT NULL,
                agent_id TEXT,
                stored_payload_hash TEXT NOT NULL,
                received_payload_hash TEXT NOT NULL
            )
            """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_dlp_ingest_conflicts_occurred_at
            ON dlp_ingest_conflicts(occurred_at DESC, conflict_id DESC)
            """
        )
        for operation in ("UPDATE", "DELETE"):
            cursor.execute(
                f"""
                CREATE TRIGGER IF NOT EXISTS reject_dlp_ingest_conflicts_{operation.lower()}
                BEFORE {operation} ON dlp_ingest_conflicts
                BEGIN
                    SELECT RAISE(ABORT, 'ingest conflict audit is append-only');
                END
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
        "analysis_status": row["analysis_status"],
        "ai_score": row["ai_score"],
        "model_version": row["model_version"],
        "matched_keywords": decode_matched_keywords(row["matched_keywords"]),
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


def serialize_policy_audit(row: sqlite3.Row) -> dict:
    return {
        "audit_id": row["audit_id"],
        "occurred_at": row["occurred_at"],
        "actor": row["actor"],
        "action": row["action"],
        **serialize_policy(row),
    }


def serialize_agent_heartbeat(
    row: sqlite3.Row,
    stale_cutoff: datetime,
) -> dict:
    last_seen_at = datetime.fromisoformat(row["last_seen_at"])
    return {
        "agent_id": row["agent_id"],
        "mode": row["mode"],
        "hostname": row["hostname"],
        "agent_version": row["agent_version"],
        "last_seen_at": row["last_seen_at"],
        "status": "online" if last_seen_at >= stale_cutoff else "stale",
    }


@app.get("/")
async def read_root() -> dict:
    return {
        "message": "민감정보 파일 반출 탐지를 위한 AI 기반 Host DLP 시스템 API",
        "dashboard_url": "/dashboard",
        "logs_url": "/logs",
        "docs_url": "/docs",
    }


@app.get(
    "/openapi.json",
    dependencies=[Depends(verify_dashboard_viewer)],
    include_in_schema=False,
)
def protected_openapi() -> JSONResponse:
    return JSONResponse(app.openapi(), headers=NO_STORE_HEADERS)


@app.get(
    "/docs",
    dependencies=[Depends(verify_dashboard_viewer)],
    include_in_schema=False,
)
def protected_swagger_docs() -> HTMLResponse:
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title=f"{app.title} - Swagger UI",
    )


@app.get(
    "/redoc",
    dependencies=[Depends(verify_dashboard_viewer)],
    include_in_schema=False,
)
def protected_redoc() -> HTMLResponse:
    return get_redoc_html(
        openapi_url="/openapi.json",
        title=f"{app.title} - ReDoc",
    )


@app.get("/health")
def health_check() -> dict:
    health = {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "analysis_mode": "external" if get_external_analyze_url() else "disabled",
        "ai_server_url_configured": bool(get_external_analyze_url()),
        "high_risk_score_threshold": HIGH_RISK_SCORE_THRESHOLD,
        "dashboard_auth_enabled": DASHBOARD_AUTH_ENABLED,
    }
    try:
        with closing(get_connection()) as connection:
            database_epoch = connection.execute(
                """
                SELECT metadata_value
                FROM dlp_metadata
                WHERE metadata_key = ?
                """,
                (DATABASE_EPOCH_KEY,),
            ).fetchone()
    except sqlite3.Error:
        database_epoch = None

    if database_epoch is None:
        health["status"] = "error"
        health["database_status"] = "error"
        return JSONResponse(status_code=503, content=health)

    health["database_status"] = "ok"
    return health


@app.get("/api/v1/agent-check", dependencies=[Depends(verify_agent_token)])
async def agent_connection_check() -> dict:
    """Verify Agent authentication without creating a dashboard log."""
    return {"status": "ok", "agent_token": "accepted"}


@app.post("/api/v1/agents/heartbeat")
def record_agent_heartbeat(
    payload: AgentHeartbeat,
    authenticated_agent_id: str | None = Depends(verify_agent_token),
) -> dict:
    """Record process liveness using the Web server's clock."""
    require_matching_agent_id(authenticated_agent_id, payload.agent_id)
    last_seen_at = datetime.now(timezone.utc).isoformat()
    with closing(get_connection()) as connection:
        connection.execute(
            """
            INSERT INTO dlp_agent_heartbeats (
                agent_id, mode, hostname, agent_version, last_seen_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(agent_id, mode) DO UPDATE SET
                hostname = excluded.hostname,
                agent_version = excluded.agent_version,
                last_seen_at = excluded.last_seen_at
            """,
            (
                payload.agent_id,
                payload.mode,
                payload.hostname,
                payload.agent_version,
                last_seen_at,
            ),
        )
        connection.commit()

    return {
        "status": "ok",
        "agent_id": payload.agent_id,
        "mode": payload.mode,
        "last_seen_at": last_seen_at,
    }


@app.get("/api/v1/agents", dependencies=[Depends(verify_dashboard_viewer)])
def list_agent_processes() -> dict:
    """List heartbeat freshness; this does not assert channel health."""
    checked_at = datetime.now(timezone.utc)
    stale_cutoff = checked_at - timedelta(seconds=AGENT_HEARTBEAT_TTL_SECONDS)
    with closing(get_connection()) as connection:
        rows = connection.execute(
            """
            SELECT agent_id, mode, hostname, agent_version, last_seen_at
            FROM dlp_agent_heartbeats
            ORDER BY agent_id ASC, mode ASC
            """
        ).fetchall()

    items = [serialize_agent_heartbeat(row, stale_cutoff) for row in rows]
    online_count = sum(item["status"] == "online" for item in items)
    return {
        "items": items,
        "count": len(items),
        "online_count": online_count,
        "stale_count": len(items) - online_count,
        "heartbeat_ttl_seconds": AGENT_HEARTBEAT_TTL_SECONDS,
        "checked_at": checked_at.isoformat(),
    }


@app.get("/dashboard", dependencies=[Depends(verify_dashboard_viewer)])
async def dashboard() -> FileResponse:
    if not FRONTEND_PATH.exists():
        raise HTTPException(status_code=404, detail="Dashboard file not found.")
    return FileResponse(FRONTEND_PATH, headers=NO_STORE_HEADERS)


@app.get("/logs", dependencies=[Depends(verify_dashboard_viewer)])
async def logs_page() -> FileResponse:
    if not FRONTEND_PATH.exists():
        raise HTTPException(status_code=404, detail="Dashboard file not found.")
    return FileResponse(FRONTEND_PATH, headers=NO_STORE_HEADERS)


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
def analyze_event(
    payload: AnalyzeRequest,
    _: str | None = Depends(verify_agent_token),
) -> dict:
    """Run the blocking upstream HTTP call in FastAPI's worker thread pool."""
    return call_external_ai_server(payload)


@app.post("/api/v1/logs", status_code=201)
def create_log(
    payload: LogCreate,
    authenticated_agent_id: str | None = Depends(verify_agent_token),
) -> JSONResponse:
    if payload.agent_id is None and authenticated_agent_id is not None:
        raise HTTPException(status_code=422, detail="agent_id is required with per-agent tokens.")
    if payload.agent_id is not None:
        require_matching_agent_id(authenticated_agent_id, payload.agent_id)
    received_at = datetime.now(timezone.utc).isoformat()
    incoming_payload_hash = log_payload_hash(payload)

    with closing(get_connection()) as connection:
        cursor = connection.cursor()
        existing_log = cursor.execute(
            "SELECT log_id, payload_hash FROM dlp_logs WHERE event_id = ?",
            (payload.event_id,),
        ).fetchone()
        if existing_log is not None:
            if existing_log["payload_hash"] == incoming_payload_hash:
                return JSONResponse(
                    status_code=200,
                    content={
                        "message": "Log already exists.",
                        "log_id": existing_log["log_id"],
                        "event_id": payload.event_id,
                        "duplicate": True,
                    },
                )
            cursor.execute(
                """
                INSERT INTO dlp_ingest_conflicts (
                    occurred_at, event_id, agent_id,
                    stored_payload_hash, received_payload_hash
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    received_at,
                    payload.event_id,
                    payload.agent_id,
                    existing_log["payload_hash"],
                    incoming_payload_hash,
                ),
            )
            connection.commit()
            raise HTTPException(
                status_code=409,
                detail="event_id already exists with a different payload.",
            )

        try:
            cursor.execute(
                """
                INSERT INTO dlp_logs (
                    event_id, agent_id, timestamp, received_at, host_ip, hostname,
                    user_id, department, file_name, file_path, process_name,
                    leak_channel, detection_type, analysis_status, ai_score,
                    matched_keywords, model_version, policy_id, action_taken,
                    decision_reason, evidence_summary, latency_ms, payload_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    payload.analysis_status,
                    payload.ai_score,
                    json.dumps(payload.matched_keywords, ensure_ascii=False),
                    payload.model_version,
                    payload.policy_id,
                    payload.action_taken,
                    payload.decision_reason,
                    payload.evidence_summary,
                    payload.latency_ms,
                    incoming_payload_hash,
                ),
            )
        except sqlite3.IntegrityError:
            connection.rollback()
            existing_log = cursor.execute(
                "SELECT log_id, payload_hash FROM dlp_logs WHERE event_id = ?",
                (payload.event_id,),
            ).fetchone()
            if existing_log is None:
                raise

            if existing_log["payload_hash"] == incoming_payload_hash:
                return JSONResponse(
                    status_code=200,
                    content={
                        "message": "Log already exists.",
                        "log_id": existing_log["log_id"],
                        "event_id": payload.event_id,
                        "duplicate": True,
                    },
                )
            cursor.execute(
                """
                INSERT INTO dlp_ingest_conflicts (
                    occurred_at, event_id, agent_id,
                    stored_payload_hash, received_payload_hash
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    received_at,
                    payload.event_id,
                    payload.agent_id,
                    existing_log["payload_hash"],
                    incoming_payload_hash,
                ),
            )
            connection.commit()
            raise HTTPException(
                status_code=409,
                detail="event_id already exists with a different payload.",
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


@app.get("/api/v1/logs", dependencies=[Depends(verify_dashboard_viewer)])
def list_logs(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    action: str | None = Query(default=None),
    analysis_status: Literal["SUCCESS", "FAILED", "SKIPPED"] | None = Query(default=None),
    leak_channel: str | None = Query(default=None),
    department: str | None = Query(default=None),
    user_id: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    start_date: str | None = Query(default=None),
    end_date: str | None = Query(default=None),
    q: str | None = Query(default=None),
) -> dict:
    where_clause = """
        FROM dlp_logs
        WHERE 1=1
    """
    params: list[str | int] = []

    if action:
        where_clause += " AND action_taken = ?"
        params.append(action)
    if analysis_status:
        where_clause += " AND analysis_status = ?"
        params.append(analysis_status)
    if leak_channel:
        where_clause += " AND leak_channel = ?"
        params.append(leak_channel)
    if department:
        where_clause += " AND department = ?"
        params.append(department)
    if user_id:
        where_clause += " AND user_id = ?"
        params.append(user_id)
    if agent_id:
        where_clause += " AND agent_id = ?"
        params.append(agent_id)
    if start_date:
        where_clause += " AND timestamp >= ?"
        params.append(f"{start_date}T00:00:00+00:00")
    if end_date:
        where_clause += " AND timestamp <= ?"
        params.append(f"{end_date}T23:59:59+00:00")
    if q:
        where_clause += """
            AND (
                file_name LIKE ? OR file_path LIKE ? OR user_id LIKE ? OR
                hostname LIKE ? OR department LIKE ? OR agent_id LIKE ? OR event_id LIKE ?
            )
        """
        search = f"%{q}%"
        params.extend([search, search, search, search, search, search, search])

    with closing(get_connection()) as connection:
        total = connection.execute(
            f"SELECT COUNT(*) {where_clause}",
            params,
        ).fetchone()[0]
        rows = connection.execute(
            f"""
            SELECT * {where_clause}
            ORDER BY timestamp DESC, log_id DESC
            LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        ).fetchall()

    return {
        "items": [serialize_log(row) for row in rows],
        "count": len(rows),
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/v1/alerts", dependencies=[Depends(verify_dashboard_viewer)])
def list_realtime_alerts(
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
              AND (
                  action_taken = 'BLOCKED'
                  OR (analysis_status = 'SUCCESS' AND ai_score >= ?)
              )
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


@app.get(
    "/api/v1/logs/filter-options",
    dependencies=[Depends(verify_dashboard_viewer)],
)
def log_filter_options() -> dict:
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
        "analysis_statuses": ["SUCCESS", "FAILED", "SKIPPED"],
        "leak_channels": LEAK_CHANNELS,
    }


@app.get("/api/v1/logs/{log_id}", dependencies=[Depends(verify_dashboard_viewer)])
def get_log(log_id: int) -> dict:
    with closing(get_connection()) as connection:
        row = connection.execute("SELECT * FROM dlp_logs WHERE log_id = ?", (log_id,)).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Log not found.")
    return serialize_log(row)


@app.get("/api/v1/policies", dependencies=[Depends(verify_dashboard_viewer)])
def list_policies() -> dict:
    with closing(get_connection()) as connection:
        rows = connection.execute(
            "SELECT * FROM dlp_policies ORDER BY is_active DESC, policy_id ASC"
        ).fetchall()
    return {"items": [serialize_policy(row) for row in rows], "count": len(rows)}


@app.post("/api/v1/policies", status_code=201)
def create_policy(
    payload: PolicyCreate,
    actor: str = Depends(verify_policy_admin_access),
) -> dict:
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
        policy_id = cursor.lastrowid
        cursor.execute(
            """
            INSERT INTO dlp_policy_audit (
                occurred_at, actor, action, policy_id, policy_name, description,
                ai_threshold, block_threshold, is_active, exception_extensions
            ) VALUES (?, ?, 'POLICY_CREATED', ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                actor,
                policy_id,
                payload.policy_name,
                payload.description,
                payload.ai_threshold,
                payload.block_threshold,
                int(payload.is_active),
                ",".join(payload.exception_extensions),
            ),
        )
        connection.commit()

    return {"message": "Policy saved successfully.", "policy_id": policy_id}


@app.get("/api/v1/policy-audit")
def list_policy_audit(
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: str = Depends(verify_policy_admin_access),
) -> dict:
    with closing(get_connection()) as connection:
        total = connection.execute(
            "SELECT COUNT(*) FROM dlp_policy_audit"
        ).fetchone()[0]
        rows = connection.execute(
            """
            SELECT * FROM dlp_policy_audit
            ORDER BY occurred_at DESC, audit_id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
    return {
        "items": [serialize_policy_audit(row) for row in rows],
        "count": len(rows),
        "total": total,
    }


@app.get("/api/v1/ingest-conflicts")
def list_ingest_conflicts(
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _: str = Depends(verify_policy_admin_access),
) -> dict:
    with closing(get_connection()) as connection:
        total = connection.execute(
            "SELECT COUNT(*) FROM dlp_ingest_conflicts"
        ).fetchone()[0]
        rows = connection.execute(
            """
            SELECT * FROM dlp_ingest_conflicts
            ORDER BY occurred_at DESC, conflict_id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
    return {
        "items": [dict(row) for row in rows],
        "count": len(rows),
        "total": total,
    }


@app.get(
    "/api/v1/dashboard/summary",
    dependencies=[Depends(verify_dashboard_viewer)],
)
def dashboard_summary(days: int = Query(default=7, ge=1, le=30)) -> dict:
    today = datetime.now(timezone.utc).date()
    since = datetime.combine(
        today - timedelta(days=days - 1),
        time.min,
        tzinfo=timezone.utc,
    )
    until = datetime.combine(today + timedelta(days=1), time.min, tzinfo=timezone.utc)

    with closing(get_connection()) as connection:
        rows = connection.execute(
            """
            SELECT * FROM dlp_logs
            WHERE timestamp >= ? AND timestamp < ?
            ORDER BY timestamp DESC
            """,
            (since.isoformat(), until.isoformat()),
        ).fetchall()

    logs = [serialize_log(row) for row in rows]
    total_events = len(logs)
    blocked_count = sum(1 for item in logs if item["action_taken"] == "BLOCKED")
    warned_count = sum(1 for item in logs if item["action_taken"] == "WARNED")
    allowed_count = sum(1 for item in logs if item["action_taken"] == "ALLOWED")
    successful_ai_logs = [
        item
        for item in logs
        if item["analysis_status"] == "SUCCESS" and item["ai_score"] is not None
    ]
    failed_analysis_count = sum(
        1 for item in logs if item["analysis_status"] == "FAILED"
    )
    skipped_analysis_count = sum(
        1 for item in logs if item["analysis_status"] == "SKIPPED"
    )
    attempted_analysis_count = len(successful_ai_logs) + failed_analysis_count
    average_score = round(
        sum(item["ai_score"] for item in successful_ai_logs) / len(successful_ai_logs),
        2,
    ) if successful_ai_logs else None
    analysis_failure_rate = round(
        failed_analysis_count / attempted_analysis_count,
        4,
    ) if attempted_analysis_count else 0.0

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
            or (
                item["analysis_status"] == "SUCCESS"
                and item["ai_score"] is not None
                and item["ai_score"] >= HIGH_RISK_SCORE_THRESHOLD
            )
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
            "successful_analysis_count": len(successful_ai_logs),
            "failed_analysis_count": failed_analysis_count,
            "skipped_analysis_count": skipped_analysis_count,
            "analysis_failure_rate": analysis_failure_rate,
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
                "analysis_status": item["analysis_status"],
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


def is_loopback_host(host: str) -> bool:
    normalized = host.strip().strip("[]").lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def validate_server_security(
    host: str,
    ssl_certfile: str | None,
    ssl_keyfile: str | None,
) -> None:
    if not AGENT_API_TOKEN and not AGENT_API_TOKENS:
        raise RuntimeError(
            "Set AGENT_API_TOKEN or AGENT_API_TOKENS_JSON before starting the server."
        )
    if AGENT_API_TOKEN:
        require_ascii_token("AGENT_API_TOKEN", AGENT_API_TOKEN)
    if bool(ssl_certfile) != bool(ssl_keyfile):
        raise RuntimeError("Configure both --ssl-certfile and --ssl-keyfile.")
    if is_loopback_host(host):
        return
    if not DASHBOARD_AUTH_ENABLED:
        raise RuntimeError(
            "Non-loopback binding requires dashboard viewer/admin authentication."
        )
    if not ssl_certfile:
        raise RuntimeError(
            "Non-loopback binding requires HTTPS. Configure a certificate and key, "
            "or bind this app to loopback behind an HTTPS reverse proxy."
        )
