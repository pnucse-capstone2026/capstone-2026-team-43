from __future__ import annotations

import json
import sqlite3
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from urllib.error import URLError

import pytest
from fastapi.testclient import TestClient

from backend import main


def make_log_payload(
    event_id: str,
    *,
    timestamp: datetime | None = None,
    department: str = "Finance",
    user_id: str = "finance_user",
    agent_id: str = "agent-test-01",
    file_name: str = "q3_revenue_forecast.xlsx",
    file_path: str = r"C:\Users\finance_user\Documents\q3_revenue_forecast.xlsx",
    leak_channel: str = "USB_COPY",
    detection_type: str = "HYBRID",
    ai_score: float = 0.91,
    action_taken: str = "BLOCKED",
) -> dict:
    return {
        "event_id": event_id,
        "agent_id": agent_id,
        "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
        "host_ip": "192.168.10.42",
        "hostname": "host-agent-test-01",
        "user_id": user_id,
        "department": department,
        "file_name": file_name,
        "file_path": file_path,
        "process_name": "explorer.exe",
        "leak_channel": leak_channel,
        "detection_type": detection_type,
        "ai_score": ai_score,
        "matched_keywords": ["confidential", "forecast"],
        "policy_id": "DLP-TEST-001",
        "action_taken": action_taken,
        "decision_reason": "Automated test decision.",
        "evidence_summary": "Automated test evidence.",
        "latency_ms": 42,
    }


def make_analyze_payload(event_id: str = "analyze-test-001") -> dict:
    return {
        "event_id": event_id,
        "channel": "web_upload",
        "user_id": "researcher",
        "matched_patterns": ["source_code", "api_key"],
        "snippet": "Confidential source_code archive includes an API key.",
        "metadata": {"dest": "external", "severity_hint": "high"},
    }


def post_log(client: TestClient, headers: dict[str, str], payload: dict) -> dict:
    response = client.post("/api/v1/logs", json=payload, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def test_startup_creates_only_the_temporary_database(
    client: TestClient,
    temp_db_path: Path,
) -> None:
    assert temp_db_path.exists()
    assert main.DB_PATH == temp_db_path

    with sqlite3.connect(temp_db_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        log_count = connection.execute("SELECT COUNT(*) FROM dlp_logs").fetchone()[0]
        policy_count = connection.execute("SELECT COUNT(*) FROM dlp_policies").fetchone()[0]

    assert {"dlp_logs", "dlp_policies"}.issubset(tables)
    assert log_count == 0
    assert policy_count == 2


def test_health_and_frontend_routes(client: TestClient) -> None:
    health = client.get("/health")

    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert health.json()["analysis_mode"] == "mock"
    assert health.json()["ai_server_url_configured"] is False

    for path in ("/dashboard", "/logs"):
        response = client.get(path)
        assert response.status_code == 200
        assert "AI 기반 Host DLP 시스템" in response.text


@pytest.mark.parametrize("token", [None, "wrong-token"])
def test_protected_endpoints_reject_invalid_agent_tokens(
    client: TestClient,
    token: str | None,
) -> None:
    headers = {"X-Agent-Token": token} if token else {}

    analyze_response = client.post(
        "/api/v1/analyze",
        json=make_analyze_payload(),
        headers=headers,
    )
    log_response = client.post(
        "/api/v1/logs",
        json=make_log_payload("unauthorized-log"),
        headers=headers,
    )

    assert analyze_response.status_code == 401
    assert log_response.status_code == 401
    assert analyze_response.json()["detail"] == "Invalid or missing agent token."
    assert log_response.json()["detail"] == "Invalid or missing agent token."


def test_mock_analysis_returns_a_normalized_decision(
    client: TestClient,
    agent_headers: dict[str, str],
) -> None:
    response = client.post(
        "/api/v1/analyze",
        json=make_analyze_payload(),
        headers=agent_headers,
    )

    assert response.status_code == 200
    result = response.json()
    assert result["event_id"] == "analyze-test-001"
    assert result["decision"] == "block"
    assert 0.85 <= result["confidence_score"] <= 1.0
    assert result["model_version"] == main.MOCK_MODEL_VERSION
    assert result["latency_ms"] >= 1
    assert "api_key" in result["evidence_summary"]


def test_log_create_detail_and_database_persistence(
    client: TestClient,
    agent_headers: dict[str, str],
    temp_db_path: Path,
) -> None:
    payload = make_log_payload("event-create-001")
    created = post_log(client, agent_headers, payload)

    assert created["duplicate"] is False
    assert created["event_id"] == payload["event_id"]

    detail_response = client.get(f"/api/v1/logs/{created['log_id']}")
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["event_id"] == payload["event_id"]
    assert detail["file_path"] == payload["file_path"]
    assert detail["matched_keywords"] == payload["matched_keywords"]
    assert detail["received_at"] is not None

    with sqlite3.connect(temp_db_path) as connection:
        stored = connection.execute(
            "SELECT event_id, action_taken, ai_score FROM dlp_logs"
        ).fetchone()

    assert stored == ("event-create-001", "BLOCKED", 0.91)


def test_duplicate_event_id_is_idempotent(
    client: TestClient,
    agent_headers: dict[str, str],
    temp_db_path: Path,
) -> None:
    payload = make_log_payload("duplicate-event-001")

    first_response = client.post("/api/v1/logs", json=payload, headers=agent_headers)
    second_response = client.post("/api/v1/logs", json=payload, headers=agent_headers)

    assert first_response.status_code == 201
    assert first_response.json()["duplicate"] is False
    assert second_response.status_code == 200
    assert second_response.json()["duplicate"] is True
    assert second_response.json()["log_id"] == first_response.json()["log_id"]

    with sqlite3.connect(temp_db_path) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM dlp_logs WHERE event_id = ?",
            (payload["event_id"],),
        ).fetchone()[0]

    assert count == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ai_score", 1.1),
        ("action_taken", "UNKNOWN"),
        ("leak_channel", "CLOUD_DRIVE"),
    ],
)
def test_log_payload_validation(
    client: TestClient,
    agent_headers: dict[str, str],
    field: str,
    value: object,
) -> None:
    payload = make_log_payload(f"invalid-{field}")
    payload[field] = value

    response = client.post("/api/v1/logs", json=payload, headers=agent_headers)

    assert response.status_code == 422


def test_log_filters_and_filter_options(
    client: TestClient,
    agent_headers: dict[str, str],
) -> None:
    now = datetime.now(timezone.utc)
    payloads = [
        make_log_payload(
            "filter-finance",
            timestamp=now - timedelta(days=1),
            department="Finance",
            user_id="finance_user",
            agent_id="agent-finance",
            file_name="quarterly_forecast.xlsx",
            leak_channel="USB_COPY",
            ai_score=0.93,
            action_taken="BLOCKED",
        ),
        make_log_payload(
            "filter-research",
            timestamp=now - timedelta(days=2),
            department="R&D",
            user_id="research_user",
            agent_id="agent-research",
            file_name="prototype_source.zip",
            file_path=r"C:\Research\prototype_source.zip",
            leak_channel="WEB_UPLOAD",
            ai_score=0.72,
            action_taken="WARNED",
        ),
        make_log_payload(
            "filter-old",
            timestamp=now - timedelta(days=20),
            department="Legal",
            user_id="legal_user",
            agent_id="agent-legal",
            file_name="old_contract.pdf",
            leak_channel="PRINT",
            ai_score=0.31,
            action_taken="ALLOWED",
        ),
    ]
    for payload in payloads:
        post_log(client, agent_headers, payload)

    combined = client.get(
        "/api/v1/logs",
        params={
            "department": "R&D",
            "user_id": "research_user",
            "agent_id": "agent-research",
            "action": "WARNED",
            "leak_channel": "WEB_UPLOAD",
            "q": "prototype_source",
            "start_date": (now - timedelta(days=3)).date().isoformat(),
            "end_date": now.date().isoformat(),
        },
    )
    assert combined.status_code == 200
    assert combined.json()["count"] == 1
    assert combined.json()["items"][0]["event_id"] == "filter-research"

    old_only = client.get("/api/v1/logs", params={"q": "old_contract"})
    assert old_only.status_code == 200
    assert old_only.json()["count"] == 1

    options = client.get("/api/v1/logs/filter-options")
    assert options.status_code == 200
    option_data = options.json()
    assert option_data["departments"] == ["Finance", "Legal", "R&D"]
    assert option_data["users"] == ["finance_user", "legal_user", "research_user"]
    assert option_data["agents"] == ["agent-finance", "agent-legal", "agent-research"]


def test_dashboard_summary_uses_only_the_requested_recent_period(
    client: TestClient,
    agent_headers: dict[str, str],
) -> None:
    now = datetime.now(timezone.utc)
    recent_payloads = [
        make_log_payload(
            "summary-blocked",
            timestamp=now,
            department="Finance",
            leak_channel="USB_COPY",
            ai_score=0.90,
            action_taken="BLOCKED",
        ),
        make_log_payload(
            "summary-warned",
            timestamp=now - timedelta(days=1),
            department="R&D",
            user_id="research_user",
            leak_channel="WEB_UPLOAD",
            ai_score=0.70,
            action_taken="WARNED",
        ),
        make_log_payload(
            "summary-allowed",
            timestamp=now - timedelta(days=2),
            department="R&D",
            user_id="research_user_2",
            leak_channel="MESSENGER",
            ai_score=0.20,
            action_taken="ALLOWED",
        ),
    ]
    for payload in recent_payloads:
        post_log(client, agent_headers, payload)
    post_log(
        client,
        agent_headers,
        make_log_payload(
            "summary-outside-period",
            timestamp=now - timedelta(days=20),
            department="Old Department",
            ai_score=0.99,
            action_taken="BLOCKED",
        ),
    )

    response = client.get("/api/v1/dashboard/summary", params={"days": 7})

    assert response.status_code == 200
    summary = response.json()
    assert summary["period_days"] == 7
    assert summary["kpis"] == {
        "total_events": 3,
        "blocked_count": 1,
        "warned_count": 1,
        "allowed_count": 1,
        "average_score": 0.6,
    }
    assert sum(item["count"] for item in summary["timeline"]) == 3
    assert len(summary["timeline"]) == 7
    assert summary["top_departments"][0] == {"department": "R&D", "count": 2}
    assert {item["channel"] for item in summary["channel_breakdown"]} == {
        "USB_COPY",
        "WEB_UPLOAD",
        "MESSENGER",
    }
    assert [item["event_id"] for item in summary["high_risk_events"]] == [
        "summary-blocked"
    ]


def test_dashboard_summary_includes_the_first_day_from_midnight(
    client: TestClient,
    agent_headers: dict[str, str],
) -> None:
    first_day = datetime.combine(
        datetime.now(timezone.utc).date() - timedelta(days=6),
        time.min,
        tzinfo=timezone.utc,
    )
    post_log(
        client,
        agent_headers,
        make_log_payload("summary-first-day", timestamp=first_day),
    )

    response = client.get("/api/v1/dashboard/summary", params={"days": 7})

    assert response.status_code == 200
    assert response.json()["kpis"]["total_events"] == 1
    assert response.json()["timeline"][0] == {
        "date": first_day.date().isoformat(),
        "count": 1,
    }


def test_policy_create_and_threshold_validation(
    client: TestClient,
    temp_db_path: Path,
) -> None:
    initial = client.get("/api/v1/policies")
    assert initial.status_code == 200
    assert initial.json()["count"] == 2

    valid_response = client.post(
        "/api/v1/policies",
        json={
            "policy_name": "테스트 정책",
            "description": "자동화 테스트용 정책",
            "ai_threshold": 0.6,
            "block_threshold": 0.8,
            "is_active": True,
            "exception_extensions": [".tmp"],
        },
    )
    invalid_response = client.post(
        "/api/v1/policies",
        json={
            "policy_name": "잘못된 정책",
            "ai_threshold": 0.9,
            "block_threshold": 0.8,
        },
    )

    assert valid_response.status_code == 201
    assert invalid_response.status_code == 400
    assert "greater than or equal" in invalid_response.json()["detail"]

    with sqlite3.connect(temp_db_path) as connection:
        count = connection.execute("SELECT COUNT(*) FROM dlp_policies").fetchone()[0]
    assert count == 3


class FakeExternalResponse:
    def __init__(self, payload: object) -> None:
        self.body = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> FakeExternalResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self.body


def test_external_ai_response_is_forwarded_and_normalized(
    client: TestClient,
    agent_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_urlopen(request: object, timeout: float) -> FakeExternalResponse:
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeExternalResponse(
            {
                "decision": "REVIEW",
                "score": 73,
                "model_version": "team-ai-v1",
                "latency_ms": "125",
                "reason": "External model detected sensitive context.",
            }
        )

    monkeypatch.setattr(main, "AI_SERVER_URL", "http://team-ai.local")
    monkeypatch.setattr(main, "AI_SERVER_TOKEN", "team-ai-token")
    monkeypatch.setattr(main, "AI_SERVER_TIMEOUT_SECONDS", 2.5)
    monkeypatch.setattr(main, "urlopen", fake_urlopen)

    response = client.post(
        "/api/v1/analyze",
        json=make_analyze_payload("external-ai-001"),
        headers=agent_headers,
    )

    assert response.status_code == 200
    assert response.json() == {
        "event_id": "external-ai-001",
        "decision": "review",
        "confidence_score": 0.73,
        "model_version": "team-ai-v1",
        "latency_ms": 125,
        "evidence_summary": "External model detected sensitive context.",
    }
    request = captured["request"]
    assert request.full_url == "http://team-ai.local/api/v1/analyze"
    assert request.get_header("Authorization") == "Bearer team-ai-token"
    assert captured["timeout"] == 2.5

    health = client.get("/health").json()
    assert health["analysis_mode"] == "external"
    assert health["ai_server_url_configured"] is True


@pytest.mark.parametrize(
    "external_payload",
    [
        [],
        {"decision": "unknown", "confidence_score": 0.5},
        {"decision": "allow", "confidence_score": 101},
        {"decision": "block", "confidence_score": "not-a-number"},
    ],
)
def test_invalid_external_ai_responses_return_502(
    client: TestClient,
    agent_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    external_payload: object,
) -> None:
    monkeypatch.setattr(main, "AI_SERVER_URL", "http://team-ai.local/api/v1")
    monkeypatch.setattr(
        main,
        "urlopen",
        lambda request, timeout: FakeExternalResponse(external_payload),
    )

    response = client.post(
        "/api/v1/analyze",
        json=make_analyze_payload(),
        headers=agent_headers,
    )

    assert response.status_code == 502


def test_external_ai_connection_failure_returns_502(
    client: TestClient,
    agent_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_connection_error(request: object, timeout: float) -> None:
        raise URLError("connection refused")

    monkeypatch.setattr(main, "AI_SERVER_URL", "http://team-ai.local/analyze")
    monkeypatch.setattr(main, "urlopen", raise_connection_error)

    response = client.post(
        "/api/v1/analyze",
        json=make_analyze_payload(),
        headers=agent_headers,
    )

    assert response.status_code == 502
    assert "Could not connect to AI server" in response.json()["detail"]


def test_unknown_log_returns_404(client: TestClient) -> None:
    response = client.get("/api/v1/logs/99999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Log not found."
