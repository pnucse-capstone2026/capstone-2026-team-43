from __future__ import annotations

import inspect
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from threading import Event
from urllib.error import URLError

import pytest
from pydantic import ValidationError
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
    model_version: str | None = "koelectra-dlp-v7",
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
        "model_version": model_version,
        "matched_keywords": ["confidential", "forecast"],
        "policy_id": "DLP-TEST-001",
        "action_taken": action_taken,
        "decision_reason": "Automated test decision.",
        "evidence_summary": "Automated test evidence.",
        "latency_ms": 42,
    }


def make_analyze_payload(
    event_id: str = "analyze-test-001",
    *,
    channel: str = "web_upload",
) -> dict:
    return {
        "event_id": event_id,
        "channel": channel,
        "user_id": "researcher",
        "matched_patterns": ["source_code", "api_key"],
        "snippet": "Confidential source_code archive includes an API key.",
        "metadata": {"dest": "external", "severity_hint": "high"},
    }


def post_log(client: TestClient, headers: dict[str, str], payload: dict) -> dict:
    response = client.post("/api/v1/logs", json=payload, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def assert_host_response_contract(result: dict, event_id: str) -> None:
    """Mirror the strict fields consumed by Host Agent's ResponseParser."""
    assert result["event_id"] == event_id
    assert result["decision"] in {"allow", "review", "block"}
    assert isinstance(result["confidence_score"], (int, float))
    assert not isinstance(result["confidence_score"], bool)
    assert 0.0 <= result["confidence_score"] <= 1.0
    assert isinstance(result["model_version"], str)
    assert result["model_version"].strip()
    assert isinstance(result["latency_ms"], (int, float))
    assert not isinstance(result["latency_ms"], bool)
    assert result["latency_ms"] >= 0
    assert isinstance(result["reason"], str)


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
        database_epoch = connection.execute(
            """
            SELECT metadata_value
            FROM dlp_metadata
            WHERE metadata_key = 'database_epoch'
            """
        ).fetchone()[0]

    assert {"dlp_logs", "dlp_policies", "dlp_metadata"}.issubset(tables)
    assert log_count == 0
    assert policy_count == 2
    assert database_epoch


def test_log_schema_migration_adds_model_version_to_existing_database() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.execute(
            """
            CREATE TABLE dlp_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT,
                timestamp TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO dlp_logs (event_id, timestamp) VALUES (?, ?)",
            ("legacy-event", "2026-08-13T00:00:00+00:00"),
        )

        main.ensure_log_schema(connection.cursor())
        main.ensure_log_schema(connection.cursor())

        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(dlp_logs)").fetchall()
        }
        assert "model_version" in columns
        legacy_row = connection.execute(
            "SELECT event_id, model_version FROM dlp_logs"
        ).fetchone()
        assert tuple(legacy_row) == ("legacy-event", None)
    finally:
        connection.close()


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
        assert 'value="CLIPBOARD"' in response.text
        assert 'value="CLOUD_DRIVE"' in response.text
        assert 'id="analysisMode"' in response.text
        assert "Web 분석" in response.text
        assert "AI 모델 버전" in response.text


def test_agent_connection_check_verifies_token_without_creating_log(
    client: TestClient,
) -> None:
    rejected = client.get("/api/v1/agent-check")
    wrong_token = client.get(
        "/api/v1/agent-check",
        headers={"X-Agent-Token": "wrong-agent-token"},
    )
    accepted = client.get(
        "/api/v1/agent-check",
        headers={"X-Agent-Token": main.AGENT_API_TOKEN},
    )

    assert rejected.status_code == 401
    assert wrong_token.status_code == 401
    assert accepted.status_code == 200
    assert accepted.json() == {"status": "ok", "agent_token": "accepted"}
    assert client.get("/api/v1/logs").json()["count"] == 0


def test_frontend_realtime_risk_alert_contract(client: TestClient) -> None:
    html = client.get("/dashboard").text

    for marker in (
        'id="realtimeRiskAlert"',
        'aria-live="assertive"',
        'id="alertSoundToggle"',
        "const RISK_POLL_INTERVAL_MS = 2000",
        "function pollRealtimeRiskAlerts",
        "async function refreshDashboardData()",
        "function createDashboardChart",
        'typeof window.Chart !== "function"',
        "if (timelineChart) {",
        "if (channelChart) {",
        'fetch(`/api/v1/alerts?',
        'query.set("cursor_epoch", riskAlertCursorEpoch)',
        "startRiskPolling();\n        loadDashboard();",
        "result.cursor_reset === true || cursorEpochChanged",
        "const previousCursor = riskAlertCursor",
        "const cursorAdvanced = previousCursor !== null",
        "if (cursorAdvanced) {",
        "refreshDashboardData().catch",
        'setText("analysisMode", String(health.analysis_mode || "unknown").toUpperCase())',
    ):
        assert marker in html

    assert "setInterval(loadDashboard" not in html
    assert html.index("if (cursorAdvanced) {") < html.index("if (items.length) {")
    assert html.index("alertSoundEnabled = shouldEnable") > html.index("await alertAudioContext.resume()")
    assert 'setText("alertSoundStatus", "사용 불가")' in html
    assert 'console.warn("경고음을 활성화하지 못했습니다.", error)' in html


def test_same_origin_dashboard_does_not_enable_wildcard_cors(client: TestClient) -> None:
    response = client.options(
        "/api/v1/logs",
        headers={
            "Origin": "https://untrusted.example",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert "access-control-allow-origin" not in response.headers


def test_frontend_pins_chart_dependency_with_integrity(client: TestClient) -> None:
    html = client.get("/dashboard").text

    assert "chart.js@4.5.1/dist/chart.umd.min.js" in html
    assert (
        'integrity="sha384-jb8JQMbMoBUzgWatfe6COACi2ljcDdZQ2OxczGA3bGNeWe+'
        '6DChMTBJemed7ZnvJ"'
    ) in html
    assert "crossorigin=\"anonymous\"" in html


@pytest.mark.parametrize(
    ("endpoint", "payload", "field"),
    [
        (
            "/api/v1/logs",
            {**make_log_payload("too-many-keywords"), "matched_keywords": ["k"] * 101},
            "matched_keywords",
        ),
        (
            "/api/v1/analyze",
            {**make_analyze_payload("too-many-patterns"), "matched_patterns": ["p"] * 101},
            "matched_patterns",
        ),
        (
            "/api/v1/analyze",
            {**make_analyze_payload("too-much-metadata"), "metadata": {f"k{i}": i for i in range(51)}},
            "metadata",
        ),
        (
            "/api/v1/policies",
            {
                "policy_name": "too-many-extensions",
                "ai_threshold": 0.4,
                "block_threshold": 0.8,
                "exception_extensions": [f"x{i}" for i in range(51)],
            },
            "exception_extensions",
        ),
    ],
)
def test_agent_payload_collections_have_size_limits(
    client: TestClient,
    agent_headers: dict[str, str],
    endpoint: str,
    payload: dict,
    field: str,
) -> None:
    response = client.post(endpoint, json=payload, headers=agent_headers)

    assert response.status_code == 422
    assert any(item["loc"][-1] == field for item in response.json()["detail"])


@pytest.mark.parametrize(
    ("endpoint", "payload", "field"),
    [
        (
            "/api/v1/logs",
            {**make_log_payload("long-keyword"), "matched_keywords": ["k" * 101]},
            "matched_keywords",
        ),
        (
            "/api/v1/analyze",
            {**make_analyze_payload("long-pattern"), "matched_patterns": ["p" * 101]},
            "matched_patterns",
        ),
        (
            "/api/v1/analyze",
            {**make_analyze_payload("long-metadata"), "metadata": {"detail": "v" * 501}},
            "metadata",
        ),
        (
            "/api/v1/analyze",
            {**make_analyze_payload("long-metadata-key"), "metadata": {"k" * 101: "value"}},
            "metadata",
        ),
        (
            "/api/v1/policies",
            {
                "policy_name": "long-extension",
                "ai_threshold": 0.4,
                "block_threshold": 0.8,
                "exception_extensions": ["e" * 21],
            },
            "exception_extensions",
        ),
    ],
)
def test_agent_payload_collection_items_have_length_limits(
    client: TestClient,
    agent_headers: dict[str, str],
    endpoint: str,
    payload: dict,
    field: str,
) -> None:
    response = client.post(endpoint, json=payload, headers=agent_headers)

    assert response.status_code == 422
    assert any(field in item["loc"] for item in response.json()["detail"])


@pytest.mark.parametrize(
    ("endpoint", "payload"),
    [
        ("/api/v1/logs", {**make_log_payload("extra-log-field"), "typo_field": True}),
        ("/api/v1/analyze", {**make_analyze_payload("extra-analysis-field"), "typo_field": True}),
        (
            "/api/v1/policies",
            {
                "policy_name": "extra-policy-field",
                "ai_threshold": 0.4,
                "block_threshold": 0.8,
                "typo_field": True,
            },
        ),
    ],
)
def test_write_contracts_reject_unknown_fields(
    client: TestClient,
    agent_headers: dict[str, str],
    endpoint: str,
    payload: dict,
) -> None:
    response = client.post(endpoint, json=payload, headers=agent_headers)

    assert response.status_code == 422
    assert any(item["loc"][-1] == "typo_field" for item in response.json()["detail"])


def test_analysis_metadata_rejects_non_finite_numbers() -> None:
    with pytest.raises(ValidationError):
        main.AnalyzeRequest(
            **{
                **make_analyze_payload("non-finite-metadata"),
                "metadata": {"score": float("nan")},
            }
        )


@pytest.mark.parametrize("token", ["short", "가" * 32])
def test_configured_tokens_must_be_long_ascii_values(token: str) -> None:
    with pytest.raises(RuntimeError):
        main.require_ascii_token("TEST_TOKEN", token)

    assert main.require_ascii_token("TEST_TOKEN", "a" * 32) is None


def test_external_analysis_endpoint_uses_fastapi_worker_thread() -> None:
    assert inspect.iscoroutinefunction(main.analyze_event) is False


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
    assert "api_key" in result["reason"]
    assert "api_key" in result["evidence_summary"]
    assert result["reason"] == result["evidence_summary"]
    assert_host_response_contract(result, "analyze-test-001")


@pytest.mark.parametrize("channel", ["smtp", "web_mail", "file_guard"])
def test_host_agent_channels_are_accepted_with_reason(
    client: TestClient,
    agent_headers: dict[str, str],
    channel: str,
) -> None:
    event_id = f"host-channel-{channel}"
    response = client.post(
        "/api/v1/analyze",
        json=make_analyze_payload(event_id, channel=channel),
        headers=agent_headers,
    )

    assert response.status_code == 200
    result = response.json()
    assert result["reason"]
    assert result["evidence_summary"] == result["reason"]
    assert f"channel:{channel}" in result["reason"]
    assert_host_response_contract(result, event_id)


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
    assert detail["model_version"] == payload["model_version"]
    assert detail["received_at"] is not None

    with sqlite3.connect(temp_db_path) as connection:
        stored = connection.execute(
            "SELECT event_id, action_taken, ai_score, model_version FROM dlp_logs"
        ).fetchone()

    assert stored == ("event-create-001", "BLOCKED", 0.91, "koelectra-dlp-v7")


def test_log_model_version_is_optional(
    client: TestClient,
    agent_headers: dict[str, str],
) -> None:
    payload = make_log_payload("event-without-model")
    payload.pop("model_version")

    created = post_log(client, agent_headers, payload)
    detail = client.get(f"/api/v1/logs/{created['log_id']}")

    assert detail.status_code == 200
    assert detail.json()["model_version"] is None


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


def test_realtime_alerts_use_a_cursor_without_replaying_history(
    client: TestClient,
    agent_headers: dict[str, str],
) -> None:
    historical = post_log(
        client,
        agent_headers,
        make_log_payload("alert-historical", ai_score=0.95, action_taken="BLOCKED"),
    )

    baseline = client.get("/api/v1/alerts")
    assert baseline.status_code == 200
    baseline_result = baseline.json()
    assert baseline_result["items"] == []
    assert baseline_result["count"] == 0
    assert baseline_result["next_cursor"] == historical["log_id"]
    assert baseline_result["cursor_epoch"]
    assert baseline_result["cursor_reset"] is False

    post_log(
        client,
        agent_headers,
        make_log_payload("alert-low-risk", ai_score=0.40, action_taken="ALLOWED"),
    )
    blocked = post_log(
        client,
        agent_headers,
        make_log_payload(
            "alert-usb-blocked",
            leak_channel="USB_COPY",
            ai_score=0.60,
            action_taken="BLOCKED",
        ),
    )
    scored = post_log(
        client,
        agent_headers,
        make_log_payload(
            "alert-high-score",
            leak_channel="CLOUD_DRIVE",
            ai_score=0.90,
            action_taken="WARNED",
        ),
    )
    latest_low_risk = post_log(
        client,
        agent_headers,
        make_log_payload("alert-latest-low", ai_score=0.20, action_taken="WARNED"),
    )

    response = client.get(
        "/api/v1/alerts",
        params={
            "after_log_id": historical["log_id"],
            "cursor_epoch": baseline_result["cursor_epoch"],
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["count"] == 2
    assert result["next_cursor"] == latest_low_risk["log_id"]
    assert result["cursor_epoch"] == baseline_result["cursor_epoch"]
    assert [item["log_id"] for item in result["items"]] == [
        blocked["log_id"],
        scored["log_id"],
    ]
    assert result["items"][0]["leak_channel"] == "USB_COPY"
    assert result["items"][0]["action_taken"] == "BLOCKED"

    empty = client.get(
        "/api/v1/alerts",
        params={
            "after_log_id": result["next_cursor"],
            "cursor_epoch": result["cursor_epoch"],
        },
    )
    assert empty.status_code == 200
    assert empty.json()["items"] == []
    assert empty.json()["next_cursor"] == latest_low_risk["log_id"]
    assert empty.json()["cursor_reset"] is False


def test_realtime_alert_cursor_recovers_after_database_reset(
    client: TestClient,
    agent_headers: dict[str, str],
    temp_db_path: Path,
) -> None:
    previous = post_log(
        client,
        agent_headers,
        make_log_payload("alert-before-reset", action_taken="BLOCKED"),
    )
    previous_baseline = client.get("/api/v1/alerts").json()

    temp_db_path.unlink()
    main.init_db()

    blocked = post_log(
        client,
        agent_headers,
        make_log_payload(
            "alert-reset-usb-blocked",
            ai_score=0.60,
            action_taken="BLOCKED",
        ),
    )
    scored = post_log(
        client,
        agent_headers,
        make_log_payload(
            "alert-reset-high-score",
            ai_score=0.90,
            action_taken="WARNED",
        ),
    )
    latest_low_risk = post_log(
        client,
        agent_headers,
        make_log_payload(
            "alert-reset-low-risk",
            ai_score=0.20,
            action_taken="ALLOWED",
        ),
    )
    assert blocked["log_id"] == previous["log_id"]

    reset = client.get(
        "/api/v1/alerts",
        params={
            "after_log_id": previous["log_id"],
            "cursor_epoch": previous_baseline["cursor_epoch"],
        },
    )

    assert reset.status_code == 200
    reset_result = reset.json()
    assert [item["log_id"] for item in reset_result["items"]] == [
        blocked["log_id"],
        scored["log_id"],
    ]
    assert latest_low_risk["log_id"] not in {
        item["log_id"] for item in reset_result["items"]
    }
    assert reset_result["next_cursor"] == latest_low_risk["log_id"]
    assert reset_result["cursor_epoch"] != previous_baseline["cursor_epoch"]
    assert reset_result["cursor_reset"] is True

    caught_up = client.get(
        "/api/v1/alerts",
        params={
            "after_log_id": reset_result["next_cursor"],
            "cursor_epoch": reset_result["cursor_epoch"],
        },
    ).json()

    assert caught_up["items"] == []
    assert caught_up["next_cursor"] == latest_low_risk["log_id"]
    assert caught_up["cursor_epoch"] == reset_result["cursor_epoch"]
    assert caught_up["cursor_reset"] is False


def test_realtime_alert_cursor_paginates_without_skipping(
    client: TestClient,
    agent_headers: dict[str, str],
) -> None:
    baseline = client.get("/api/v1/alerts").json()
    created = [
        post_log(
            client,
            agent_headers,
            make_log_payload(f"alert-page-{index}", action_taken="BLOCKED"),
        )
        for index in range(3)
    ]

    first = client.get(
        "/api/v1/alerts",
        params={
            "after_log_id": baseline["next_cursor"],
            "cursor_epoch": baseline["cursor_epoch"],
            "limit": 2,
        },
    ).json()
    second = client.get(
        "/api/v1/alerts",
        params={
            "after_log_id": first["next_cursor"],
            "cursor_epoch": first["cursor_epoch"],
            "limit": 2,
        },
    ).json()

    assert [item["log_id"] for item in first["items"]] == [
        created[0]["log_id"],
        created[1]["log_id"],
    ]
    assert first["next_cursor"] == created[1]["log_id"]
    assert [item["log_id"] for item in second["items"]] == [created[2]["log_id"]]
    assert second["next_cursor"] == created[2]["log_id"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ai_score", 1.1),
        ("action_taken", "UNKNOWN"),
        ("leak_channel", "UNKNOWN_CHANNEL"),
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


@pytest.mark.parametrize("leak_channel", ["CLIPBOARD", "CLOUD_DRIVE"])
def test_log_accepts_integration_channels(
    client: TestClient,
    agent_headers: dict[str, str],
    leak_channel: str,
) -> None:
    payload = make_log_payload(
        f"integration-{leak_channel.lower()}",
        leak_channel=leak_channel,
    )

    created = post_log(client, agent_headers, payload)
    detail = client.get(f"/api/v1/logs/{created['log_id']}")

    assert detail.status_code == 200
    assert detail.json()["leak_channel"] == leak_channel
    assert detail.json()["model_version"] == "koelectra-dlp-v7"

    filtered = client.get("/api/v1/logs", params={"leak_channel": leak_channel})
    assert filtered.status_code == 200
    assert filtered.json()["count"] == 1
    assert filtered.json()["items"][0]["event_id"] == payload["event_id"]


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
    assert option_data["leak_channels"] == main.LEAK_CHANNELS


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
    agent_headers: dict[str, str],
    temp_db_path: Path,
) -> None:
    initial = client.get("/api/v1/policies")
    assert initial.status_code == 200
    assert initial.json()["count"] == 2

    valid_response = client.post(
        "/api/v1/policies",
        headers=agent_headers,
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
        headers=agent_headers,
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


@pytest.mark.parametrize("token", [None, "wrong-token"])
def test_policy_create_requires_agent_token(
    client: TestClient,
    token: str | None,
) -> None:
    headers = {"X-Agent-Token": token} if token else {}

    response = client.post(
        "/api/v1/policies",
        headers=headers,
        json={
            "policy_name": "unauthorized-policy",
            "ai_threshold": 0.6,
            "block_threshold": 0.8,
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or missing agent token."


class FakeExternalResponse:
    def __init__(self, payload: object) -> None:
        self.body = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> FakeExternalResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        return self.body if size < 0 else self.body[:size]


class FakeRawExternalResponse(FakeExternalResponse):
    def __init__(self, body: bytes) -> None:
        self.body = body


def test_slow_external_ai_does_not_block_health_requests(
    client: TestClient,
    agent_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ai_call_started = Event()
    release_ai_call = Event()

    def slow_urlopen(request: object, timeout: float) -> FakeExternalResponse:
        ai_call_started.set()
        assert release_ai_call.wait(timeout=2)
        return FakeExternalResponse(
            {
                "event_id": "slow-external-ai",
                "decision": "allow",
                "confidence_score": 0.12,
                "model_version": "koelectra-dlp-v7",
                "latency_ms": 1200,
                "reason": "normal context",
            }
        )

    monkeypatch.setattr(main, "AI_SERVER_URL", "http://slow-ai.example")
    monkeypatch.setattr(main, "urlopen", slow_urlopen)

    with ThreadPoolExecutor(max_workers=2) as executor:
        analyze_future = executor.submit(
            client.post,
            "/api/v1/analyze",
            json=make_analyze_payload("slow-external-ai"),
            headers=agent_headers,
        )
        assert ai_call_started.wait(timeout=1)
        health_future = executor.submit(client.get, "/health")
        try:
            assert health_future.result(timeout=1).status_code == 200
        finally:
            release_ai_call.set()

        assert analyze_future.result(timeout=2).status_code == 200


@pytest.mark.parametrize("channel", ["smtp", "web_mail", "file_guard"])
def test_external_ai_response_is_forwarded_and_normalized(
    client: TestClient,
    agent_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    channel: str,
) -> None:
    captured: dict[str, object] = {}
    event_id = f"external-ai-{channel}"

    def fake_urlopen(request: object, timeout: float) -> FakeExternalResponse:
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeExternalResponse(
            {
                "event_id": event_id,
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

    payload = make_analyze_payload(event_id, channel=channel)
    response = client.post(
        "/api/v1/analyze",
        json=payload,
        headers=agent_headers,
    )

    assert response.status_code == 200
    assert response.json() == {
        "event_id": event_id,
        "decision": "review",
        "confidence_score": 0.73,
        "model_version": "team-ai-v1",
        "latency_ms": 125,
        "reason": "External model detected sensitive context.",
        "evidence_summary": "External model detected sensitive context.",
    }
    request = captured["request"]
    assert request.full_url == "http://team-ai.local/api/v1/analyze"
    assert request.get_header("Authorization") == "Bearer team-ai-token"
    assert json.loads(request.data.decode("utf-8")) == payload
    assert captured["timeout"] == 2.5
    assert_host_response_contract(response.json(), event_id)

    health = client.get("/health").json()
    assert health["analysis_mode"] == "external"
    assert health["ai_server_url_configured"] is True


def test_external_evidence_summary_is_preserved_and_used_as_reason() -> None:
    payload = main.AnalyzeRequest.model_validate(make_analyze_payload("external-evidence"))

    result = main.normalize_external_analyze_response(
        payload,
        {
            "event_id": "external-evidence",
            "decision": "allow",
            "confidence_score": 0.23,
            "model_version": "team-ai-v2",
            "latency_ms": 18,
            "evidence_summary": "No high-risk context was detected.",
        },
        latency_ms=20,
    )

    assert result["reason"] == "No high-risk context was detected."
    assert result["evidence_summary"] == "No high-risk context was detected."
    assert_host_response_contract(result, "external-evidence")


@pytest.mark.parametrize(
    ("external_payload", "expected_detail"),
    [
        (
            {
                "event_id": "different-event-id",
                "decision": "allow",
                "confidence_score": 0.2,
                "model_version": "team-ai-v1",
            },
            "event_id does not match",
        ),
        (
            {
                "event_id": "analyze-test-001",
                "decision": "allow",
                "confidence_score": 0.2,
            },
            "model_version",
        ),
        (
            {
                "event_id": "analyze-test-001",
                "decision": "allow",
                "confidence_score": 0.2,
                "model_version": "   ",
            },
            "model_version",
        ),
    ],
)
def test_external_ai_identity_contract_violations_return_502(
    client: TestClient,
    agent_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    external_payload: dict,
    expected_detail: str,
) -> None:
    monkeypatch.setattr(main, "AI_SERVER_URL", "http://team-ai.local")
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
    assert expected_detail in response.json()["detail"]


@pytest.mark.parametrize(
    "external_payload",
    [
        [],
        {
            "event_id": "analyze-test-001",
            "decision": "unknown",
            "confidence_score": 0.5,
            "model_version": "team-ai-v1",
        },
        {
            "event_id": "analyze-test-001",
            "decision": "allow",
            "confidence_score": 101,
            "model_version": "team-ai-v1",
        },
        {
            "event_id": "analyze-test-001",
            "decision": "block",
            "confidence_score": "not-a-number",
            "model_version": "team-ai-v1",
        },
        {
            "event_id": "analyze-test-001",
            "decision": "block",
            "confidence_score": True,
            "model_version": "team-ai-v1",
        },
        {
            "event_id": "analyze-test-001",
            "decision": "allow",
            "confidence_score": 0.1,
            "model_version": "team-ai-v1",
            "latency_ms": 600001,
        },
        {
            "event_id": "analyze-test-001",
            "decision": "allow",
            "confidence_score": 0.1,
            "model_version": "m" * 101,
        },
        {
            "event_id": "analyze-test-001",
            "decision": "allow",
            "confidence_score": 0.1,
            "model_version": "team-ai-v1",
            "reason": "r" * 501,
        },
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


@pytest.mark.parametrize(
    ("body", "detail"),
    [
        (b"x" * (main.MAX_AI_RESPONSE_BYTES + 1), "too large"),
        (b"\xff\xfe", "not UTF-8"),
    ],
)
def test_external_ai_rejects_unbounded_or_invalid_response_bodies(
    client: TestClient,
    agent_headers: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    body: bytes,
    detail: str,
) -> None:
    monkeypatch.setattr(main, "AI_SERVER_URL", "http://team-ai.local")
    monkeypatch.setattr(
        main,
        "urlopen",
        lambda request, timeout: FakeRawExternalResponse(body),
    )

    response = client.post(
        "/api/v1/analyze",
        json=make_analyze_payload(),
        headers=agent_headers,
    )

    assert response.status_code == 502
    assert detail in response.json()["detail"]


def test_non_ascii_agent_token_is_rejected_as_unauthorized() -> None:
    with pytest.raises(main.HTTPException) as error:
        main.verify_agent_token("가" * 32)

    assert error.value.status_code == 401


@pytest.mark.parametrize("token", sorted(main.UNSAFE_TOKEN_VALUES))
def test_public_example_tokens_are_rejected(token: str) -> None:
    with pytest.raises(RuntimeError):
        main.require_ascii_token("TEST_TOKEN", token)


def test_database_routes_run_off_the_event_loop(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection_started = Event()
    release_connection = Event()
    original_get_connection = main.get_connection

    def slow_get_connection() -> sqlite3.Connection:
        connection_started.set()
        assert release_connection.wait(timeout=2)
        return original_get_connection()

    monkeypatch.setattr(main, "get_connection", slow_get_connection)
    with ThreadPoolExecutor(max_workers=2) as executor:
        logs_future = executor.submit(client.get, "/api/v1/logs")
        assert connection_started.wait(timeout=1)
        health_future = executor.submit(client.get, "/health")
        try:
            assert health_future.result(timeout=1).status_code == 200
        finally:
            release_connection.set()
        assert logs_future.result(timeout=2).status_code == 200


def test_log_timestamp_requires_an_explicit_utc_offset(
    client: TestClient,
    agent_headers: dict[str, str],
) -> None:
    payload = make_log_payload("naive-timestamp")
    payload["timestamp"] = "2026-08-29T00:30:00"

    response = client.post("/api/v1/logs", json=payload, headers=agent_headers)

    assert response.status_code == 422


def test_matched_keywords_round_trip_commas_without_corruption(
    client: TestClient,
    agent_headers: dict[str, str],
) -> None:
    payload = make_log_payload("keyword-comma")
    payload["matched_keywords"] = ["last,name", "contract"]
    created = client.post("/api/v1/logs", json=payload, headers=agent_headers)

    detail = client.get(f"/api/v1/logs/{created.json()['log_id']}")

    assert created.status_code == 201
    assert detail.json()["matched_keywords"] == ["last,name", "contract"]


def test_legacy_comma_separated_keywords_remain_readable(
    client: TestClient,
    agent_headers: dict[str, str],
    temp_db_path: Path,
) -> None:
    created = client.post(
        "/api/v1/logs",
        json=make_log_payload("legacy-keywords"),
        headers=agent_headers,
    )
    assert created.status_code == 201
    log_id = created.json()["log_id"]
    with sqlite3.connect(temp_db_path) as connection:
        connection.execute(
            "UPDATE dlp_logs SET matched_keywords = ? WHERE log_id = ?",
            ("rrn,email", log_id),
        )

    detail = client.get(f"/api/v1/logs/{log_id}")

    assert detail.status_code == 200
    assert detail.json()["matched_keywords"] == ["rrn", "email"]


def test_dashboard_summary_excludes_future_events(
    client: TestClient,
    agent_headers: dict[str, str],
) -> None:
    future = datetime.now(timezone.utc) + timedelta(days=365)
    post_log(
        client,
        agent_headers,
        make_log_payload("future-event", timestamp=future),
    )

    summary = client.get("/api/v1/dashboard/summary", params={"days": 7}).json()

    assert summary["kpis"]["total_events"] == 0
    assert sum(item["count"] for item in summary["timeline"]) == 0


def test_unknown_log_returns_404(client: TestClient) -> None:
    response = client.get("/api/v1/logs/99999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Log not found."
