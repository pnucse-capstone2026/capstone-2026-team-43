from __future__ import annotations

import sqlite3
from collections import Counter
from datetime import date
from pathlib import Path

from fastapi.testclient import TestClient

from backend import main as backend_main
from scripts import seed_demo_data


def test_build_demo_logs_has_expected_distribution() -> None:
    base_date = date(2026, 8, 13)
    logs = seed_demo_data.build_demo_logs(base_date)

    assert len(logs) == 12
    assert len({log["event_id"] for log in logs}) == 12
    assert logs[0]["event_id"] == "demo-seed-20260813-01"
    assert logs[-1]["timestamp"].startswith("2026-08-07T")
    assert Counter(log["action_taken"] for log in logs) == {
        "BLOCKED": 6,
        "WARNED": 3,
        "ALLOWED": 3,
    }
    assert {log["leak_channel"] for log in logs} == {
        "USB_COPY",
        "WEB_UPLOAD",
        "EMAIL_ATTACHMENT",
        "PRINT",
        "MESSENGER",
    }

    for log in logs:
        backend_main.LogCreate.model_validate(log)


def test_seed_demo_data_is_idempotent_and_restores_the_backend_path(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "seed-test.db"
    original_db_path = backend_main.DB_PATH
    base_date = date(2026, 8, 13)

    first = seed_demo_data.seed_demo_data(db_path, base_date)
    second = seed_demo_data.seed_demo_data(db_path, base_date)

    assert backend_main.DB_PATH == original_db_path
    assert first["inserted"] == 12
    assert first["skipped"] == 0
    assert second["inserted"] == 0
    assert second["skipped"] == 12

    with sqlite3.connect(db_path) as connection:
        log_count = connection.execute("SELECT COUNT(*) FROM dlp_logs").fetchone()[0]
        policy_count = connection.execute("SELECT COUNT(*) FROM dlp_policies").fetchone()[0]
        action_counts = dict(
            connection.execute(
                "SELECT action_taken, COUNT(*) FROM dlp_logs GROUP BY action_taken"
            ).fetchall()
        )

    assert log_count == 12
    assert policy_count == 2
    assert action_counts == {"ALLOWED": 3, "BLOCKED": 6, "WARNED": 3}


def test_seeded_data_populates_dashboard_summary(
    client: TestClient,
    temp_db_path: Path,
) -> None:
    result = seed_demo_data.seed_demo_data(temp_db_path)
    response = client.get("/api/v1/dashboard/summary", params={"days": 7})

    assert result["inserted"] == 12
    assert response.status_code == 200
    summary = response.json()
    assert summary["kpis"] == {
        "total_events": 12,
        "blocked_count": 6,
        "warned_count": 3,
        "allowed_count": 3,
        "average_score": 0.72,
    }
    assert sum(item["count"] for item in summary["timeline"]) == 12
    assert len(summary["channel_breakdown"]) == 5
    assert len(summary["high_risk_events"]) == 6
