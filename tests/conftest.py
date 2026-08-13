from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import main


TEST_AGENT_TOKEN = "test-agent-token"


@pytest.fixture
def temp_db_path(tmp_path: Path) -> Path:
    return tmp_path / "dlp-dashboard-test.db"


@pytest.fixture
def client(temp_db_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setattr(main, "DB_PATH", temp_db_path)
    monkeypatch.setattr(main, "AGENT_API_TOKEN", TEST_AGENT_TOKEN)
    monkeypatch.setattr(main, "AI_SERVER_URL", "")
    monkeypatch.setattr(main, "AI_SERVER_TOKEN", "")
    monkeypatch.setattr(main, "AI_SERVER_TIMEOUT_SECONDS", 1.0)

    with TestClient(main.app) as test_client:
        yield test_client


@pytest.fixture
def agent_headers() -> dict[str, str]:
    return {"X-Agent-Token": TEST_AGENT_TOKEN}
