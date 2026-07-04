"""LocalEventStore / EventLogger 단위 테스트."""

import json
import tempfile
from pathlib import Path

import pytest

from core_comm.event_logger import EventLogger
from core_comm.local_store import LocalEventStore

_HITS = [
    {"id": "rrn", "name": "주민등록번호", "severity": "critical"},
]


@pytest.fixture
def tmp_store() -> LocalEventStore:
    with tempfile.TemporaryDirectory() as d:
        yield LocalEventStore(log_dir=Path(d), max_bytes=1024 * 1024)


@pytest.fixture
def tmp_logger(tmp_store: LocalEventStore) -> EventLogger:
    return EventLogger(store=tmp_store, dashboard_url=None, send_immediately=False)


# ── LocalEventStore ───────────────────────────────────────────────────────────

class TestLocalEventStore:
    def test_creates_log_file_on_first_write(self, tmp_store: LocalEventStore) -> None:
        tmp_store.write("clipboard", "blocked", "slack.exe", _HITS)
        assert tmp_store._active_path.exists()

    def test_record_is_valid_json(self, tmp_store: LocalEventStore) -> None:
        tmp_store.write("clipboard", "blocked", "slack.exe", _HITS, text="900101-1234567")
        lines = tmp_store._active_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["channel"] == "clipboard"
        assert record["action"] == "blocked"
        assert record["process"] == "slack.exe"

    def test_text_preview_truncated(self, tmp_store: LocalEventStore) -> None:
        long_text = "a" * 500
        tmp_store.write("clipboard", "blocked", "chrome.exe", _HITS, text=long_text)
        record = json.loads(tmp_store._active_path.read_text(encoding="utf-8").strip())
        assert len(record["text_preview"]) <= tmp_store._preview_len

    def test_sha256_stored(self, tmp_store: LocalEventStore) -> None:
        tmp_store.write("clipboard", "blocked", "chrome.exe", _HITS, text="hello")
        record = json.loads(tmp_store._active_path.read_text(encoding="utf-8").strip())
        assert len(record["text_sha256"]) == 64

    def test_no_text_fields_when_text_none(self, tmp_store: LocalEventStore) -> None:
        tmp_store.write("clipboard", "blocked", "chrome.exe", _HITS)
        record = json.loads(tmp_store._active_path.read_text(encoding="utf-8").strip())
        assert "text_preview" not in record
        assert "text_sha256" not in record

    def test_multiple_writes_append(self, tmp_store: LocalEventStore) -> None:
        for _ in range(5):
            tmp_store.write("clipboard", "blocked", "slack.exe", _HITS)
        lines = tmp_store._active_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 5

    def test_rotation_on_size_exceeded(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            store = LocalEventStore(log_dir=Path(d), max_bytes=500)
            big_extra = {"data": "x" * 300}
            store.write("clipboard", "blocked", "a.exe", _HITS, extra=big_extra)
            store.write("clipboard", "blocked", "b.exe", _HITS, extra=big_extra)
            rotated = list(store._log_dir.glob("events.*.jsonl"))
            assert len(rotated) >= 1

    def test_hostname_present(self, tmp_store: LocalEventStore) -> None:
        tmp_store.write("clipboard", "blocked", "slack.exe", _HITS)
        record = json.loads(tmp_store._active_path.read_text(encoding="utf-8").strip())
        assert record["hostname"]

    def test_hits_serialized(self, tmp_store: LocalEventStore) -> None:
        tmp_store.write("clipboard", "blocked", "slack.exe", _HITS)
        record = json.loads(tmp_store._active_path.read_text(encoding="utf-8").strip())
        assert record["hits"][0]["id"] == "rrn"
        assert record["hits"][0]["severity"] == "critical"


# ── EventLogger ───────────────────────────────────────────────────────────────

class TestEventLogger:
    def test_log_delegates_to_store(self, tmp_logger: EventLogger, tmp_store: LocalEventStore) -> None:
        tmp_logger.log("clipboard", "blocked", "discord.exe", _HITS, text="비밀")
        assert tmp_store._active_path.exists()
        record = json.loads(tmp_store._active_path.read_text(encoding="utf-8").strip())
        assert record["process"] == "discord.exe"

    def test_flush_returns_zero_when_no_url(self, tmp_logger: EventLogger) -> None:
        tmp_logger.log("clipboard", "blocked", "a.exe", _HITS)
        assert tmp_logger.flush_to_server() == 0
