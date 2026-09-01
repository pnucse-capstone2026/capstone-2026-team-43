from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

from core_comm.api_client import ApiClient
from core_comm.event_logger import EventLogger
from core_comm.local_store import LocalEventStore


def _logger(tmp_path, **kwargs):
    return EventLogger(LocalEventStore(tmp_path), agent_id="agent-01", **kwargs)


def _payload(logger, extra):
    return logger._build_log_payload("http", "blocked", "chrome.exe", [], None, extra)


def test_dashboard_payload_separates_ai_outcomes(tmp_path):
    logger = _logger(tmp_path)

    success = _payload(logger, {"detection_type": "HYBRID", "ai_score": 0.42})
    failed = _payload(
        logger,
        {"detection_type": "HYBRID", "ai_score": 1.0, "analysis_failed": True},
    )
    skipped = _payload(logger, {"detection_type": "RULE_BASED", "ai_score": 0.95})

    assert (success["analysis_status"], success["ai_score"]) == ("SUCCESS", 0.42)
    assert (failed["analysis_status"], failed["ai_score"]) == ("FAILED", None)
    assert (skipped["analysis_status"], skipped["ai_score"]) == ("SKIPPED", None)


def test_dashboard_payload_rejects_score_scale_guessing(tmp_path):
    with pytest.raises(ValueError):
        _payload(_logger(tmp_path), {"detection_type": "HYBRID", "ai_score": 1.0001})


def test_dashboard_request_identifies_agent(tmp_path, monkeypatch):
    post = Mock(return_value=Mock(status_code=201, raise_for_status=Mock()))
    monkeypatch.setattr("core_comm.event_logger.requests.post", post)
    logger = _logger(
        tmp_path,
        dashboard_url="https://dashboard.test",
        dashboard_token="agent-token",
    )

    logger._post({"event_id": "event-01"})

    assert post.call_args.kwargs["headers"]["X-Agent-ID"] == "agent-01"


def test_ai_transport_failure_is_explicit(monkeypatch):
    monkeypatch.setattr(
        "core_comm.api_client.requests.post",
        Mock(side_effect=requests.Timeout),
    )
    payload = SimpleNamespace(request_id="event-01", to_dict=lambda: {})

    result = ApiClient("https://ai.test").analyze(payload)

    assert result.analysis_failed is True
