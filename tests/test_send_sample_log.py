from __future__ import annotations

import sys

from scripts import send_sample_log


def test_all_scenarios_are_sent_in_presentation_order(
    monkeypatch,
) -> None:
    sent_payloads = []
    intervals = []

    def fake_post_json(api_url: str, payload: dict, token: str | None = None) -> dict:
        sent_payloads.append(payload)
        return {"event_id": payload["event_id"], "duplicate": False}

    monkeypatch.setattr(send_sample_log, "post_json", fake_post_json)
    monkeypatch.setattr(send_sample_log, "sleep", intervals.append)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "send_sample_log.py",
            "--scenario",
            "all",
            "--event-id",
            "presentation-test",
            "--interval",
            "0.25",
        ],
    )

    assert send_sample_log.expand_scenarios("usb_copy", 2) == ["usb_copy", "usb_copy"]
    assert send_sample_log.main() == 0
    assert [payload["leak_channel"] for payload in sent_payloads] == [
        send_sample_log.SCENARIOS[scenario]["leak_channel"]
        for scenario in send_sample_log.SCENARIO_ORDER
    ]
    assert [payload["event_id"] for payload in sent_payloads] == [
        "presentation-test",
        *[f"presentation-test-{index}" for index in range(2, 8)],
    ]
    assert intervals == [0.25] * 6


def test_analyzed_fixture_keeps_non_host_provenance() -> None:
    payload = send_sample_log.build_sample_payload(
        "usb_copy",
        sequence=1,
        agent_id="fixture-test",
    )

    assert payload["model_version"] == send_sample_log.FIXTURE_MODEL_VERSION
    assert payload["decision_reason"].startswith("[DEMO FIXTURE - NOT LIVE]")

    analyzed = send_sample_log.apply_analysis_result(
        payload,
        {
            "decision": "review",
            "confidence_score": 0.73,
            "model_version": "team-ai-v1",
            "latency_ms": 125,
            "reason": "External model requested review.",
            "evidence_summary": "Sensitive context was detected.",
        },
    )

    assert analyzed["action_taken"] == "WARNED"
    assert analyzed["model_version"] == "team-ai-v1"
    assert analyzed["decision_reason"] == (
        "[WEB FIXTURE - NOT HOST LIVE] External model requested review."
    )
    assert analyzed["evidence_summary"] == (
        "[WEB FIXTURE - NOT HOST LIVE] Sensitive context was detected."
    )


def test_analysis_reason_is_used_when_evidence_summary_is_absent() -> None:
    payload = send_sample_log.build_sample_payload(
        "clipboard",
        sequence=1,
        agent_id="direct-ai-test",
    )

    analyzed = send_sample_log.apply_analysis_result(
        payload,
        {
            "decision": "block",
            "confidence_score": 0.91,
            "model_version": "koelectra-dlp-v7",
            "latency_ms": 51,
            "reason": "Direct AI response reason.",
        },
    )

    assert analyzed["evidence_summary"] == (
        "[WEB FIXTURE - NOT HOST LIVE] Direct AI response reason."
    )
