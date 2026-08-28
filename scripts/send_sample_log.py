from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from time import sleep
from uuid import uuid4
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_API_URL = "http://127.0.0.1:8000/api/v1/logs"
DEFAULT_ANALYZE_URL = "http://127.0.0.1:8000/api/v1/analyze"
DEFAULT_AGENT_API_TOKEN = os.getenv("AGENT_API_TOKEN", "sentry-agent-demo-token")
FIXTURE_MODEL_VERSION = "demo-fixture-not-live"
ANALYZED_FIXTURE_MARKER = "[WEB FIXTURE - NOT HOST LIVE]"
DECISION_TO_ACTION = {
    "allow": "ALLOWED",
    "review": "WARNED",
    "block": "BLOCKED",
}

SCENARIOS = {
    "web_upload": {
        "department": "R&D",
        "user_id": "agent_test_user",
        "file_name": "prototype_source_export.zip",
        "file_path": r"C:\Users\agent_test_user\Desktop\prototype_source_export.zip",
        "process_name": "chrome.exe",
        "leak_channel": "WEB_UPLOAD",
        "detection_type": "HYBRID",
        "ai_score": 0.93,
        "matched_keywords": ["source_code", "api_key", "prototype"],
        "policy_id": "DLP-WEB-001",
        "action_taken": "BLOCKED",
        "decision_reason": "AI score exceeded block threshold after rule keyword match.",
        "evidence_summary": "Host Agent demo event for web upload integration test.",
        "latency_ms": 184,
    },
    "usb_copy": {
        "department": "Finance",
        "user_id": "finance_user",
        "file_name": "q3_revenue_forecast.xlsx",
        "file_path": r"C:\Users\finance_user\Documents\q3_revenue_forecast.xlsx",
        "process_name": "explorer.exe",
        "leak_channel": "USB_COPY",
        "detection_type": "HYBRID",
        "ai_score": 0.88,
        "matched_keywords": ["forecast", "revenue", "confidential"],
        "policy_id": "DLP-USB-002",
        "action_taken": "BLOCKED",
        "decision_reason": "USB copy attempt matched confidential finance document policy.",
        "evidence_summary": "Confidential finance forecast copied to removable storage.",
        "latency_ms": 96,
    },
    "email_attachment": {
        "department": "Sales",
        "user_id": "sales_user",
        "file_name": "enterprise_contract_terms.docx",
        "file_path": r"C:\Users\sales_user\Documents\enterprise_contract_terms.docx",
        "process_name": "OUTLOOK.EXE",
        "leak_channel": "EMAIL_ATTACHMENT",
        "detection_type": "RULE_BASED",
        "ai_score": 0.74,
        "matched_keywords": ["contract", "discount", "NDA"],
        "policy_id": "DLP-MAIL-003",
        "action_taken": "WARNED",
        "decision_reason": "Rule matched sensitive contract terms; user warning required.",
        "evidence_summary": "Sensitive contract document attached to an outbound email.",
        "latency_ms": 121,
    },
    "print": {
        "department": "HR",
        "user_id": "hr_user",
        "file_name": "promotion_candidate_list.pdf",
        "file_path": r"C:\Users\hr_user\Downloads\promotion_candidate_list.pdf",
        "process_name": "AcroRd32.exe",
        "leak_channel": "PRINT",
        "detection_type": "AI_MODEL",
        "ai_score": 0.81,
        "matched_keywords": ["candidate", "salary", "evaluation"],
        "policy_id": "DLP-PRINT-004",
        "action_taken": "WARNED",
        "decision_reason": "AI classified HR document as sensitive; print warning issued.",
        "evidence_summary": "HR evaluation material sent to a printer.",
        "latency_ms": 147,
    },
    "messenger": {
        "department": "Product",
        "user_id": "product_user",
        "file_name": "launch_roadmap_internal.pdf",
        "file_path": r"C:\Users\product_user\Documents\launch_roadmap_internal.pdf",
        "process_name": "Teams.exe",
        "leak_channel": "MESSENGER",
        "detection_type": "HYBRID",
        "ai_score": 0.67,
        "matched_keywords": ["launch", "roadmap", "internal"],
        "policy_id": "DLP-MSG-005",
        "action_taken": "ALLOWED",
        "decision_reason": "Sensitivity score below warning threshold after keyword review.",
        "evidence_summary": "Internal roadmap shared through messenger under monitoring threshold.",
        "latency_ms": 109,
    },
    "clipboard": {
        "department": "R&D",
        "user_id": "research_user",
        "file_name": "clipboard_content",
        "file_path": None,
        "process_name": "chrome.exe",
        "leak_channel": "CLIPBOARD",
        "detection_type": "HYBRID",
        "ai_score": 0.72,
        "matched_keywords": ["confidential", "prototype"],
        "policy_id": "DLP-CLIP-006",
        "action_taken": "WARNED",
        "decision_reason": "Clipboard content requires a warning before external paste.",
        "evidence_summary": "Sensitive prototype context was detected in clipboard text.",
        "latency_ms": 78,
    },
    "cloud_drive": {
        "department": "Finance",
        "user_id": "finance_user",
        "file_name": "forecast_backup.xlsx",
        "file_path": r"C:\Users\finance_user\Documents\forecast_backup.xlsx",
        "process_name": "chrome.exe",
        "leak_channel": "CLOUD_DRIVE",
        "detection_type": "HYBRID",
        "ai_score": 0.89,
        "matched_keywords": ["forecast", "confidential"],
        "policy_id": "DLP-CLOUD-007",
        "action_taken": "BLOCKED",
        "decision_reason": "Confidential forecast upload to cloud storage was blocked.",
        "evidence_summary": "A finance forecast was detected in a cloud drive upload.",
        "latency_ms": 136,
    },
}
SCENARIO_ORDER = tuple(SCENARIOS)

ANALYZE_SCENARIOS = {
    "web_upload": {
        "channel": "web_upload",
        "snippet": "prototype source_code archive contains internal API key and confidential roadmap notes.",
        "dest": "external",
        "severity_hint": "high",
    },
    "usb_copy": {
        "channel": "usb",
        "snippet": "q3 revenue forecast spreadsheet contains confidential finance projections.",
        "dest": "removable",
        "severity_hint": "high",
    },
    "email_attachment": {
        "channel": "email_attachment",
        "snippet": "enterprise contract terms include NDA clauses and non-public discount conditions.",
        "dest": "external",
        "severity_hint": "medium",
    },
    "print": {
        "channel": "print",
        "snippet": "promotion candidate list includes salary, evaluation, and HR review notes.",
        "dest": "internal",
        "severity_hint": "medium",
    },
    "messenger": {
        "channel": "messenger",
        "snippet": "launch roadmap internal summary shared for product team discussion.",
        "dest": "internal",
        "severity_hint": "low",
    },
    "clipboard": {
        "channel": "clipboard",
        "snippet": "Confidential prototype notes copied for an external browser paste.",
        "dest": "external",
        "severity_hint": "medium",
    },
    "cloud_drive": {
        "channel": "drive_upload",
        "snippet": "Confidential finance forecast uploaded to an external cloud drive.",
        "dest": "external",
        "severity_hint": "high",
    },
}


def build_sample_payload(
    scenario: str,
    *,
    sequence: int,
    agent_id: str,
    event_id: str | None = None,
) -> dict:
    scenario_payload = SCENARIOS[scenario]
    generated_event_id = event_id
    if generated_event_id and sequence > 1:
        generated_event_id = f"{generated_event_id}-{sequence}"
    if not generated_event_id:
        generated_event_id = f"{agent_id}-{scenario}-{uuid4()}"

    return {
        "event_id": generated_event_id,
        "agent_id": agent_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host_ip": "192.168.10.42",
        "hostname": "host-agent-demo-01",
        **scenario_payload,
        "model_version": FIXTURE_MODEL_VERSION,
        "decision_reason": (
            f"[DEMO FIXTURE - NOT LIVE] {scenario_payload['decision_reason']}"
        ),
        "evidence_summary": (
            f"[DEMO FIXTURE - NOT LIVE] {scenario_payload['evidence_summary']}"
        ),
    }


def build_analyze_payload(scenario: str, log_payload: dict) -> dict:
    scenario_payload = ANALYZE_SCENARIOS[scenario]
    return {
        "event_id": log_payload["event_id"],
        "channel": scenario_payload["channel"],
        "user_id": log_payload["user_id"],
        "matched_patterns": log_payload["matched_keywords"],
        "snippet": scenario_payload["snippet"],
        "metadata": {
            "app": log_payload["process_name"],
            "dest": scenario_payload["dest"],
            "severity_hint": scenario_payload["severity_hint"],
            "file_name": log_payload["file_name"],
        },
    }


def apply_analysis_result(log_payload: dict, analysis_result: dict) -> dict:
    decision = analysis_result["decision"]
    log_payload["ai_score"] = analysis_result["confidence_score"]
    log_payload["action_taken"] = DECISION_TO_ACTION[decision]
    log_payload["detection_type"] = "HYBRID"
    log_payload["latency_ms"] = analysis_result["latency_ms"]
    log_payload["model_version"] = analysis_result["model_version"]
    log_payload["decision_reason"] = (
        f"{ANALYZED_FIXTURE_MARKER} {analysis_result['reason']}"
    )
    log_payload["evidence_summary"] = (
        f"{ANALYZED_FIXTURE_MARKER} "
        f"{analysis_result.get('evidence_summary') or analysis_result['reason']}"
    )
    return log_payload


def expand_scenarios(scenario: str, count: int) -> list[str]:
    return list(SCENARIO_ORDER) * count if scenario == "all" else [scenario] * count


def post_json(api_url: str, payload: dict, token: str | None = None) -> dict:
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Agent-Token"] = token

    request = Request(
        api_url,
        data=body,
        headers=headers,
        method="POST",
    )

    with urlopen(request, timeout=10) as response:
        response_body = response.read().decode("utf-8")
        return json.loads(response_body)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Send sample Host Agent DLP events to the dashboard API."
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_API_URL,
        help=f"Target logs API URL. Default: {DEFAULT_API_URL}",
    )
    parser.add_argument(
        "--analyze-url",
        default=DEFAULT_ANALYZE_URL,
        help=f"Target analyze API URL. Default: {DEFAULT_ANALYZE_URL}",
    )
    parser.add_argument(
        "--scenario",
        choices=["all", *SCENARIO_ORDER],
        default="web_upload",
        help=(
            "Web display fixture to send. Use 'all' for all seven fixtures; "
            "this does not mean Host Agent has seven independent detectors."
        ),
    )
    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="Number of events, or rounds when --scenario all is used. Default: 1",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.1,
        help="Seconds to wait between events. Default: 0.1",
    )
    parser.add_argument(
        "--agent-id",
        default="sentry-agent-demo-01",
        help="Agent identifier included in the payload.",
    )
    parser.add_argument(
        "--event-id",
        default=None,
        help="Explicit event_id for idempotency tests. Reusing the same value should not create a duplicate log.",
    )
    parser.add_argument(
        "--token",
        default=DEFAULT_AGENT_API_TOKEN,
        help="X-Agent-Token header value. Default: AGENT_API_TOKEN or local demo token.",
    )
    parser.add_argument(
        "--analyze-first",
        action="store_true",
        help="Call /api/v1/analyze first and use its returned decision in the log payload.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the payload without sending it.",
    )
    args = parser.parse_args()

    if args.count < 1:
        parser.error("--count must be greater than or equal to 1.")
    if args.interval < 0:
        parser.error("--interval must be greater than or equal to 0.")

    if args.analyze_url == DEFAULT_ANALYZE_URL and args.url != DEFAULT_API_URL:
        args.analyze_url = args.url.removesuffix("/logs") + "/analyze"

    scenario_names = expand_scenarios(args.scenario, args.count)
    scenario_payloads = [
        (
            scenario,
            build_sample_payload(
                scenario,
                sequence=index,
                agent_id=args.agent_id,
                event_id=args.event_id,
            ),
        )
        for index, scenario in enumerate(scenario_names, start=1)
    ]
    payloads = [payload for _, payload in scenario_payloads]

    if args.analyze_first:
        print(
            "Web fixture payload before analysis. Any returned model result still "
            "does not prove a live Host hook event."
        )
    else:
        print("Demo fixture only: scores and actions below are predefined, not live analysis results.")
    print(json.dumps(payloads[0] if len(payloads) == 1 else payloads, ensure_ascii=False, indent=2))

    if args.dry_run:
        print("Dry run complete. No request was sent.")
        return 0

    results = []
    for index, (scenario, payload) in enumerate(scenario_payloads, start=1):
        if args.analyze_first:
            analyze_payload = build_analyze_payload(scenario, payload)
            try:
                analysis_result = post_json(args.analyze_url, analyze_payload, token=args.token)
            except HTTPError as error:
                print(
                    f"Analyze request {index} failed with HTTP {error.code}: "
                    f"{error.read().decode('utf-8')}"
                )
                return 1
            except URLError as error:
                print(f"Could not connect to {args.analyze_url}: {error.reason}")
                return 1

            payload = apply_analysis_result(payload, analysis_result)
            print(f"Analyze result {index}:")
            print(json.dumps(analysis_result, ensure_ascii=False, indent=2))
            print(f"Final log payload {index}:")
            print(json.dumps(payload, ensure_ascii=False, indent=2))

        try:
            result = post_json(args.url, payload, token=args.token)
        except HTTPError as error:
            print(f"Request {index} failed with HTTP {error.code}: {error.read().decode('utf-8')}")
            return 1
        except URLError as error:
            print(f"Could not connect to {args.url}: {error.reason}")
            return 1

        results.append(result)
        if index < len(scenario_payloads):
            sleep(args.interval)

    print(f"{len(results)} sample log(s) sent successfully.")
    print(json.dumps(results[0] if len(results) == 1 else results, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
