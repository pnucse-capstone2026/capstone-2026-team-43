from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import Counter
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend import main as backend_main


DEMO_SCENARIOS = (
    {
        "day_offset": 0,
        "department": "R&D",
        "user_id": "research_user",
        "file_name": "prototype_source_export.zip",
        "file_path": r"C:\Research\prototype_source_export.zip",
        "process_name": "chrome.exe",
        "leak_channel": "WEB_UPLOAD",
        "detection_type": "HYBRID",
        "ai_score": 0.96,
        "matched_keywords": ["source_code", "api_key", "prototype"],
        "policy_id": "DLP-WEB-001",
        "action_taken": "BLOCKED",
        "decision_reason": "AI score exceeded the web upload block threshold.",
        "evidence_summary": "Source code and API key patterns were detected in an external upload.",
        "latency_ms": 132,
    },
    {
        "day_offset": 0,
        "department": "Finance",
        "user_id": "finance_user",
        "file_name": "quarterly_revenue_forecast.xlsx",
        "file_path": r"C:\Finance\quarterly_revenue_forecast.xlsx",
        "process_name": "explorer.exe",
        "leak_channel": "USB_COPY",
        "detection_type": "HYBRID",
        "ai_score": 0.92,
        "matched_keywords": ["revenue", "forecast", "confidential"],
        "policy_id": "DLP-USB-002",
        "action_taken": "BLOCKED",
        "decision_reason": "Confidential finance data was copied to removable storage.",
        "evidence_summary": "Revenue forecast keywords and a removable destination were detected.",
        "latency_ms": 87,
    },
    {
        "day_offset": 0,
        "department": "Sales",
        "user_id": "sales_user",
        "file_name": "enterprise_contract_terms.docx",
        "file_path": r"C:\Sales\enterprise_contract_terms.docx",
        "process_name": "OUTLOOK.EXE",
        "leak_channel": "EMAIL_ATTACHMENT",
        "detection_type": "RULE_BASED",
        "ai_score": 0.74,
        "matched_keywords": ["contract", "discount", "nda"],
        "policy_id": "DLP-MAIL-003",
        "action_taken": "WARNED",
        "decision_reason": "Contract terms require user confirmation before external email.",
        "evidence_summary": "Sensitive contract terms were attached to an outbound email.",
        "latency_ms": 104,
    },
    {
        "day_offset": 1,
        "department": "HR",
        "user_id": "hr_user",
        "file_name": "promotion_candidate_list.pdf",
        "file_path": r"C:\HR\promotion_candidate_list.pdf",
        "process_name": "AcroRd32.exe",
        "leak_channel": "PRINT",
        "detection_type": "AI_MODEL",
        "ai_score": 0.71,
        "matched_keywords": ["candidate", "salary", "evaluation"],
        "policy_id": "DLP-PRINT-004",
        "action_taken": "WARNED",
        "decision_reason": "Sensitive HR document printing requires review.",
        "evidence_summary": "Salary and employee evaluation context was detected.",
        "latency_ms": 141,
    },
    {
        "day_offset": 1,
        "department": "Product",
        "user_id": "product_user",
        "file_name": "launch_roadmap_internal.pdf",
        "file_path": r"C:\Product\launch_roadmap_internal.pdf",
        "process_name": "Teams.exe",
        "leak_channel": "MESSENGER",
        "detection_type": "HYBRID",
        "ai_score": 0.42,
        "matched_keywords": ["roadmap", "internal"],
        "policy_id": "DLP-MSG-005",
        "action_taken": "ALLOWED",
        "decision_reason": "Internal collaboration remained below the warning threshold.",
        "evidence_summary": "Internal roadmap context was monitored and allowed.",
        "latency_ms": 65,
    },
    {
        "day_offset": 2,
        "department": "Security",
        "user_id": "security_user",
        "file_name": "incident_response_credentials.txt",
        "file_path": r"C:\Security\incident_response_credentials.txt",
        "process_name": "msedge.exe",
        "leak_channel": "WEB_UPLOAD",
        "detection_type": "HYBRID",
        "ai_score": 0.88,
        "matched_keywords": ["password", "secret", "api_key"],
        "policy_id": "DLP-WEB-001",
        "action_taken": "BLOCKED",
        "decision_reason": "Credential patterns exceeded the block threshold.",
        "evidence_summary": "Password, secret, and API key patterns were detected.",
        "latency_ms": 118,
    },
    {
        "day_offset": 2,
        "department": "Legal",
        "user_id": "legal_user",
        "file_name": "acquisition_nda_draft.docx",
        "file_path": r"C:\Legal\acquisition_nda_draft.docx",
        "process_name": "OUTLOOK.EXE",
        "leak_channel": "EMAIL_ATTACHMENT",
        "detection_type": "HYBRID",
        "ai_score": 0.90,
        "matched_keywords": ["acquisition", "nda", "confidential"],
        "policy_id": "DLP-MAIL-003",
        "action_taken": "BLOCKED",
        "decision_reason": "A confidential acquisition draft was addressed externally.",
        "evidence_summary": "NDA and acquisition context matched a high-risk mail policy.",
        "latency_ms": 126,
    },
    {
        "day_offset": 3,
        "department": "Marketing",
        "user_id": "marketing_user",
        "file_name": "unreleased_campaign_plan.pptx",
        "file_path": r"C:\Marketing\unreleased_campaign_plan.pptx",
        "process_name": "chrome.exe",
        "leak_channel": "WEB_UPLOAD",
        "detection_type": "AI_MODEL",
        "ai_score": 0.68,
        "matched_keywords": ["unreleased", "campaign", "internal"],
        "policy_id": "DLP-WEB-001",
        "action_taken": "WARNED",
        "decision_reason": "Unreleased campaign material requires user confirmation.",
        "evidence_summary": "Internal campaign planning context was detected.",
        "latency_ms": 109,
    },
    {
        "day_offset": 3,
        "department": "Operations",
        "user_id": "operations_user",
        "file_name": "public_shipping_schedule.csv",
        "file_path": r"C:\Operations\public_shipping_schedule.csv",
        "process_name": "explorer.exe",
        "leak_channel": "USB_COPY",
        "detection_type": "RULE_BASED",
        "ai_score": 0.35,
        "matched_keywords": ["shipping", "schedule"],
        "policy_id": "DLP-USB-002",
        "action_taken": "ALLOWED",
        "decision_reason": "The document contained no restricted data patterns.",
        "evidence_summary": "Only public operations schedule terms were detected.",
        "latency_ms": 53,
    },
    {
        "day_offset": 4,
        "department": "Executive",
        "user_id": "executive_user",
        "file_name": "board_strategy_notes.pdf",
        "file_path": r"C:\Executive\board_strategy_notes.pdf",
        "process_name": "AcroRd32.exe",
        "leak_channel": "PRINT",
        "detection_type": "HYBRID",
        "ai_score": 0.87,
        "matched_keywords": ["board", "strategy", "confidential"],
        "policy_id": "DLP-PRINT-004",
        "action_taken": "BLOCKED",
        "decision_reason": "Board strategy material exceeded the print block threshold.",
        "evidence_summary": "Confidential executive strategy context was detected.",
        "latency_ms": 116,
    },
    {
        "day_offset": 5,
        "department": "Design",
        "user_id": "design_user",
        "file_name": "released_brand_assets.zip",
        "file_path": r"C:\Design\released_brand_assets.zip",
        "process_name": "Slack.exe",
        "leak_channel": "MESSENGER",
        "detection_type": "RULE_BASED",
        "ai_score": 0.29,
        "matched_keywords": ["brand", "released"],
        "policy_id": "DLP-MSG-005",
        "action_taken": "ALLOWED",
        "decision_reason": "Released brand assets are approved for team sharing.",
        "evidence_summary": "No confidential or restricted patterns were detected.",
        "latency_ms": 48,
    },
    {
        "day_offset": 6,
        "department": "Finance",
        "user_id": "finance_manager",
        "file_name": "annual_salary_budget.xlsx",
        "file_path": r"C:\Finance\annual_salary_budget.xlsx",
        "process_name": "OUTLOOK.EXE",
        "leak_channel": "EMAIL_ATTACHMENT",
        "detection_type": "HYBRID",
        "ai_score": 0.94,
        "matched_keywords": ["salary", "budget", "confidential"],
        "policy_id": "DLP-MAIL-003",
        "action_taken": "BLOCKED",
        "decision_reason": "Salary budget data exceeded the outbound mail block threshold.",
        "evidence_summary": "Salary and confidential budget patterns were detected.",
        "latency_ms": 137,
    },
)


def parse_base_date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("base date must use YYYY-MM-DD format") from error


def build_demo_logs(base_date: date | None = None) -> list[dict]:
    selected_date = base_date or datetime.now(timezone.utc).date()
    date_token = selected_date.strftime("%Y%m%d")
    logs: list[dict] = []

    for sequence, scenario in enumerate(DEMO_SCENARIOS, start=1):
        event_date = selected_date - timedelta(days=scenario["day_offset"])
        event_time = time(hour=8 + (sequence % 8), minute=(sequence * 7) % 60)
        timestamp = datetime.combine(event_date, event_time, tzinfo=timezone.utc)
        logs.append(
            {
                "event_id": f"demo-seed-{date_token}-{sequence:02d}",
                "agent_id": f"sentry-demo-agent-{(sequence % 3) + 1:02d}",
                "timestamp": timestamp.isoformat(),
                "host_ip": f"192.168.10.{40 + sequence}",
                "hostname": f"demo-host-{sequence:02d}",
                **{key: value for key, value in scenario.items() if key != "day_offset"},
            }
        )

    return logs


def initialize_database(db_path: Path) -> None:
    original_db_path = backend_main.DB_PATH
    backend_main.DB_PATH = db_path
    try:
        backend_main.init_db()
    finally:
        backend_main.DB_PATH = original_db_path


def seed_demo_data(db_path: Path, base_date: date | None = None) -> dict:
    target_path = db_path.resolve()
    logs = build_demo_logs(base_date)
    initialize_database(target_path)
    received_at = datetime.now(timezone.utc).isoformat()
    inserted = 0

    with sqlite3.connect(target_path) as connection:
        for raw_log in logs:
            log = backend_main.LogCreate.model_validate(raw_log)
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO dlp_logs (
                    event_id, agent_id, timestamp, received_at, host_ip, hostname,
                    user_id, department, file_name, file_path, process_name,
                    leak_channel, detection_type, ai_score, matched_keywords,
                    policy_id, action_taken, decision_reason, evidence_summary, latency_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    log.event_id,
                    log.agent_id,
                    log.timestamp.astimezone(timezone.utc).isoformat(),
                    received_at,
                    log.host_ip,
                    log.hostname,
                    log.user_id,
                    log.department,
                    log.file_name,
                    log.file_path,
                    log.process_name,
                    log.leak_channel,
                    log.detection_type,
                    log.ai_score,
                    ",".join(log.matched_keywords),
                    log.policy_id,
                    log.action_taken,
                    log.decision_reason,
                    log.evidence_summary,
                    log.latency_ms,
                ),
            )
            inserted += cursor.rowcount

    return {
        "database": str(target_path),
        "base_date": (base_date or datetime.now(timezone.utc).date()).isoformat(),
        "requested": len(logs),
        "inserted": inserted,
        "skipped": len(logs) - inserted,
    }


def build_preview(db_path: Path, base_date: date) -> dict:
    logs = build_demo_logs(base_date)
    return {
        "dry_run": True,
        "database": str(db_path.resolve()),
        "base_date": base_date.isoformat(),
        "event_count": len(logs),
        "action_counts": dict(Counter(log["action_taken"] for log in logs)),
        "channels": sorted({log["leak_channel"] for log in logs}),
        "first_timestamp": min(log["timestamp"] for log in logs),
        "last_timestamp": max(log["timestamp"] for log in logs),
        "event_ids": [log["event_id"] for log in logs],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Seed the DLP dashboard with idempotent demo logs for the current date."
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=backend_main.DB_PATH,
        help=f"Target SQLite DB. Default: {backend_main.DB_PATH}",
    )
    parser.add_argument(
        "--base-date",
        type=parse_base_date,
        default=datetime.now(timezone.utc).date(),
        help="Latest demo event date in YYYY-MM-DD format. Default: current UTC date.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview generated event IDs and distribution without writing the DB.",
    )
    args = parser.parse_args()

    if args.dry_run:
        result = build_preview(args.db, args.base_date)
    else:
        result = seed_demo_data(args.db, args.base_date)

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
