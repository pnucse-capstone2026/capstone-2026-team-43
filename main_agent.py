"""Sentry Host Agent — entry point. Runs as a background process.

Current mode (no AI server): regex-only.
  - Regex hit  → block paste + Windows notification.
  - No hit     → pass through silently.

Future mode (AI server available): regex acts as gate, AI makes final decision.
"""

import logging
import sys
from pathlib import Path
from typing import Any

import yaml

from clipboard_ctrl.clipboard_hook import ClipboardHook
from clipboard_ctrl.notifier import notify_blocked
from clipboard_ctrl.paste_inspector import PasteInspector
from clipboard_ctrl.rule_filter import RuleFilter

PROJECT_ROOT = Path(__file__).resolve().parent


def load_settings() -> dict[str, Any]:
    settings_path = PROJECT_ROOT / "config" / "settings.yaml"
    with settings_path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def make_paste_handler(rule_filter: RuleFilter) -> Any:
    """Return the callback used by ClipboardHook on every inspected Ctrl+V."""

    def on_text_pasted(text: str, process_name: str) -> bool:
        """Return True to block the paste, False to allow it."""
        hits = rule_filter.match(text)
        if not hits:
            return False  # Clean → allow

        # Sensitive content detected → block + alert
        notify_blocked(process_name, hits)
        return True

    return on_text_pasted


def main() -> None:
    settings = load_settings()
    setup_logging(settings.get("agent", {}).get("log_level", "INFO"))
    logger = logging.getLogger(__name__)

    patterns_path = PROJECT_ROOT / settings.get("agent", {}).get(
        "regex_patterns", "config/regex_patterns.json"
    )
    policy_path = PROJECT_ROOT / "config" / "paste_policy.json"

    rule_filter = RuleFilter(patterns_path)
    inspector = PasteInspector(policy_path)

    hook = ClipboardHook(
        should_inspect=inspector.should_inspect,
        on_text_pasted=make_paste_handler(rule_filter),
    )
    hook.start()

    logger.info("Sentry Host Agent running. Press Ctrl+C to stop.")
    try:
        import time

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        hook.stop()
        logger.info("Agent stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
