"""Format and forward detection events to the web dashboard."""

import logging
from datetime import datetime, timezone
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)


class EventLogger:
    """Sends structured detection logs to the dashboard API."""

    def __init__(self, dashboard_url: str, timeout: float = 10.0) -> None:
        self._dashboard_url = dashboard_url.rstrip("/")
        self._timeout = timeout

    def log_event(
        self,
        event_type: str,
        text_preview: str,
        risk_score: float,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        """POST a formatted event to the dashboard."""
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "text_preview": text_preview[:200],
            "risk_score": risk_score,
            "details": details or {},
        }

        url = f"{self._dashboard_url}/api/v1/events"
        logger.info("Logging event: type=%s risk=%.1f", event_type, risk_score)

        response = requests.post(url, json=payload, timeout=self._timeout)
        response.raise_for_status()
