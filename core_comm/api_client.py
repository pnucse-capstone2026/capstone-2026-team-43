"""REST API client for AI analysis server requests."""

import logging
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)


class ApiClient:
    """Sends clipboard content to the AI server and returns analysis results."""

    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    def analyze(self, text: str, metadata: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """POST text to the analysis endpoint and return the server response."""
        payload: dict[str, Any] = {"text": text}
        if metadata:
            payload["metadata"] = metadata

        url = f"{self._base_url}/api/v1/analyze"
        logger.debug("Sending analysis request to %s", url)

        response = requests.post(url, json=payload, timeout=self._timeout)
        response.raise_for_status()
        return response.json()
