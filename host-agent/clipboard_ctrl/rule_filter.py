"""Lightweight regex-based first-pass filter for sensitive data patterns."""

import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class RuleFilter:
    """Matches clipboard text against configured regex patterns."""

    def __init__(self, patterns_path: Path) -> None:
        self._patterns: list[dict[str, Any]] = []
        self._load_patterns(patterns_path)

    def _load_patterns(self, path: Path) -> None:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
        self._patterns = data.get("patterns", [])
        logger.debug("Loaded %d regex patterns from %s", len(self._patterns), path)

    def match(self, text: str) -> list[dict[str, Any]]:
        """Return all patterns that match the given text."""
        hits: list[dict[str, Any]] = []
        for entry in self._patterns:
            pattern = entry.get("regex", "")
            if pattern and re.search(pattern, text):
                hits.append(entry)
        return hits

    def is_suspicious(self, text: str) -> bool:
        """Return True if any pattern matches."""
        return bool(self.match(text))
