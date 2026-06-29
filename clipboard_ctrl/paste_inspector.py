"""Determine whether a paste destination process should be inspected.

Policy resolution order
-----------------------
1. If the process name is in ``allowlist``  → skip inspection (internal tool).
2. If the process name is in ``inspect_list`` → inspect.
3. Otherwise fall back to ``default_action`` (``"allow"`` or ``"inspect"``).
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class PasteInspector:
    """Loads paste_policy.json and answers: should this process be inspected?"""

    def __init__(self, policy_path: Path) -> None:
        with policy_path.open(encoding="utf-8") as f:
            policy = json.load(f)

        self._allowlist: frozenset[str] = frozenset(
            p.lower() for p in policy.get("allowlist", [])
        )
        self._inspect_list: frozenset[str] = frozenset(
            p.lower() for p in policy.get("inspect_list", [])
        )
        self._default_inspect: bool = policy.get("default_action", "allow") == "inspect"

        logger.info(
            "Paste policy loaded — allowlist=%d inspect_list=%d default=%s",
            len(self._allowlist),
            len(self._inspect_list),
            "inspect" if self._default_inspect else "allow",
        )

    def should_inspect(self, process_name: str) -> bool:
        """Return True if the process should be inspected before paste."""
        name = process_name.lower()
        if name in self._allowlist:
            logger.debug("Allow-listed: %s", name)
            return False
        if name in self._inspect_list:
            logger.debug("Inspect-listed: %s", name)
            return True
        logger.debug("Default action for '%s': %s", name, "inspect" if self._default_inspect else "allow")
        return self._default_inspect
