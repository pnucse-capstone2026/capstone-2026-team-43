"""Windows notifications for blocked paste events.

The message box is shown in a daemon thread so that it never stalls the
WH_KEYBOARD_LL hook callback (Windows will forcibly remove hooks that
block for too long).
"""

import ctypes
import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)

_MB_OK           = 0x00000000
_MB_ICONWARNING  = 0x00000030
_MB_TOPMOST      = 0x00040000
_MB_SETFOREGROUND = 0x00010000


def _show_messagebox(title: str, body: str) -> None:
    ctypes.windll.user32.MessageBoxW(
        None,
        body,
        title,
        _MB_OK | _MB_ICONWARNING | _MB_TOPMOST | _MB_SETFOREGROUND,
    )


def notify_blocked(process_name: str, hits: list[dict[str, Any]]) -> None:
    """Fire-and-forget: show a warning dialog listing what was detected."""
    hit_names = ", ".join(h.get("name", "알 수 없음") for h in hits[:3])
    if len(hits) > 3:
        hit_names += f" 외 {len(hits) - 3}건"

    title = "Sentry DLP — 붙여넣기 차단"
    body = (
        f"민감한 정보가 감지되어 붙여넣기가 차단되었습니다.\n\n"
        f"대상 프로그램 : {process_name}\n"
        f"탐지 항목     : {hit_names}\n\n"
        f"해당 내용을 외부로 전달해야 한다면 보안 담당자에게 문의하십시오."
    )

    threading.Thread(
        target=_show_messagebox,
        args=(title, body),
        daemon=True,
        name="DLPNotifier",
    ).start()

    logger.warning(
        "Paste BLOCKED → process='%s' hits=[%s]",
        process_name,
        ", ".join(h.get("id", "?") for h in hits),
    )
