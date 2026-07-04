"""이벤트 로거 — 로컬 저장과 웹 서버 전송을 분리한다.

현재 단계 (웹 서버 없음)
  └─ LocalEventStore에 JSONL 저장만 수행.

웹 서버 준비 완료 후
  └─ flush_to_server()로 미전송 레코드를 POST하거나,
     실시간 전송 모드(send_immediately=True)를 켠다.
"""

import json
import logging
import threading
from pathlib import Path
from typing import Any, Optional

import requests

from core_comm.local_store import LocalEventStore

logger = logging.getLogger(__name__)


class EventLogger:
    """탐지 이벤트를 로컬에 기록하고 (선택적으로) 웹 서버로 전송한다."""

    def __init__(
        self,
        store: LocalEventStore,
        dashboard_url: Optional[str] = None,
        timeout: float = 10.0,
        send_immediately: bool = False,
    ) -> None:
        """
        Parameters
        ----------
        store:
            로컬 JSONL 저장소.
        dashboard_url:
            웹 대시보드 API 베이스 URL. None이면 네트워크 전송을 시도하지 않는다.
        timeout:
            HTTP 요청 타임아웃 (초).
        send_immediately:
            True면 write()마다 웹으로도 즉시 전송(best-effort, 실패해도 로컬 저장은 보장).
        """
        self._store = store
        self._dashboard_url = dashboard_url.rstrip("/") if dashboard_url else None
        self._timeout = timeout
        self._send_immediately = send_immediately and bool(dashboard_url)

    # ── Public API ────────────────────────────────────────────────────────────

    def log(
        self,
        channel: str,
        action: str,
        process_name: str,
        hits: list[dict[str, Any]],
        text: Optional[str] = None,
        extra: Optional[dict[str, Any]] = None,
    ) -> None:
        """이벤트를 로컬에 저장하고 즉시 전송 모드면 비동기로 서버에도 보낸다."""
        self._store.write(
            channel=channel,
            action=action,
            process_name=process_name,
            hits=hits,
            text=text,
            extra=extra,
        )

        if self._send_immediately:
            payload = self._store._build_record(
                channel, action, process_name, hits, text, extra
            )
            threading.Thread(
                target=self._post,
                args=(payload,),
                daemon=True,
                name="EventSender",
            ).start()

    def flush_to_server(self) -> int:
        """로컬 JSONL의 모든 레코드를 웹 서버로 POST하고 성공 건수를 반환한다.

        나중에 대시보드 서버가 준비되면 이 메서드를 호출하면 된다.
        전송 성공한 레코드는 별도로 삭제하지 않는다(서버 쪽에서 중복 처리).
        """
        if not self._dashboard_url:
            logger.warning("flush_to_server: dashboard_url이 설정되지 않았습니다.")
            return 0

        active = self._store._active_path
        if not active.exists():
            return 0

        sent = 0
        with active.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    self._post(record)
                    sent += 1
                except Exception as exc:
                    logger.warning("flush 중 오류 (건너뜀): %s", exc)

        logger.info("flush_to_server 완료: %d건 전송", sent)
        return sent

    # ── Internals ─────────────────────────────────────────────────────────────

    def _post(self, payload: dict[str, Any]) -> None:
        """단일 레코드를 대시보드 API로 POST한다. 실패는 로그로만 남긴다."""
        url = f"{self._dashboard_url}/api/v1/events"
        try:
            resp = requests.post(url, json=payload, timeout=self._timeout)
            resp.raise_for_status()
            logger.debug("Event posted → %s (%d)", url, resp.status_code)
        except Exception as exc:
            logger.warning("Event POST 실패 (로컬에는 저장됨): %s", exc)
