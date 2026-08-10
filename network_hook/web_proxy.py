"""web_proxy.py — HTTPS MITM 웹 메일 DLP 채널.

- allow_hosts: channel_policy inspect_domains (국내 주요 웹메일) 만 TLS 가로채기
- 로그/DLP: 해당 호스트의 전송(POST/PUT/PATCH) 패킷만
- 그 외 트래픽: 터널 통과 (복호화·로그 없음)
"""

from __future__ import annotations

import asyncio
import email as _email_lib
import json
import logging
import re
import threading
import urllib.parse
from email import message_from_bytes
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# 차단 시 브라우저에 보여줄 HTML
_BLOCK_HTML = """\
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <title>Sentry DLP — 전송 차단</title>
  <style>
    body {{ font-family: 'Malgun Gothic', sans-serif; text-align: center;
            padding: 80px; background: #f8f9fa; }}
    .card {{ background: #fff; border-radius: 8px; padding: 40px;
             display: inline-block; box-shadow: 0 2px 8px rgba(0,0,0,.1); }}
    h2 {{ color: #c0392b; }}
    .reason {{ color: #555; font-size: 14px; margin-top: 16px; }}
    .patterns {{ color: #888; font-size: 12px; margin-top: 8px; }}
  </style>
</head>
<body>
  <div class="card">
    <h2>🔒 Sentry DLP — 전송 차단</h2>
    <p>민감정보가 포함된 내용의 전송이 차단되었습니다.<br>
       보안 담당자에게 문의하세요.</p>
    <div class="reason">{reason}</div>
    <div class="patterns">탐지 패턴: {patterns}</div>
  </div>
</body>
</html>"""


# ── DLP 애드온 ────────────────────────────────────────────────────────────────

class _DLPAddon:
    """mitmproxy 애드온 클래스 — POST/PUT 요청을 가로채 DLP 파이프라인 실행."""

    # 가로채기 로그에 붙일 본문 미리보기 길이 (원문 전체 덤프 방지)
    _BODY_PREVIEW = 160

    # 같은 호스트에서 팝업을 중복 발생시키지 않을 시간(초) — Gmail 장기 재시도 커버
    _POPUP_DEDUP_SEC = 600  # 10분

    def __init__(
        self,
        inspect_domains: list[str],
        rule_filter: Any,
        payload_builder: Any,
        api_client: Any,
        event_logger: Any,
        file_inspector: Any,
        on_blocked: Optional[Callable[[str, list, str], None]] = None,
        log_traffic: bool = True,
        skip_path_patterns: Optional[list[str]] = None,
        min_body_bytes: int = 0,
    ) -> None:
        self._domains           = frozenset(d.lower().lstrip("*.") for d in inspect_domains)
        self._rule_filter       = rule_filter
        self._builder           = payload_builder
        self._api               = api_client
        self._event_logger      = event_logger
        self._fi                = file_inspector
        self._on_blocked        = on_blocked
        self._log_traffic       = log_traffic
        self._skip_patterns     = [s.lower() for s in (skip_path_patterns or [])]
        self._min_body_bytes    = min_body_bytes
        # {body_hash: last_popup_time} — 재시도 팝업 중복 방지
        self._popup_cache: dict[str, float] = {}

    # ── mitmproxy 훅 ─────────────────────────────────────────────────────────

    def request(self, flow) -> None:  # noqa: ANN001
        """요청이 서버로 전달되기 전 호출. block 결정 시 즉시 응답 설정."""
        try:
            self._handle(flow)
        except Exception:
            logger.exception("[WebProxy] request 처리 중 예외")

    def response(self, flow) -> None:  # noqa: ANN001
        """메일 전송 요청에 대한 응답만 로그."""
        if not self._log_traffic:
            return
        try:
            if not self._is_mail_send(flow):
                return
            req = flow.request
            res = flow.response
            if res is None:
                return
            logger.info(
                "[WebProxy] <- status=%s  %s %s",
                res.status_code,
                req.method,
                req.pretty_url[:200],
            )
        except Exception:
            logger.debug("[WebProxy] response 로그 실패", exc_info=True)

    # ── 내부 로직 ─────────────────────────────────────────────────────────────

    def _is_mail_send(self, flow) -> bool:
        """검사 대상 웹메일 + 본문 전송 메서드(POST/PUT/PATCH) 여부.

        skip_path_patterns 에 걸리는 경로(sync·jserror·자동완성 등)는 제외.
        min_body_bytes 미만 본문도 제외.
        """
        if flow.request.method not in ("POST", "PUT", "PATCH"):
            return False
        if not self._is_target(flow.request.pretty_host.lower()):
            return False

        # 경로·쿼리 기반 제외
        url_lower = flow.request.pretty_url.lower()
        for pat in self._skip_patterns:
            if pat in url_lower:
                return False

        # 최소 본문 크기 미만 제외
        if self._min_body_bytes and len(flow.request.content or b"") < self._min_body_bytes:
            return False

        return True

    def _log_send(self, flow) -> None:
        """메일 전송 패킷 한 줄 + 본문 미리보기."""
        req = flow.request
        body = req.content or b""
        ct = req.headers.get("content-type", "-")
        if len(ct) > 60:
            ct = ct[:57] + "..."

        logger.info(
            "[WebProxy] -> %s %s  bytes=%d  ct=%s",
            req.method,
            req.pretty_url[:200],
            len(body),
            ct,
        )

        if body:
            try:
                preview = body.decode("utf-8", errors="replace")
            except Exception:
                preview = repr(body[: self._BODY_PREVIEW])
            preview = preview.replace("\r", " ").replace("\n", " ")
            if len(preview) > self._BODY_PREVIEW:
                preview = preview[: self._BODY_PREVIEW] + "..."
            logger.info("[WebProxy]    body preview: %s", preview)

    def _handle(self, flow) -> None:
        from mitmproxy.http import Response  # 지연 임포트 — 서비스 시 유효

        # 메일 전송 패킷만 처리 (일반 트래픽/GET 로깅 없음)
        if not self._is_mail_send(flow):
            return

        if self._log_traffic:
            self._log_send(flow)

        text = self._extract_text(flow)
        if not text or not text.strip():
            if self._log_traffic:
                logger.info(
                    "[WebProxy]    DLP skip (empty text) url=%s",
                    flow.request.pretty_url[:180],
                )
            return

        hits = self._rule_filter.match(text)
        if not hits:
            if self._log_traffic:
                logger.info(
                    "[WebProxy]    DLP regex: no hit  text_len=%d",
                    len(text),
                )
            return

        if self._log_traffic:
            ids = ",".join(h.get("id", "?") for h in hits[:8])
            logger.info(
                "[WebProxy]    DLP regex: HIT n=%d ids=[%s]  text_len=%d",
                len(hits),
                ids,
                len(text),
            )

        host = flow.request.pretty_host.lower()
        process_name = f"browser@{host}"
        payload = self._builder.build(text, hits, "web_mail", process_name)
        result  = self._api.analyze(payload)

        logger.info(
            "[WebProxy] AI 판단: action=%s risk=%.0f url=%s",
            result.action, result.risk_score, flow.request.pretty_url,
        )

        if result.should_block:
            self._event_logger.log(
                channel="web_mail",
                action="blocked",
                process_name=process_name,
                hits=hits,
                text=text,
                extra={
                    "url":        flow.request.pretty_url,
                    "risk_score": result.risk_score,
                    "reason":     result.reason,
                },
            )
            # 같은 호스트 60초 내 팝업 1회만 (재시도/동시다발 차단 팝업 폭탄 방지)
            if self._on_blocked:
                import time as _time
                host = flow.request.pretty_host.lower()
                now = _time.monotonic()
                last = self._popup_cache.get(host, 0)
                if now - last > self._POPUP_DEDUP_SEC:
                    self._popup_cache[host] = now
                    self._on_blocked(flow.request.pretty_url, hits, process_name)
                else:
                    logger.info("[WebProxy] 재시도 차단 (팝업 생략) url=%s", flow.request.pretty_url[:120])

            pattern_names = ", ".join(h.get("name", h.get("id", "")) for h in hits)
            html = _BLOCK_HTML.format(
                reason=result.reason or "민감정보 탐지",
                patterns=pattern_names,
            )
            flow.response = Response.make(
                451,
                html.encode("utf-8"),
                {
                    "Content-Type":  "text/html; charset=utf-8",
                    "X-DLP-Blocked": "1",
                    "Cache-Control": "no-store",
                },
            )
            return

        if result.needs_review:
            self._event_logger.log(
                channel="web_mail",
                action="review",
                process_name=process_name,
                hits=hits,
                text=text,
                extra={
                    "url":        flow.request.pretty_url,
                    "risk_score": result.risk_score,
                    "reason":     result.reason,
                },
            )
            logger.warning("[WebProxy] review 기록 — %s", flow.request.pretty_url)
        # allow → 그대로 통과

    # ── 도메인 매칭 ──────────────────────────────────────────────────────────

    def _is_target(self, host: str) -> bool:
        if host in self._domains:
            return True
        for domain in self._domains:
            if host == domain or host.endswith("." + domain):
                return True
        return False

    # ── 본문 텍스트 추출 ─────────────────────────────────────────────────────

    def _extract_text(self, flow) -> str:
        ct   = flow.request.headers.get("content-type", "").lower()
        body = flow.request.content
        if not body:
            return ""

        if "application/json" in ct:
            return self._from_json(body)
        if "multipart/form-data" in ct:
            return self._from_multipart(body, ct)
        if "application/x-www-form-urlencoded" in ct:
            return self._from_urlencoded(body)
        # 기타 (text/plain 등)
        return body.decode("utf-8", errors="ignore")

    def _from_json(self, body: bytes) -> str:
        """JSON 객체에서 모든 문자열 값을 재귀 수집."""
        try:
            obj = json.loads(body)
        except Exception:
            return body.decode("utf-8", errors="ignore")
        parts: list[str] = []
        _collect_strings(obj, parts)
        return "\n".join(parts)

    def _from_multipart(self, body: bytes, ct: str) -> str:
        """multipart 파트별 텍스트 + 첨부파일 추출."""
        try:
            mime = message_from_bytes(
                b"Content-Type: " + ct.encode() + b"\r\n\r\n" + body
            )
        except Exception:
            return body.decode("utf-8", errors="ignore")

        parts: list[str] = []
        for part in mime.walk():
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            filename = part.get_filename()
            pct = part.get_content_type() or ""

            if filename and self._fi:
                try:
                    extracted = self._fi.extract_from_bytes(payload, filename)
                    if extracted:
                        parts.append(f"[첨부: {filename}]\n{extracted}")
                except Exception as exc:
                    logger.debug("[WebProxy] 첨부 추출 실패 %s: %s", filename, exc)
            elif "text" in pct:
                charset = part.get_param("charset", "utf-8")
                try:
                    parts.append(payload.decode(charset, errors="ignore"))
                except Exception:
                    parts.append(payload.decode("utf-8", errors="ignore"))

        return "\n\n".join(parts)

    def _from_urlencoded(self, body: bytes) -> str:
        """application/x-www-form-urlencoded 파싱."""
        try:
            params = urllib.parse.parse_qs(body.decode("utf-8", errors="ignore"))
            return "\n".join(v for values in params.values() for v in values)
        except Exception:
            return body.decode("utf-8", errors="ignore")


def _collect_strings(obj: Any, parts: list[str], depth: int = 0) -> None:
    """JSON 객체를 재귀 순회해 의미 있는 문자열을 수집."""
    if depth > 12:
        return
    if isinstance(obj, str):
        if len(obj) > 3:  # 너무 짧은 값 제외
            parts.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _collect_strings(v, parts, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _collect_strings(item, parts, depth + 1)


# ── WebProxy 클래스 ───────────────────────────────────────────────────────────

class WebProxy:
    """mitmproxy를 백그라운드 스레드에서 실행하는 HTTPS MITM DLP 채널.

    allow_hosts 로 inspect_domains 만 TLS 가로채기하고,
    그 외 트래픽은 터널 통과(로그·복호화 없음).
    DLP/로그는 메일 전송(POST/PUT/PATCH) 패킷만 대상.
    """

    def __init__(
        self,
        port: int,
        inspect_domains: list[str],
        rule_filter: Any,
        payload_builder: Any,
        api_client: Any,
        event_logger: Any,
        file_inspector: Any,
        on_blocked: Optional[Callable[[str, list, str], None]] = None,
        log_traffic: bool = True,
        skip_path_patterns: Optional[list[str]] = None,
        min_body_bytes: int = 0,
    ) -> None:
        self._port = port
        self._inspect_domains = [
            d.strip().lower().lstrip("*.") for d in inspect_domains if d and d.strip()
        ]
        self._addon = _DLPAddon(
            inspect_domains=self._inspect_domains,
            rule_filter=rule_filter,
            payload_builder=payload_builder,
            api_client=api_client,
            event_logger=event_logger,
            file_inspector=file_inspector,
            on_blocked=on_blocked,
            log_traffic=log_traffic,
            skip_path_patterns=skip_path_patterns,
            min_body_bytes=min_body_bytes,
        )
        self._thread: Optional[threading.Thread] = None
        self._master: Any = None
        self._loop: Any = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run,
            name="WebProxy",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "[채널] web_proxy   ON  (port=%d, mail_hosts=%d)",
            self._port,
            len(self._inspect_domains),
        )

    def stop(self) -> None:
        if self._master is not None:
            try:
                if self._loop and self._loop.is_running():
                    self._loop.call_soon_threadsafe(self._master.shutdown)
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("[WebProxy] 중지")

    @staticmethod
    def _allow_host_patterns(domains: list[str]) -> list[str]:
        """mitmproxy allow_hosts 용 정규식.

        mitmproxy는 allow_hosts 패턴을 'host:port' 문자열 전체에 대해
        re.search() 로 매칭한다. $ 앵커를 쓰면 :443 때문에 미매칭 발생.
        → 서브도메인 포함 도메인만 매칭하도록 lookahead 없이 구성.
        """
        patterns: list[str] = []
        for d in domains:
            esc = re.escape(d)
            # (subdomain.)domain.com(:port)? — re.search 기준
            patterns.append(rf"(?:^|\.){esc}(?::\d+)?$")
        return patterns

    # ── 내부 ─────────────────────────────────────────────────────────────────

    def _run(self) -> None:
        try:
            from mitmproxy.options import Options
            from mitmproxy.tools.dump import DumpMaster
        except ImportError:
            logger.error(
                "[WebProxy] mitmproxy가 설치되지 않았습니다.\n"
                "  pip install mitmproxy"
            )
            return

        # mitmproxy 자체 connect 로그 억제 — 메일 전송 로그만 노출
        logging.getLogger("mitmproxy").setLevel(logging.WARNING)
        logging.getLogger("mitmproxy.proxy").setLevel(logging.WARNING)
        logging.getLogger("mitmproxy.proxy.server").setLevel(logging.WARNING)
        logging.getLogger("mitmproxy.proxy.mode_servers").setLevel(logging.INFO)

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        allow = self._allow_host_patterns(self._inspect_domains)
        opts_kwargs: dict[str, Any] = {
            "listen_host": "127.0.0.1",
            "listen_port": self._port,
            "ssl_insecure": False,
        }
        # 메일 호스트만 TLS 가로채기. 그 외는 터널 통과 (복호화·로그 없음)
        if allow:
            opts_kwargs["allow_hosts"] = allow

        opts = Options(**opts_kwargs)

        self._master = DumpMaster(
            opts,
            loop=self._loop,
            with_termlog=False,
            with_dumper=False,
        )
        self._master.addons.add(self._addon)

        if allow:
            logger.info(
                "[WebProxy] TLS inspect limited to %d mail host pattern(s)",
                len(allow),
            )

        try:
            self._loop.run_until_complete(self._master.run())
        except Exception:
            logger.exception("[WebProxy] mitmproxy 실행 오류")
        finally:
            try:
                self._loop.run_until_complete(self._loop.shutdown_asyncgens())
            except Exception:
                pass
            self._loop.close()
