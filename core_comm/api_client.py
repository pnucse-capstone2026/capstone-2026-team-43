"""AI 분석 서버 클라이언트.

운영 모드 (ai_base_url 설정 시)
  AnalysisPayload → POST /api/v1/analyze → AnalysisResult

Mock 모드 (ai_base_url = "" 또는 미설정 시)
  severity 기반 규칙으로 즉시 AnalysisResult 반환
  실제 AI 서버 없이도 파이프라인 전체를 테스트할 수 있다.

Mock 판단 기준
--------------
  critical 패턴 있음 → block  (risk_score 95)
  high 패턴만 있음   → block  (risk_score 75)
  medium만 있음      → review (risk_score 45)  ← AI가 최종 판단할 영역
"""

import logging
from typing import Any, Optional

import requests

from core_comm.payload_builder import AnalysisPayload, AnalysisResult, ResponseParser

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def _mock_result(payload: AnalysisPayload) -> AnalysisResult:
    """AI 서버 없이 severity만으로 즉시 판단하는 mock."""
    max_sev = payload.metadata.get("max_severity", "medium")
    rank = _SEVERITY_RANK.get(max_sev, 1)

    if rank >= 3:          # critical
        return AnalysisResult(
            request_id=payload.request_id,
            risk_score=95.0,
            action="block",
            is_sensitive=True,
            reason=f"[mock] critical 패턴 탐지 ({payload.metadata.get('pattern_ids')})",
        )
    elif rank == 2:        # high
        return AnalysisResult(
            request_id=payload.request_id,
            risk_score=75.0,
            action="block",
            is_sensitive=True,
            reason=f"[mock] high 패턴 탐지 ({payload.metadata.get('pattern_ids')})",
        )
    else:                  # medium / low
        return AnalysisResult(
            request_id=payload.request_id,
            risk_score=45.0,
            action="review",
            is_sensitive=False,
            reason=f"[mock] medium 패턴 탐지 — AI 검토 필요 ({payload.metadata.get('pattern_ids')})",
        )


class ApiClient:
    """AnalysisPayload를 AI 서버로 전송하고 AnalysisResult를 반환한다."""

    def __init__(
        self,
        base_url: str = "",
        timeout: float = 10.0,
    ) -> None:
        self._base_url = base_url.rstrip("/") if base_url else ""
        self._timeout  = timeout
        self._mock     = not bool(self._base_url)

        if self._mock:
            logger.info("ApiClient: AI 서버 URL 없음 → mock 모드")
        else:
            logger.info("ApiClient: AI 서버 → %s", self._base_url)

    @property
    def is_mock(self) -> bool:
        return self._mock

    def analyze(self, payload: AnalysisPayload) -> AnalysisResult:
        """페이로드를 분석하고 결과를 반환한다. mock 모드면 즉시 반환."""
        if self._mock:
            result = _mock_result(payload)
            logger.debug(
                "Mock 분석 결과: action=%s risk=%.0f reason=%s",
                result.action, result.risk_score, result.reason,
            )
            return result

        return self._call_server(payload)

    def _call_server(self, payload: AnalysisPayload) -> AnalysisResult:
        url = f"{self._base_url}/api/v1/analyze"
        logger.debug("AI 서버 요청 → %s (request_id=%s)", url, payload.request_id)

        try:
            resp = requests.post(
                url,
                json=payload.to_dict(),
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return ResponseParser.parse(resp.json(), payload.request_id)
        except requests.Timeout:
            logger.error("AI 서버 타임아웃 (%.1fs) — 보수적으로 block 처리", self._timeout)
            return AnalysisResult(
                request_id=payload.request_id,
                risk_score=100.0,
                action="block",
                is_sensitive=True,
                reason="AI 서버 타임아웃 — 보수적 차단",
            )
        except Exception as exc:
            logger.error("AI 서버 오류: %s — block 처리", exc)
            return AnalysisResult(
                request_id=payload.request_id,
                risk_score=100.0,
                action="block",
                is_sensitive=True,
                reason=f"AI 서버 오류: {exc}",
            )
