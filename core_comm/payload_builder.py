"""AI 분석 서버 전송용 페이로드 구성 모듈.

설계 원칙
---------
1. 정규식 1차 hit가 난 원문 전체를 AI에 전달 → 문맥 기반 기밀 판별에 필요
2. 마스킹하지 않음 — 마스킹은 문맥 분석 성능을 해침
3. matched_patterns로 1차 게이트 힌트만 부가 제공 (AI가 어디에 주목할지 참고)

AI Request 포맷
--------------
{
  "request_id": "<uuid>",
  "timestamp": "<ISO 8601 UTC>",
  "channel": "clipboard|outlook|smtp|http|usb|network_share",
  "process": "slack.exe",
  "text": "검사 대상 원문 전체 (마스킹 없음)",
  "matched_patterns": [
    {
      "pattern_id": "rrn",
      "pattern_name": "주민등록번호",
      "severity": "critical",
      "match": "900101-1234567",
      "start": 10,
      "end": 24
    }
  ],
  "metadata": {
    "hostname": "PC-001",
    "total_text_len": 1234,
    "total_hits": 1,
    "max_severity": "critical",
    "pattern_ids": ["rrn"],
    "text_hash": "a1b2c3d4e5f67890"
  }
}

AI Response 포맷 (기대값)
-------------------------
{
  "request_id": "<uuid>",
  "risk_score": 85,          // 0–100
  "action": "block",         // "allow" | "block" | "review"
  "is_sensitive": true,
  "reason": "..."
}
"""

import hashlib
import re
import socket
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

_HOSTNAME = socket.gethostname()

_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}

# 너무 긴 텍스트(예: 대용량 파일 전체)는 전송·추론 한도 보호용으로 자를 수 있다.
# 0 이하면 제한 없음.
DEFAULT_MAX_TEXT_CHARS = 0


@dataclass
class PatternMatch:
    """정규식 hit 위치 정보 — AI에 힌트로 전달 (마스킹 없음)."""
    pattern_id: str
    pattern_name: str
    severity: str
    match: str
    start: int
    end: int


@dataclass
class AnalysisPayload:
    request_id: str
    timestamp: str
    channel: str
    process: str
    text: str
    matched_patterns: list[PatternMatch]
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "channel": self.channel,
            "process": self.process,
            "text": self.text,
            "matched_patterns": [
                {
                    "pattern_id": m.pattern_id,
                    "pattern_name": m.pattern_name,
                    "severity": m.severity,
                    "match": m.match,
                    "start": m.start,
                    "end": m.end,
                }
                for m in self.matched_patterns
            ],
            "metadata": self.metadata,
        }


@dataclass
class AnalysisResult:
    request_id: str
    risk_score: float           # 0–100
    action: str                 # "allow" | "block" | "review"
    is_sensitive: bool
    reason: str = ""

    @property
    def should_block(self) -> bool:
        return self.action == "block"

    @property
    def needs_review(self) -> bool:
        return self.action == "review"


def _collect_matches(
    text: str,
    hits: list[dict[str, Any]],
    max_per_pattern: int = 10,
) -> list[PatternMatch]:
    """정규식 hit 위치·원문 매칭 문자열을 수집 (마스킹 없음)."""
    matches: list[PatternMatch] = []

    sorted_hits = sorted(
        hits,
        key=lambda h: _SEVERITY_RANK.get(h.get("severity", "medium"), 1),
        reverse=True,
    )

    for hit in sorted_hits:
        pattern_id   = hit.get("id", "unknown")
        pattern_name = hit.get("name", "알 수 없음")
        severity     = hit.get("severity", "medium")
        regex        = hit.get("regex", "")
        if not regex:
            continue

        count = 0
        try:
            for m in re.finditer(regex, text):
                if count >= max_per_pattern:
                    break
                matches.append(PatternMatch(
                    pattern_id=pattern_id,
                    pattern_name=pattern_name,
                    severity=severity,
                    match=m.group(),
                    start=m.start(),
                    end=m.end(),
                ))
                count += 1
        except re.error:
            pass

    return matches


class PayloadBuilder:
    """탐지 결과를 AI 서버 전송용 AnalysisPayload로 변환한다.

    원문 전체를 마스킹 없이 담는다. matched_patterns는 1차 Rule 힌트이다.
    """

    def __init__(
        self,
        max_text_chars: int = DEFAULT_MAX_TEXT_CHARS,
        max_per_pattern: int = 10,
    ) -> None:
        self._max_text_chars  = max_text_chars
        self._max_per_pattern = max_per_pattern

    def build(
        self,
        text: str,
        hits: list[dict[str, Any]],
        channel: str,
        process_name: str,
    ) -> AnalysisPayload:
        body = text
        truncated = False
        if self._max_text_chars and len(body) > self._max_text_chars:
            body = body[: self._max_text_chars]
            truncated = True

        matches = _collect_matches(body, hits, self._max_per_pattern)

        severities = [h.get("severity", "medium") for h in hits]
        max_sev = max(severities, key=lambda s: _SEVERITY_RANK.get(s, 1), default="medium")

        return AnalysisPayload(
            request_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            channel=channel,
            process=process_name,
            text=body,
            matched_patterns=matches,
            metadata={
                "hostname":       _HOSTNAME,
                "total_text_len": len(text),
                "sent_text_len":  len(body),
                "truncated":     truncated,
                "total_hits":     len(hits),
                "max_severity":   max_sev,
                "pattern_ids":    list(dict.fromkeys(h.get("id") for h in hits)),
                "text_hash":      hashlib.sha256(text.encode()).hexdigest()[:16],
            },
        )


class ResponseParser:
    """AI 서버 응답 dict를 AnalysisResult로 변환한다."""

    @staticmethod
    def parse(raw: dict[str, Any], request_id: str = "") -> AnalysisResult:
        action = raw.get("action", "block").lower()
        if action not in {"allow", "block", "review"}:
            action = "block"

        return AnalysisResult(
            request_id=raw.get("request_id", request_id),
            risk_score=float(raw.get("risk_score", 100)),
            action=action,
            is_sensitive=bool(raw.get("is_sensitive", True)),
            reason=raw.get("reason", ""),
        )
