"""AI 분석 서버 전송용 페이로드 정제 모듈.

설계 원칙
---------
1. 전체 텍스트 대신 매칭 구간 ±context_chars 스니펫만 전송 → 토큰·비용 절감
2. 스니펫에서 실제 민감값은 부분 마스킹 → AI 서버에도 PII 최소화
3. 동일 패턴이 여러 번 매칭돼도 패턴당 최대 N개 스니펫만 포함 → 중복 제거
4. severity 기준 내림차순 정렬 → AI가 중요한 것을 먼저 판단

AI Request 포맷
--------------
{
  "request_id": "<uuid>",
  "timestamp": "<ISO 8601 UTC>",
  "channel": "clipboard|outlook|smtp|http",
  "process": "slack.exe",
  "snippets": [
    {
      "pattern_id": "rrn",
      "pattern_name": "주민등록번호",
      "severity": "critical",
      "context": "...앞뒤 문맥...900101-1██████...앞뒤 문맥...",
      "match_masked": "900101-1██████"
    }
  ],
  "metadata": {
    "hostname": "PC-001",
    "total_text_len": 1234,
    "total_hits": 3,
    "max_severity": "critical",
    "pattern_ids": ["rrn", "phone_mobile"]
  }
}

AI Response 포맷 (기대값)
-------------------------
{
  "request_id": "<uuid>",
  "risk_score": 85,          // 0–100
  "action": "block",         // "allow" | "block" | "review"
  "is_sensitive": true,
  "reason": "주민등록번호 패턴이 유효한 형식으로 확인됨"
}
"""

import hashlib
import re
import socket
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

_HOSTNAME = socket.gethostname()

# severity 우선순위 (높을수록 먼저)
_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}

# 패턴별 마스킹 규칙: (보존 앞 자리 수, 보존 뒤 자리 수)
# 나머지는 '█'로 치환한다.
_MASK_RULES: dict[str, tuple[int, int]] = {
    "rrn":                  (7, 1),   # 900101-1██████
    "foreign_rrn":          (7, 1),
    "credit_card":          (4, 4),   # 4532-████-████-9012
    "bank_account":         (4, 0),   # 110-████
    "phone_mobile":         (3, 4),   # 010-████-5678
    "phone_landline":       (2, 4),
    "email":                (2, 0),   # us██@...
    "passport_kr":          (2, 0),
    "driver_license_kr":    (4, 0),
    "business_registration":(5, 0),
    "api_key_openai":       (6, 0),   # sk-abc████
    "api_key_anthropic":    (10, 0),
    "api_key_aws_access":   (6, 0),
    "api_key_aws_secret":   (6, 0),
    "github_token":         (7, 0),
    "bearer_token":         (10, 0),
    "private_key_header":   (20, 0),
    "connection_string":    (15, 0),  # postgresql://us████
}

_DEFAULT_MASK = (4, 0)


# ── 데이터 클래스 ─────────────────────────────────────────────────────────────

@dataclass
class Snippet:
    pattern_id: str
    pattern_name: str
    severity: str
    context: str        # 매칭 구간 ±context_chars (원문, 마스킹 적용)
    match_masked: str   # 매칭 문자열 마스킹 버전


@dataclass
class AnalysisPayload:
    request_id: str
    timestamp: str
    channel: str
    process: str
    snippets: list[Snippet]
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "channel": self.channel,
            "process": self.process,
            "snippets": [
                {
                    "pattern_id": s.pattern_id,
                    "pattern_name": s.pattern_name,
                    "severity": s.severity,
                    "context": s.context,
                    "match_masked": s.match_masked,
                }
                for s in self.snippets
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


# ── 마스킹 ────────────────────────────────────────────────────────────────────

def _mask_value(value: str, pattern_id: str) -> str:
    """민감값을 부분 마스킹한다."""
    keep_front, keep_back = _MASK_RULES.get(pattern_id, _DEFAULT_MASK)
    # 알파벳·숫자·구분자 제외한 의미 있는 문자 수 기준으로 마스킹
    visible = re.sub(r"[\s\-_/]", "", value)   # 공백·구분자 제거한 순수 값
    total = len(visible)

    if total <= keep_front + keep_back:
        # 너무 짧으면 뒷부분만 마스킹
        return value[:max(1, keep_front)] + "█" * max(0, total - keep_front)

    # 원본 문자열에서 앞/뒤 보존 위치 찾기 (구분자 포함 유지)
    front_count = 0
    front_idx = 0
    for i, ch in enumerate(value):
        if ch not in " -_/":
            front_count += 1
        if front_count == keep_front:
            front_idx = i + 1
            break

    if keep_back == 0:
        masked_len = total - keep_front
        return value[:front_idx] + "█" * masked_len
    else:
        back_count = 0
        back_idx = len(value)
        for i in range(len(value) - 1, -1, -1):
            if value[i] not in " -_/":
                back_count += 1
            if back_count == keep_back:
                back_idx = i
                break
        masked_len = total - keep_front - keep_back
        return value[:front_idx] + "█" * masked_len + value[back_idx:]


# ── 스니펫 추출 ───────────────────────────────────────────────────────────────

def _extract_snippets(
    text: str,
    hits: list[dict[str, Any]],
    context_chars: int,
    max_per_pattern: int,
) -> list[Snippet]:
    """정규식 히트 목록에서 스니펫을 추출한다."""
    snippets: list[Snippet] = []

    # severity 내림차순 정렬
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

                start   = max(0, m.start() - context_chars)
                end     = min(len(text), m.end() + context_chars)
                raw_ctx = text[start:end]
                masked  = _mask_value(m.group(), pattern_id)

                # 컨텍스트 안에서도 매칭 부분을 마스킹
                ctx_with_mask = raw_ctx[: m.start() - start] + masked + raw_ctx[m.end() - start:]

                snippets.append(Snippet(
                    pattern_id=pattern_id,
                    pattern_name=pattern_name,
                    severity=severity,
                    context=ctx_with_mask,
                    match_masked=masked,
                ))
                count += 1
        except re.error:
            pass

    return snippets


# ── 페이로드 빌더 ─────────────────────────────────────────────────────────────

class PayloadBuilder:
    """탐지 결과를 AI 서버 전송용 AnalysisPayload로 변환한다."""

    def __init__(
        self,
        context_chars: int = 150,
        max_per_pattern: int = 3,
    ) -> None:
        self._context_chars   = context_chars
        self._max_per_pattern = max_per_pattern

    def build(
        self,
        text: str,
        hits: list[dict[str, Any]],
        channel: str,
        process_name: str,
    ) -> AnalysisPayload:
        snippets = _extract_snippets(
            text, hits, self._context_chars, self._max_per_pattern
        )

        severities = [h.get("severity", "medium") for h in hits]
        max_sev = max(severities, key=lambda s: _SEVERITY_RANK.get(s, 1), default="medium")

        return AnalysisPayload(
            request_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            channel=channel,
            process=process_name,
            snippets=snippets,
            metadata={
                "hostname":       _HOSTNAME,
                "total_text_len": len(text),
                "total_hits":     len(hits),
                "max_severity":   max_sev,
                "pattern_ids":    list(dict.fromkeys(h.get("id") for h in hits)),
                "text_hash":      hashlib.sha256(text.encode()).hexdigest()[:16],
            },
        )


# ── 응답 파서 ─────────────────────────────────────────────────────────────────

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
