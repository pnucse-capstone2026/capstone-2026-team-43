"""payload_builder + api_client mock 모드 단위 테스트."""

import pytest

from core_comm.api_client import ApiClient
from core_comm.payload_builder import (
    AnalysisPayload,
    AnalysisResult,
    PayloadBuilder,
    ResponseParser,
    _mask_value,
)


# ── 마스킹 ────────────────────────────────────────────────────────────────────

class TestMaskValue:
    def test_rrn_hides_last_six_digits(self):
        """주민번호 뒷 6자리를 마스킹한다."""
        masked = _mask_value("900101-1234567", "rrn")
        assert masked.startswith("900101-1")
        assert "█" in masked
        assert "234567" not in masked

    def test_credit_card_hides_middle(self):
        """카드번호 중간 8자리를 마스킹한다."""
        masked = _mask_value("4532-1234-5678-9012", "credit_card")
        assert masked.startswith("4532")
        assert masked.endswith("9012")
        assert "1234" not in masked or "5678" not in masked

    def test_api_key_keeps_prefix(self):
        masked = _mask_value("sk-abcdefghijklmnopqrstuvwxyz1234567", "api_key_openai")
        assert masked.startswith("sk-abc")
        assert "█" in masked

    def test_email_hides_local_part(self):
        masked = _mask_value("user@example.com", "email")
        # 앞 2자 보존 후 나머지 마스킹
        assert masked.startswith("us")
        assert "█" in masked

    def test_short_value_still_masks(self):
        masked = _mask_value("12", "rrn")
        # 너무 짧아도 crash 없이 처리
        assert isinstance(masked, str)


# ── 스니펫 추출 ───────────────────────────────────────────────────────────────

HITS_RRN = [{"id": "rrn", "name": "주민등록번호", "regex": r"(?<!\d)\d{6}-[1-4]\d{6}(?!\d)", "severity": "critical"}]
HITS_PHONE = [{"id": "phone_mobile", "name": "휴대폰번호", "regex": r"01[016789][\s\-]?\d{3,4}[\s\-]?\d{4}", "severity": "medium"}]
HITS_MIXED = HITS_RRN + HITS_PHONE


class TestPayloadBuilder:
    def setup_method(self):
        self.builder = PayloadBuilder(context_chars=50, max_per_pattern=2)

    def _build(self, text, hits, channel="clipboard", process="slack.exe"):
        return self.builder.build(text, hits, channel, process)

    def test_basic_fields_present(self):
        payload = self._build("홍길동 900101-1234567입니다", HITS_RRN)
        assert payload.request_id
        assert payload.timestamp
        assert payload.channel == "clipboard"
        assert payload.process == "slack.exe"

    def test_snippet_extracted(self):
        payload = self._build("텍스트 900101-1234567 끝", HITS_RRN)
        assert len(payload.snippets) == 1
        s = payload.snippets[0]
        assert s.pattern_id == "rrn"
        assert s.severity == "critical"
        assert "█" in s.match_masked
        assert "█" in s.context

    def test_no_snippet_when_no_hit(self):
        payload = self._build("민감하지 않은 텍스트입니다", HITS_RRN)
        assert payload.snippets == []

    def test_max_per_pattern_respected(self):
        # 같은 패턴 3번 → max_per_pattern=2 이므로 2개만
        text = "900101-1234567 홍 800202-2345678 이 750303-3456789 박"
        payload = self._build(text, HITS_RRN)
        assert len(payload.snippets) <= 2

    def test_severity_ordering(self):
        # critical(rrn)이 medium(phone)보다 앞에 나와야 한다
        text = "010-1234-5678 그리고 900101-1234567"
        payload = self._build(text, HITS_MIXED)
        assert payload.snippets[0].pattern_id == "rrn"

    def test_metadata_contains_expected_keys(self):
        payload = self._build("900101-1234567", HITS_RRN)
        meta = payload.metadata
        assert "hostname" in meta
        assert "total_text_len" in meta
        assert "total_hits" in meta
        assert "max_severity" in meta
        assert "pattern_ids" in meta
        assert "text_hash" in meta

    def test_metadata_max_severity_critical(self):
        payload = self._build("900101-1234567", HITS_RRN)
        assert payload.metadata["max_severity"] == "critical"

    def test_metadata_max_severity_medium(self):
        payload = self._build("010-1234-5678", HITS_PHONE)
        assert payload.metadata["max_severity"] == "medium"

    def test_to_dict_serializable(self):
        import json
        payload = self._build("900101-1234567", HITS_RRN)
        d = payload.to_dict()
        dumped = json.dumps(d)  # JSON 직렬화 검증
        assert "request_id" in dumped
        assert "snippets" in dumped

    def test_context_chars_limits_snippet_length(self):
        long_text = "A" * 1000 + " 900101-1234567 " + "B" * 1000
        builder_narrow = PayloadBuilder(context_chars=10, max_per_pattern=1)
        payload = builder_narrow.build(long_text, HITS_RRN, "clipboard", "test.exe")
        ctx = payload.snippets[0].context
        # context_chars=10 → 매칭 전후 10자씩 + 마스킹 길이
        assert len(ctx) < 100  # 1000자보다 훨씬 짧아야 함


# ── ResponseParser ─────────────────────────────────────────────────────────────

class TestResponseParser:
    def test_parse_block(self):
        raw = {"request_id": "abc", "risk_score": 95, "action": "block", "is_sensitive": True, "reason": "테스트"}
        result = ResponseParser.parse(raw)
        assert result.should_block
        assert result.risk_score == 95.0

    def test_parse_allow(self):
        raw = {"action": "allow", "risk_score": 10, "is_sensitive": False}
        result = ResponseParser.parse(raw, "req-1")
        assert result.action == "allow"
        assert not result.should_block

    def test_parse_review(self):
        raw = {"action": "review", "risk_score": 45, "is_sensitive": False}
        result = ResponseParser.parse(raw)
        assert result.needs_review

    def test_invalid_action_defaults_to_block(self):
        raw = {"action": "unknown_value", "risk_score": 50, "is_sensitive": True}
        result = ResponseParser.parse(raw)
        assert result.action == "block"


# ── ApiClient mock 모드 ────────────────────────────────────────────────────────

class TestApiClientMock:
    def setup_method(self):
        self.client  = ApiClient(base_url="")   # mock 모드
        self.builder = PayloadBuilder()
        assert self.client.is_mock

    def _payload(self, text, hits, channel="clipboard", process="test.exe"):
        return self.builder.build(text, hits, channel, process)

    def test_critical_returns_block(self):
        payload = self._payload("900101-1234567", HITS_RRN)
        result  = self.client.analyze(payload)
        assert result.should_block
        assert result.risk_score >= 90

    def test_medium_returns_review(self):
        payload = self._payload("010-1234-5678", HITS_PHONE)
        result  = self.client.analyze(payload)
        assert result.action == "review"
        assert 40 <= result.risk_score <= 60

    def test_high_severity_returns_block(self):
        hits_high = [{"id": "passport_kr", "name": "여권번호",
                      "regex": r"(?<![A-Z0-9])[A-Z]{1,2}[0-9]{7,8}(?![A-Z0-9])",
                      "severity": "high"}]
        payload = self._payload("여권번호: M12345678", hits_high)
        result  = self.client.analyze(payload)
        assert result.should_block
        assert result.risk_score >= 70

    def test_result_has_reason(self):
        payload = self._payload("900101-1234567", HITS_RRN)
        result  = self.client.analyze(payload)
        assert result.reason  # 빈 문자열이 아님

    def test_result_request_id_matches_payload(self):
        payload = self._payload("900101-1234567", HITS_RRN)
        result  = self.client.analyze(payload)
        assert result.request_id == payload.request_id
