"""payload_builder + api_client mock 모드 단위 테스트."""

from core_comm.api_client import ApiClient
from core_comm.payload_builder import PayloadBuilder, ResponseParser


HITS_RRN = [{"id": "rrn", "name": "주민등록번호", "regex": r"(?<!\d)\d{6}-[1-4]\d{6}(?!\d)", "severity": "critical"}]
HITS_PHONE = [{"id": "phone_mobile", "name": "휴대폰번호", "regex": r"01[016789][\s\-]?\d{3,4}[\s\-]?\d{4}", "severity": "medium"}]
HITS_MIXED = HITS_RRN + HITS_PHONE


class TestPayloadBuilder:
    def setup_method(self):
        self.builder = PayloadBuilder()

    def _build(self, text, hits, channel="clipboard", process="slack.exe"):
        return self.builder.build(text, hits, channel, process)

    def test_basic_fields_present(self):
        payload = self._build("홍길동 900101-1234567입니다", HITS_RRN)
        assert payload.request_id
        assert payload.timestamp
        assert payload.channel == "clipboard"
        assert payload.process == "slack.exe"

    def test_full_text_unmasked(self):
        """원문 전체가 마스킹 없이 담겨야 한다."""
        text = "텍스트 900101-1234567 끝"
        payload = self._build(text, HITS_RRN)
        assert payload.text == text
        assert "█" not in payload.text
        assert "900101-1234567" in payload.text

    def test_matched_patterns_include_raw_match(self):
        payload = self._build("텍스트 900101-1234567 끝", HITS_RRN)
        assert len(payload.matched_patterns) == 1
        m = payload.matched_patterns[0]
        assert m.pattern_id == "rrn"
        assert m.severity == "critical"
        assert m.match == "900101-1234567"
        assert "█" not in m.match
        assert payload.text[m.start:m.end] == m.match

    def test_no_match_when_regex_misses(self):
        payload = self._build("민감하지 않은 텍스트입니다", HITS_RRN)
        assert payload.matched_patterns == []
        assert payload.text == "민감하지 않은 텍스트입니다"

    def test_severity_ordering(self):
        text = "010-1234-5678 그리고 900101-1234567"
        payload = self._build(text, HITS_MIXED)
        assert payload.matched_patterns[0].pattern_id == "rrn"

    def test_metadata_contains_expected_keys(self):
        payload = self._build("900101-1234567", HITS_RRN)
        meta = payload.metadata
        assert "hostname" in meta
        assert "total_text_len" in meta
        assert "sent_text_len" in meta
        assert "truncated" in meta
        assert "total_hits" in meta
        assert "max_severity" in meta
        assert "pattern_ids" in meta
        assert "text_hash" in meta
        assert meta["truncated"] is False

    def test_metadata_max_severity_critical(self):
        payload = self._build("900101-1234567", HITS_RRN)
        assert payload.metadata["max_severity"] == "critical"

    def test_metadata_max_severity_medium(self):
        payload = self._build("010-1234-5678", HITS_PHONE)
        assert payload.metadata["max_severity"] == "medium"

    def test_to_dict_has_text_not_snippets(self):
        import json
        text = "원문 900101-1234567"
        payload = self._build(text, HITS_RRN)
        d = payload.to_dict()
        dumped = json.dumps(d, ensure_ascii=False)
        assert "request_id" in dumped
        assert "text" in d
        assert d["text"] == text
        assert "snippets" not in d
        assert "matched_patterns" in d
        assert d["matched_patterns"][0]["match"] == "900101-1234567"

    def test_optional_truncate(self):
        long_text = "A" * 100 + " 900101-1234567"
        builder = PayloadBuilder(max_text_chars=50)
        payload = builder.build(long_text, HITS_RRN, "clipboard", "test.exe")
        assert len(payload.text) == 50
        assert payload.metadata["truncated"] is True
        assert payload.metadata["total_text_len"] == len(long_text)


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


class TestApiClientMock:
    def setup_method(self):
        self.client  = ApiClient(base_url="")
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
        assert result.reason

    def test_result_request_id_matches_payload(self):
        payload = self._payload("900101-1234567", HITS_RRN)
        result  = self.client.analyze(payload)
        assert result.request_id == payload.request_id
