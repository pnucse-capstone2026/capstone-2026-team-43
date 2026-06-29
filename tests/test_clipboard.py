"""Unit tests for clipboard_ctrl modules."""

import json
import tempfile
from pathlib import Path

import pytest

from clipboard_ctrl.paste_inspector import PasteInspector
from clipboard_ctrl.rule_filter import RuleFilter
from clipboard_ctrl.text_extractor import TextExtractor

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PATTERNS_PATH = PROJECT_ROOT / "config" / "regex_patterns.json"
POLICY_PATH = PROJECT_ROOT / "config" / "paste_policy.json"


# ── TextExtractor ─────────────────────────────────────────────────────────────

class TestTextExtractor:
    def test_normalize_strips_whitespace(self) -> None:
        assert TextExtractor.normalize("  hello   \n\n\n  world  ") == "hello\n\nworld"

    def test_normalize_collapses_blank_lines(self) -> None:
        text = "a\n\n\n\n\nb"
        assert TextExtractor.normalize(text) == "a\n\nb"

    def test_strip_html_removes_tags(self) -> None:
        html = "<b>주민번호:</b> 900101-1234567"
        result = TextExtractor._strip_html(html)
        assert "<b>" not in result
        assert "주민번호:" in result
        assert "900101-1234567" in result

    def test_strip_html_decodes_entities(self) -> None:
        html = "a &lt; b &amp; c"
        assert "a < b & c" in TextExtractor._strip_html(html)


# ── RuleFilter ────────────────────────────────────────────────────────────────

class TestRuleFilter:
    @pytest.fixture
    def rf(self) -> RuleFilter:
        return RuleFilter(PATTERNS_PATH)

    def test_patterns_file_loads(self, rf: RuleFilter) -> None:
        with PATTERNS_PATH.open(encoding="utf-8") as f:
            data = json.load(f)
        assert len(data["patterns"]) > 0

    def test_detects_resident_number(self, rf: RuleFilter) -> None:
        assert rf.is_suspicious("주민번호: 900101-1234567")

    def test_detects_credit_card(self, rf: RuleFilter) -> None:
        assert rf.is_suspicious("카드번호 4532-1234-5678-9012")

    def test_detects_phone_number(self, rf: RuleFilter) -> None:
        assert rf.is_suspicious("연락처: 010-1234-5678")

    def test_detects_email(self, rf: RuleFilter) -> None:
        assert rf.is_suspicious("이메일: test@example.com")

    def test_detects_openai_api_key(self, rf: RuleFilter) -> None:
        fake_key = "sk-" + "a" * 48
        assert rf.is_suspicious(f"API_KEY={fake_key}")

    def test_detects_aws_key(self, rf: RuleFilter) -> None:
        assert rf.is_suspicious("AKIAIOSFODNN7EXAMPLE")

    def test_detects_private_key_header(self, rf: RuleFilter) -> None:
        assert rf.is_suspicious("-----BEGIN RSA PRIVATE KEY-----")

    def test_clean_text_no_match(self, rf: RuleFilter) -> None:
        assert not rf.is_suspicious("오늘 점심 뭐 먹을까요? 회의는 3시입니다.")

    def test_returns_hit_details(self, rf: RuleFilter) -> None:
        hits = rf.match("900101-1234567")
        assert hits
        hit_ids = [h["id"] for h in hits]
        assert "rrn" in hit_ids


# ── PasteInspector ────────────────────────────────────────────────────────────

class _TmpPolicy:
    """Context manager that writes a temporary policy file."""

    def __init__(self, policy: dict) -> None:
        self._policy = policy
        self._tmpdir = tempfile.TemporaryDirectory()

    def __enter__(self) -> Path:
        path = Path(self._tmpdir.name) / "paste_policy.json"
        path.write_text(json.dumps(self._policy), encoding="utf-8")
        return path

    def __exit__(self, *_) -> None:
        self._tmpdir.cleanup()


class TestPasteInspector:
    _POLICY = {
        "inspect_list": ["slack.exe", "chrome.exe", "discord.exe"],
        "allowlist": ["excel.exe", "winword.exe"],
        "default_action": "allow",
    }

    @pytest.fixture
    def inspector(self) -> PasteInspector:
        with _TmpPolicy(self._POLICY) as p:
            return PasteInspector(p)

    def test_inspect_list_returns_true(self, inspector: PasteInspector) -> None:
        assert inspector.should_inspect("slack.exe") is True
        assert inspector.should_inspect("Chrome.EXE") is True   # case-insensitive

    def test_allowlist_returns_false(self, inspector: PasteInspector) -> None:
        assert inspector.should_inspect("excel.exe") is False
        assert inspector.should_inspect("WINWORD.EXE") is False

    def test_unknown_default_allow(self, inspector: PasteInspector) -> None:
        assert inspector.should_inspect("notepad.exe") is False

    def test_unknown_default_inspect(self) -> None:
        policy = dict(self._POLICY)
        policy["default_action"] = "inspect"
        with _TmpPolicy(policy) as p:
            ins = PasteInspector(p)
        assert ins.should_inspect("notepad.exe") is True

    def test_real_policy_file_loads(self) -> None:
        inspector = PasteInspector(POLICY_PATH)
        assert inspector.should_inspect("slack.exe") is True
        assert inspector.should_inspect("excel.exe") is False
