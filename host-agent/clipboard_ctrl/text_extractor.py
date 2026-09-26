"""Extract and normalize plain text from clipboard data."""

import logging
import re
from typing import Optional

import win32clipboard
import win32con

logger = logging.getLogger(__name__)

# Registered clipboard format for HTML (set by browsers, Office, etc.)
_CF_HTML: int = win32clipboard.RegisterClipboardFormat("HTML Format")


class TextExtractor:
    """Reads clipboard contents and returns cleaned plain text."""

    @staticmethod
    def extract() -> Optional[str]:
        """Return clipboard text (Unicode preferred, HTML fallback).

        Returns None when the clipboard holds no text-extractable data
        (e.g. an image or is empty).
        """
        try:
            win32clipboard.OpenClipboard()
            try:
                # Priority 1: plain Unicode text
                if win32clipboard.IsClipboardFormatAvailable(win32con.CF_UNICODETEXT):
                    return win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)

                # Priority 2: HTML (browser copy, rich text from Office)
                if win32clipboard.IsClipboardFormatAvailable(_CF_HTML):
                    raw = win32clipboard.GetClipboardData(_CF_HTML)
                    html = raw.decode("utf-8", errors="ignore") if isinstance(raw, bytes) else raw
                    return TextExtractor._strip_html(html)

            finally:
                win32clipboard.CloseClipboard()

        except Exception as exc:
            logger.debug("Clipboard read failed: %s", exc)

        return None

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _strip_html(html: str) -> str:
        """Remove HTML markup and decode common entities."""
        # Extract the actual HTML body from the CF_HTML header block
        body_match = re.search(r"<body[^>]*>(.*?)</body>", html, re.DOTALL | re.IGNORECASE)
        content = body_match.group(1) if body_match else html

        # Remove script / style blocks entirely
        content = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", content, flags=re.DOTALL | re.IGNORECASE)
        # Strip remaining tags
        content = re.sub(r"<[^>]+>", " ", content)
        # Decode common HTML entities
        for entity, char in (
            ("&nbsp;", " "), ("&lt;", "<"), ("&gt;", ">"),
            ("&amp;", "&"), ("&quot;", '"'), ("&#39;", "'"),
        ):
            content = content.replace(entity, char)
        return content

    @staticmethod
    def normalize(text: str) -> str:
        """Collapse excessive whitespace and strip stray control characters."""
        # Remove null bytes and other non-printable control chars (keep newlines/tabs)
        text = re.sub(r"[^\S\n\t ]+", " ", text)
        lines = text.splitlines()
        cleaned = "\n".join(line.strip() for line in lines)
        # Collapse 3+ consecutive blank lines into one
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
        return cleaned.strip()
