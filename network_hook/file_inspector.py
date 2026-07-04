"""첨부파일·파일 경로에서 검사용 텍스트를 추출한다.

지원 형식
---------
.txt / .csv / .log / .xml / .json  → 직접 디코딩
.docx                              → python-docx
.pdf                               → PyMuPDF (fitz)
.xlsx / .xls                       → openpyxl
그 외                              → UTF-8 / CP949 decode 시도, 실패 시 None
"""

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# 샘플링 상한 — 파일 전체를 AI에 보내지 않도록 제한한다.
DEFAULT_SAMPLE_BYTES = 32 * 1024   # 32 KB
MAX_PDF_PAGES       = 5            # PDF 처음 N페이지만 추출


class FileInspector:
    """파일 경로 또는 바이너리 바이트에서 텍스트를 추출한다."""

    def __init__(self, sample_bytes: int = DEFAULT_SAMPLE_BYTES) -> None:
        self._sample_bytes = sample_bytes

    # ── Public API ────────────────────────────────────────────────────────────

    def extract_from_path(self, path: Path) -> Optional[str]:
        """파일 경로로 텍스트를 추출한다. 지원되지 않으면 None."""
        suffix = path.suffix.lower()
        try:
            if suffix in {".txt", ".csv", ".log", ".xml", ".json", ".md", ".yaml", ".yml"}:
                return self._read_text(path)
            if suffix == ".docx":
                return self._read_docx(path)
            if suffix == ".pdf":
                return self._read_pdf(path)
            if suffix in {".xlsx", ".xls"}:
                return self._read_xlsx(path)
            return self._try_decode(path.read_bytes())
        except Exception as exc:
            logger.debug("extract_from_path(%s) 실패: %s", path, exc)
            return None

    def extract_from_bytes(self, data: bytes, filename: str) -> Optional[str]:
        """메모리 바이트(첨부파일 등)에서 텍스트를 추출한다."""
        suffix = Path(filename).suffix.lower()
        try:
            if suffix in {".txt", ".csv", ".log", ".xml", ".json", ".md"}:
                return self._try_decode(data)
            if suffix == ".docx":
                return self._read_docx_bytes(data)
            if suffix == ".pdf":
                return self._read_pdf_bytes(data)
            if suffix in {".xlsx", ".xls"}:
                return self._read_xlsx_bytes(data)
            return self._try_decode(data)
        except Exception as exc:
            logger.debug("extract_from_bytes(%s) 실패: %s", filename, exc)
            return None

    # ── 형식별 추출 ───────────────────────────────────────────────────────────

    def _read_text(self, path: Path) -> Optional[str]:
        raw = path.read_bytes()[: self._sample_bytes]
        return self._try_decode(raw)

    def _try_decode(self, data: bytes) -> Optional[str]:
        for enc in ("utf-8-sig", "utf-8", "cp949", "euc-kr", "latin-1"):
            try:
                return data[: self._sample_bytes].decode(enc)
            except UnicodeDecodeError:
                continue
        return None

    def _read_docx(self, path: Path) -> Optional[str]:
        return self._read_docx_bytes(path.read_bytes())

    def _read_docx_bytes(self, data: bytes) -> Optional[str]:
        try:
            import io
            import docx  # python-docx
            doc = docx.Document(io.BytesIO(data))
            parts = [para.text for para in doc.paragraphs if para.text.strip()]
            text = "\n".join(parts)
            return text[: self._sample_bytes]
        except ImportError:
            logger.warning("python-docx 미설치 — pip install python-docx")
            return None

    def _read_pdf(self, path: Path) -> Optional[str]:
        return self._read_pdf_bytes(path.read_bytes())

    def _read_pdf_bytes(self, data: bytes) -> Optional[str]:
        try:
            import fitz  # PyMuPDF
            doc = fitz.open(stream=data, filetype="pdf")
            parts: list[str] = []
            for page_num in range(min(len(doc), MAX_PDF_PAGES)):
                parts.append(doc[page_num].get_text())
            text = "\n".join(parts)
            return text[: self._sample_bytes]
        except ImportError:
            logger.warning("PyMuPDF 미설치 — pip install PyMuPDF")
            return None

    def _read_xlsx(self, path: Path) -> Optional[str]:
        return self._read_xlsx_bytes(path.read_bytes())

    def _read_xlsx_bytes(self, data: bytes) -> Optional[str]:
        try:
            import io
            import openpyxl
            wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
            parts: list[str] = []
            for sheet in wb.worksheets:
                for row in sheet.iter_rows(values_only=True):
                    cells = [str(c) for c in row if c is not None]
                    if cells:
                        parts.append("\t".join(cells))
                if sum(len(p) for p in parts) >= self._sample_bytes:
                    break
            return "\n".join(parts)[: self._sample_bytes]
        except ImportError:
            logger.warning("openpyxl 미설치 — pip install openpyxl")
            return None
