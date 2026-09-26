"""첨부파일·파일 경로에서 검사용 텍스트를 추출한다.

지원 형식
---------
텍스트계열   .txt .csv .log .xml .json .yaml .yml .md .html .htm .rtf
             .py .js .ts .java .c .cpp .h .cs .go .rb .php .sql .sh .bat .ps1
MS Office    .docx .xlsx .xls .pptx
PDF          .pdf
한글(HWP)    .hwp .hwpx  (olefile 기반 부분 지원)
압축파일     .zip         (내부 파일 재귀 검사)
그 외        UTF-8 / CP949 decode 시도, 실패 시 None
"""

import io
import logging
import zipfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_SAMPLE_BYTES = None         # None = 제한 없음 (정규식 검사용 전체 추출)
MAX_PDF_PAGES        = None         # None = 전체 페이지
MAX_ZIP_FILES        = 50          # zip 내 최대 검사 파일 수

# 텍스트로 직접 읽는 확장자
_TEXT_SUFFIXES = {
    ".txt", ".csv", ".log", ".xml", ".json", ".yaml", ".yml", ".md",
    ".html", ".htm",
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".c", ".cpp", ".h", ".cs", ".go", ".rb", ".php",
    ".sql", ".sh", ".bat", ".ps1", ".env",
}


class FileInspector:
    """파일 경로 또는 바이너리 바이트에서 텍스트를 추출한다."""

    def __init__(self, sample_bytes: Optional[int] = DEFAULT_SAMPLE_BYTES) -> None:
        self._sample_bytes = sample_bytes  # None = 무제한

    def _cap(self, text: str) -> str:
        """sample_bytes 제한 적용. None이면 전체 반환."""
        if self._sample_bytes is None or len(text) <= self._sample_bytes:
            return text
        return text[: self._sample_bytes]

    def _cap_bytes(self, data: bytes) -> bytes:
        if self._sample_bytes is None or len(data) <= self._sample_bytes:
            return data
        return data[: self._sample_bytes]

    # ── Public API ────────────────────────────────────────────────────────────

    def extract_from_path(self, path: Path) -> Optional[str]:
        """파일 경로로 텍스트를 추출한다. 지원되지 않으면 None."""
        suffix = path.suffix.lower()
        try:
            if suffix in _TEXT_SUFFIXES:
                return self._read_text(path)
            if suffix == ".rtf":
                return self._read_rtf_bytes(path.read_bytes())
            if suffix == ".docx":
                return self._read_docx_bytes(path.read_bytes())
            if suffix == ".pdf":
                return self._read_pdf_bytes(path.read_bytes())
            if suffix in {".xlsx", ".xls"}:
                return self._read_xlsx_bytes(path.read_bytes())
            if suffix == ".pptx":
                return self._read_pptx_bytes(path.read_bytes())
            if suffix in {".hwp", ".hwpx"}:
                return self._read_hwp_bytes(path.read_bytes(), suffix)
            if suffix == ".zip":
                return self._read_zip_bytes(path.read_bytes())
            return self._try_decode(path.read_bytes())
        except Exception as exc:
            logger.debug("extract_from_path(%s) 실패: %s", path, exc)
            return None

    def extract_from_bytes(self, data: bytes, filename: str) -> Optional[str]:
        """메모리 바이트(첨부파일 등)에서 텍스트를 추출한다."""
        suffix = Path(filename).suffix.lower()
        try:
            if suffix in _TEXT_SUFFIXES:
                return self._try_decode(data)
            if suffix == ".rtf":
                return self._read_rtf_bytes(data)
            if suffix == ".docx":
                return self._read_docx_bytes(data)
            if suffix == ".pdf":
                return self._read_pdf_bytes(data)
            if suffix in {".xlsx", ".xls"}:
                return self._read_xlsx_bytes(data)
            if suffix == ".pptx":
                return self._read_pptx_bytes(data)
            if suffix in {".hwp", ".hwpx"}:
                return self._read_hwp_bytes(data, suffix)
            if suffix == ".zip":
                return self._read_zip_bytes(data)
            return self._try_decode(data)
        except Exception as exc:
            logger.debug("extract_from_bytes(%s) 실패: %s", filename, exc)
            return None

    # ── 텍스트 공통 ───────────────────────────────────────────────────────────

    def _read_text(self, path: Path) -> Optional[str]:
        return self._try_decode(path.read_bytes())

    def _try_decode(self, data: bytes) -> Optional[str]:
        data = self._cap_bytes(data)
        for enc in ("utf-8-sig", "utf-8", "cp949", "euc-kr", "latin-1"):
            try:
                return data.decode(enc)
            except UnicodeDecodeError:
                continue
        return None

    # ── RTF ───────────────────────────────────────────────────────────────────

    def _read_rtf_bytes(self, data: bytes) -> Optional[str]:
        try:
            from striprtf.striprtf import rtf_to_text
            raw = self._cap_bytes(data).decode("utf-8", errors="ignore")
            return self._cap(rtf_to_text(raw))
        except ImportError:
            logger.warning("striprtf 미설치 — pip install striprtf")
            import re
            raw = self._cap_bytes(data).decode("utf-8", errors="ignore")
            text = re.sub(r"\\[a-z]+\d*\s?|[{}]", " ", raw)
            return self._cap(text)
        except Exception as exc:
            logger.debug("RTF 추출 실패: %s", exc)
            return None

    # ── DOCX ──────────────────────────────────────────────────────────────────

    def _read_docx_bytes(self, data: bytes) -> Optional[str]:
        try:
            import docx  # python-docx
            doc = docx.Document(io.BytesIO(data))
            parts = [para.text for para in doc.paragraphs if para.text.strip()]
            for table in doc.tables:
                for row in table.rows:
                    for cell in row.cells:
                        if cell.text.strip():
                            parts.append(cell.text)
            return self._cap("\n".join(parts))
        except ImportError:
            logger.warning("python-docx 미설치 — pip install python-docx")
            return None
        except Exception as exc:
            logger.debug("DOCX 추출 실패: %s", exc)
            return None

    # ── PDF ───────────────────────────────────────────────────────────────────

    def _read_pdf_bytes(self, data: bytes) -> Optional[str]:
        try:
            import fitz  # PyMuPDF
            doc = fitz.open(stream=data, filetype="pdf")
            parts: list[str] = []
            page_limit = len(doc) if MAX_PDF_PAGES is None else min(len(doc), MAX_PDF_PAGES)
            for page_num in range(page_limit):
                parts.append(doc[page_num].get_text())
            return self._cap("\n".join(parts))
        except ImportError:
            logger.warning("PyMuPDF 미설치 — pip install PyMuPDF")
            return None
        except Exception as exc:
            logger.debug("PDF 추출 실패: %s", exc)
            return None

    # ── XLSX / XLS ────────────────────────────────────────────────────────────

    def _read_xlsx_bytes(self, data: bytes) -> Optional[str]:
        try:
            import openpyxl
            wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
            parts: list[str] = []
            for sheet in wb.worksheets:
                for row in sheet.iter_rows(values_only=True):
                    cells = [str(c) for c in row if c is not None]
                    if cells:
                        parts.append("\t".join(cells))
                if self._sample_bytes and sum(len(p) for p in parts) >= self._sample_bytes:
                    break
            return self._cap("\n".join(parts))
        except ImportError:
            logger.warning("openpyxl 미설치 — pip install openpyxl")
            return None
        except Exception as exc:
            logger.debug("XLSX 추출 실패: %s", exc)
            return None

    # ── PPTX ──────────────────────────────────────────────────────────────────

    def _read_pptx_bytes(self, data: bytes) -> Optional[str]:
        try:
            from pptx import Presentation
            prs = Presentation(io.BytesIO(data))
            parts: list[str] = []
            for slide in prs.slides:
                for shape in slide.shapes:
                    if shape.has_text_frame:
                        for para in shape.text_frame.paragraphs:
                            t = para.text.strip()
                            if t:
                                parts.append(t)
            return self._cap("\n".join(parts))
        except ImportError:
            logger.warning("python-pptx 미설치 — pip install python-pptx")
            return None
        except Exception as exc:
            logger.debug("PPTX 추출 실패: %s", exc)
            return None

    # ── HWP / HWPX ────────────────────────────────────────────────────────────

    def _read_hwp_bytes(self, data: bytes, suffix: str) -> Optional[str]:
        """한글 문서 부분 지원.

        .hwpx: ZIP 기반 XML 포맷 (한글 2010+) → 직접 파싱 가능
        .hwp:  OLE Compound Document → olefile로 본문 스트림 추출
        """
        if suffix == ".hwpx":
            return self._read_hwpx(data)
        return self._read_hwp_ole(data)

    def _read_hwpx(self, data: bytes) -> Optional[str]:
        """HWPX(ZIP+XML) 형식 텍스트 추출."""
        try:
            import re
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                parts: list[str] = []
                for name in zf.namelist():
                    if name.endswith(".xml") and "section" in name.lower():
                        xml = zf.read(name).decode("utf-8", errors="ignore")
                        text = re.sub(r"<[^>]+>", "", xml)
                        parts.append(text)
                return self._cap("\n".join(parts)) or None
        except Exception as exc:
            logger.debug("HWPX 추출 실패: %s", exc)
            return None

    def _read_hwp_ole(self, data: bytes) -> Optional[str]:
        """HWP OLE 형식 본문 스트림 추출 (olefile 사용)."""
        try:
            import olefile
            import zlib
            import re
            ole = olefile.OleFileIO(io.BytesIO(data))
            # BodyText 섹션별 스트림 읽기
            parts: list[str] = []
            for i in range(100):
                entry = f"BodyText/Section{i}"
                if not ole.exists(entry):
                    break
                raw = ole.openstream(entry).read()
                # HWP 본문은 zlib 압축 + 독자 포맷
                try:
                    raw = zlib.decompress(raw, -15)
                except Exception:
                    pass
                # HWP 레코드에서 텍스트 파트(type=67) 추출
                text = self._hwp_extract_text_records(raw)
                if text:
                    parts.append(text)
            ole.close()
            result = self._cap("\n".join(parts))
            return result if result.strip() else None
        except ImportError:
            logger.warning("olefile 미설치 — pip install olefile")
            return None
        except Exception as exc:
            logger.debug("HWP OLE 추출 실패: %s", exc)
            return None

    @staticmethod
    def _hwp_extract_text_records(data: bytes) -> str:
        """HWP 레코드 스트림에서 HWPTAG_PARA_TEXT(67) 레코드의 텍스트 추출."""
        import struct
        parts: list[str] = []
        offset = 0
        while offset + 4 <= len(data):
            header = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            rec_type = header & 0x3FF
            size     = (header >> 20) & 0xFFF
            if size == 0xFFF and offset + 4 <= len(data):
                size = struct.unpack_from("<I", data, offset)[0]
                offset += 4
            payload = data[offset: offset + size]
            offset += size
            if rec_type == 67:  # HWPTAG_PARA_TEXT
                try:
                    text = payload.decode("utf-16-le", errors="ignore")
                    # 제어 문자(0x0000–0x001F) 제거, 공백 정리
                    text = "".join(c if c >= " " else " " for c in text)
                    if text.strip():
                        parts.append(text.strip())
                except Exception:
                    pass
        return "\n".join(parts)

    # ── ZIP ───────────────────────────────────────────────────────────────────

    def _read_zip_bytes(self, data: bytes) -> Optional[str]:
        """ZIP 내 파일을 재귀 추출해 텍스트를 합친다."""
        try:
            parts: list[str] = []
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for i, info in enumerate(zf.infolist()):
                    if i >= MAX_ZIP_FILES:
                        break
                    if info.is_dir():
                        continue
                    try:
                        file_data = zf.read(info.filename)
                        text = self.extract_from_bytes(file_data, info.filename)
                        if text and text.strip():
                            parts.append(f"[{info.filename}]\n{text}")
                    except Exception as exc:
                        logger.debug("ZIP 내 파일 추출 실패 %s: %s", info.filename, exc)
            result = self._cap("\n\n".join(parts))
            return result if result.strip() else None
        except Exception as exc:
            logger.debug("ZIP 추출 실패: %s", exc)
            return None
