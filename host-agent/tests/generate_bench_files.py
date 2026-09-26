"""크기 구간별 × 모든 확장자 더미 민감정보 파일 생성 + 검사 시간 벤치마크.

지원 확장자 (35종)
------------------
텍스트계열(29): txt csv log xml json yaml yml md html htm rtf
                py js ts jsx tsx java c cpp h cs go rb php
                sql sh bat ps1 env
Office(4)     : docx xlsx pptx pdf
한글/압축(2)  : hwpx zip

크기 구간(5)  : 10kb / 100kb / 1mb / 10mb / 50mb
  * zip은 내부 txt 파일 크기로 구간 맞춤

실행
----
  python tests/generate_bench_files.py              # 전체 생성 + 벤치마크
  python tests/generate_bench_files.py --gen        # 생성만
  python tests/generate_bench_files.py --gen --tier 50mb   # 50mb 구간만
  python tests/generate_bench_files.py --bench    # 벤치마크만
"""

from __future__ import annotations

import io
import pathlib
import shutil
import sys
import time
import zipfile

ROOT      = pathlib.Path(__file__).parent
BENCH_DIR = ROOT / "bench"

# ── 민감정보 블록 ────────────────────────────────────────────────────────────

_SENSITIVE = (
    "\n[개인정보]\n"
    "주민등록번호: 900123-1234567\n"
    "신용카드: 4532-1234-5678-9012\n"
    "전화번호: 010-9876-5432\n"
    "이메일: hong.gildong@company.com\n"
    "계좌번호: 110-123-456789\n"
    "사업자등록번호: 123-45-67890\n"
)

_FILLER = (
    "개인정보 처리방침에 의거하여 수집된 정보를 관리합니다. "
    "해당 데이터는 인사팀에서 관리하며 외부 유출이 금지됩니다. "
    "본 문서는 내부 보안 정책에 따라 작성된 문서입니다. "
    "분기별 실적 보고서를 첨부하오니 검토 부탁드립니다. "
    "고객 데이터베이스 접근 권한은 승인된 담당자에게만 부여됩니다. "
)


def _text(target_bytes: int) -> str:
    """target_bytes 크기의 텍스트. 민감정보를 앞/중간/끝에 삽입."""
    chunk  = (_FILLER * 20).encode("utf-8")         # ~2 KB 단위
    repeat = max(1, target_bytes // len(chunk) + 1)
    body   = (_FILLER * 20 * repeat)[:target_bytes]
    mid    = len(body) // 2
    return body[:80] + _SENSITIVE + body[80:mid] + _SENSITIVE + body[mid:] + _SENSITIVE


# ── 형식별 생성 함수 ─────────────────────────────────────────────────────────

def _write_text(path: pathlib.Path, content: str):
    path.write_text(content, encoding="utf-8")

def _write_text_bytes(path: pathlib.Path, content: str):
    path.write_bytes(content.encode("utf-8"))

def gen_text(path: pathlib.Path, size: int, **_):
    _write_text(path, _text(size))

def gen_xml(path: pathlib.Path, size: int, **_):
    inner = _text(size).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    _write_text(path, f"<?xml version='1.0' encoding='UTF-8'?>\n<root>\n{inner}\n</root>")

def gen_json(path: pathlib.Path, size: int, **_):
    import json
    body = _text(size)
    _write_text(path, json.dumps({"content": body, "sensitive": _SENSITIVE}, ensure_ascii=False))

def gen_html(path: pathlib.Path, size: int, **_):
    body = _text(size)
    _write_text(path, f"<html><body><pre>{body}</pre></body></html>")

def gen_rtf(path: pathlib.Path, size: int, **_):
    body = _text(size).replace("\\", "\\\\").replace("{", r"\{").replace("}", r"\}")
    rtf  = r"{\rtf1\ansi\ansicpg949\f0\fs20 " + body.replace("\n", r"\par ") + "}"
    path.write_bytes(rtf.encode("cp949", errors="replace"))

def gen_csv(path: pathlib.Path, size: int, **_):
    row  = "홍길동,900123-1234567,010-9876-5432,hong@company.com,110-123-456789\n"
    frow = "일반직원,일반부서,팀원,2020-01-01,서울시 강남구\n"
    rows = []
    total = 0
    i = 0
    while total < size:
        line = row if i % 10 == 0 else frow
        rows.append(line)
        total += len(line.encode("utf-8"))
        i += 1
    _write_text(path, "이름,주민번호,전화,이메일,계좌\n" + "".join(rows))

_LARGE_BYTES = 10 * 1024**2   # 이 이상이면 대용량 생성 경로 사용


def gen_docx(path: pathlib.Path, size: int, **_):
    import docx as dx
    doc = dx.Document()
    doc.add_heading("내부 문서 (대외비)", level=1)
    text = _text(size)
    chunk = 8000 if size > _LARGE_BYTES else 4000
    for i in range(0, len(text), chunk):
        doc.add_paragraph(text[i:i + chunk])
    doc.save(path)

def gen_pdf(path: pathlib.Path, size: int, **_):
    import fitz
    doc  = fitz.open()
    text = _text(size)
    cpp  = 12000 if size > _LARGE_BYTES else 2800
    for i in range(0, len(text), cpp):
        page = doc.new_page(width=595, height=842)
        page.insert_text((40, 40), text[i:i + cpp], fontsize=9)
    doc.save(path)

def gen_xlsx(path: pathlib.Path, size: int, **_):
    import openpyxl
    wb = openpyxl.Workbook(write_only=True)
    ws = wb.create_sheet()
    ws.append(["이름", "주민번호", "전화", "이메일", "계좌"])
    sens = ["홍길동", "900123-1234567", "010-9876-5432", "hong@company.com", "110-123-456789"]
    frow = ["일반직원", "일반부서", "팀원", "2020-01-01", "서울"]
    if size <= _LARGE_BYTES:
        rows = max(10, size // 80)
        for i in range(rows):
            ws.append(sens if i % 10 == 0 else frow)
    else:
        body = _text(size)
        chunk = 8000
        for i in range(0, len(body), chunk):
            part = body[i:i + chunk]
            ws.append((sens if (i // chunk) % 10 == 0 else frow) + [part])
    wb.save(path)

def gen_pptx(path: pathlib.Path, size: int, **_):
    from pptx import Presentation
    prs   = Presentation()
    text  = _text(size)
    cpslide = 50000 if size > _LARGE_BYTES else 800
    for i in range(0, len(text), cpslide):
        slide = prs.slides.add_slide(prs.slide_layouts[1])
        slide.shapes.title.text = f"슬라이드 {i // cpslide + 1}"
        slide.placeholders[1].text = text[i:i + cpslide]
    prs.save(path)

def gen_hwpx(path: pathlib.Path, size: int, **_):
    text = _text(size)
    body_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<hh:HWPXPart xmlns:hh="urn:schemas-microsoft-com:office:hwpxml">'
        "<hh:Body><hh:Section>"
    )
    for line in text.splitlines():
        safe = line.replace("<", "").replace(">", "").replace("&", "")
        body_xml += f"<hh:Para><hh:Run><hh:T>{safe}</hh:T></hh:Run></hh:Para>"
    body_xml += "</hh:Section></hh:Body></hh:HWPXPart>"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("mimetype", "application/hwp+zip")
        zf.writestr("Contents/section0.xml", body_xml)
    path.write_bytes(buf.getvalue())

def gen_zip(path: pathlib.Path, size: int, **_):
    inner = _text(size).encode("utf-8")
    buf   = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("민감정보.txt", inner)
    path.write_bytes(buf.getvalue())


# ── 확장자 → 생성 함수 매핑 ─────────────────────────────────────────────────

#   (확장자, 생성함수, 최대 구간인덱스)
#    max_tier_idx: 0=10kb 1=100kb 2=1mb 3=10mb 4=50mb  None=전체
FORMATS: list[tuple[str, any, int | None]] = [
    # 텍스트 계열 — 전 구간
    (".txt",  gen_text,  None),
    (".csv",  gen_csv,   None),
    (".log",  gen_text,  None),
    (".xml",  gen_xml,   None),
    (".json", gen_json,  None),
    (".yaml", gen_text,  None),
    (".yml",  gen_text,  None),
    (".md",   gen_text,  None),
    (".html", gen_html,  None),
    (".htm",  gen_html,  None),
    (".rtf",  gen_rtf,   None),
    (".py",   gen_text,  None),
    (".js",   gen_text,  None),
    (".ts",   gen_text,  None),
    (".jsx",  gen_text,  None),
    (".tsx",  gen_text,  None),
    (".java", gen_text,  None),
    (".c",    gen_text,  None),
    (".cpp",  gen_text,  None),
    (".h",    gen_text,  None),
    (".cs",   gen_text,  None),
    (".go",   gen_text,  None),
    (".rb",   gen_text,  None),
    (".php",  gen_text,  None),
    (".sql",  gen_text,  None),
    (".sh",   gen_text,  None),
    (".bat",  gen_text,  None),
    (".ps1",  gen_text,  None),
    (".env",  gen_text,  None),
    # Office / 한글 — 전 구간
    (".docx", gen_docx,  None),
    (".xlsx", gen_xlsx,  None),
    (".pptx", gen_pptx,  None),
    (".pdf",  gen_pdf,   None),
    # 한글/압축
    (".hwpx", gen_hwpx,  None),
    (".zip",  gen_zip,   None),
]

TIERS: list[tuple[str, int]] = [
    ("10kb",  10   * 1024),
    ("100kb", 100  * 1024),
    ("1mb",   1    * 1024**2),
    ("10mb",  10   * 1024**2),
    ("50mb",  50   * 1024**2),
]


# ── 생성 ────────────────────────────────────────────────────────────────────

def generate_all(tier_filter: str | None = None):
    print("=== 더미 파일 생성 ===\n")
    total_files = 0
    total_bytes = 0

    tiers = TIERS if tier_filter is None else [t for t in TIERS if t[0] == tier_filter]
    if tier_filter and not tiers:
        print(f"[!] Unknown tier: {tier_filter}")
        return

    for tier_idx, (tier_name, size) in enumerate(TIERS):
        if tier_filter and tier_name != tier_filter:
            continue
        tier_dir = BENCH_DIR / tier_name
        tier_dir.mkdir(parents=True, exist_ok=True)
        created = 0

        for ext, fn, max_idx in FORMATS:
            if max_idx is not None and tier_idx > max_idx:
                continue
            fname = f"sample{ext}"
            fpath = tier_dir / fname
            try:
                t0 = time.perf_counter()
                fn(fpath, size)
                elapsed = time.perf_counter() - t0
                actual  = fpath.stat().st_size
                total_bytes += actual
                created += 1
                print(f"  [{tier_name:>5s}] {fname:<16}  {actual/1024:>8,.1f} KB  {elapsed:.2f}s")
            except Exception as e:
                print(f"  [{tier_name:>5s}] {fname:<16}  ERROR: {e}")

        total_files += created
        print(f"         → {created}개 생성\n")

    print(f"총 {total_files}개 파일 / {total_bytes/1024/1024:.1f} MB\n")


# ── 벤치마크 ────────────────────────────────────────────────────────────────

def benchmark_all():
    sys.path.insert(0, str(ROOT.parent))
    from network_hook.file_inspector import FileInspector
    from clipboard_ctrl.rule_filter  import RuleFilter

    fi = FileInspector()
    rf = RuleFilter(ROOT.parent / "config" / "regex_patterns.json")

    print("=== 검사 시간 벤치마크 ===\n")
    fmt = "{:<8} {:<16} {:>10} {:>9} {:>10} {:>9} {}"
    header = fmt.format("구간", "확장자", "크기(KB)", "추출(s)", "정규식(s)", "합계(s)", "탐지")
    print(header)
    print("-" * len(header))

    tier_stats: dict[str, list] = {}

    for tier_dir in sorted(BENCH_DIR.iterdir()):
        if not tier_dir.is_dir():
            continue
        tier_name = tier_dir.name
        tier_stats[tier_name] = []

        for fpath in sorted(tier_dir.iterdir()):
            ext = fpath.suffix
            kb  = fpath.stat().st_size / 1024

            t0 = time.perf_counter()
            try:
                text = fi.extract_from_path(fpath)
            except Exception:
                text = None
            ext_s = time.perf_counter() - t0

            if not text:
                print(fmt.format(tier_name, ext, f"{kb:.1f}", "-", "-", "-", "SKIP"))
                continue

            t1    = time.perf_counter()
            hits  = rf.match(text)
            rex_s = time.perf_counter() - t1
            tot_s = ext_s + rex_s

            detected = "HIT" if hits else "MISS"
            print(fmt.format(tier_name, ext, f"{kb:.1f}", f"{ext_s:.3f}", f"{rex_s:.3f}", f"{tot_s:.3f}", detected))
            tier_stats[tier_name].append((kb, ext_s, rex_s, tot_s, bool(hits)))

    # 구간별 요약
    print()
    print("=== 구간별 평균 ===\n")
    sfmt = "{:<8} {:>6} {:>10} {:>10} {:>10} {:>10} {:>8}"
    print(sfmt.format("구간", "파일수", "평균KB", "추출(s)", "정규식(s)", "합계(s)", "탐지율"))
    print("-" * 70)
    for tier_name, rows in tier_stats.items():
        if not rows:
            continue
        n    = len(rows)
        avg  = lambda i: sum(r[i] for r in rows) / n
        hits = sum(1 for r in rows if r[4])
        print(sfmt.format(
            tier_name, n,
            f"{avg(0):.1f}",
            f"{avg(1):.3f}",
            f"{avg(2):.3f}",
            f"{avg(3):.3f}",
            f"{hits}/{n}",
        ))


if __name__ == "__main__":
    args = sys.argv[1:]
    tier_filter = None
    if "--tier" in args:
        idx = args.index("--tier")
        if idx + 1 >= len(args):
            print("Usage: --tier 50mb")
            sys.exit(1)
        tier_filter = args[idx + 1]
        args = args[:idx] + args[idx + 2:]

    mode = args[0] if args else "--all"
    if mode in ("--gen", "--all"):
        generate_all(tier_filter)
    if mode in ("--bench", "--all"):
        benchmark_all()
