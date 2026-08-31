"""
bench_clipboard.py — Clipboard channel benchmark

Simulates two paste modes:
  file (--mode file, default): CF_HDROP path resolve + FileInspector
  text (--mode text):          TextExtractor equivalent (read utf-8) + regex/AI

Usage:
  python tests/bench_clipboard.py
  python tests/bench_clipboard.py --mode text --ext txt --size 10kb
  python tests/bench_clipboard.py --out tests/results/bench_clipboard.xlsx
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bench_common import (
    build_clients,
    collect_files,
    load_settings,
    make_arg_parser,
    resolve_filters,
    run_bench_loop,
    run_dlp_core,
    warmup_ai,
)

CHANNEL = "clipboard"


def main() -> None:
    parser = make_arg_parser("Clipboard channel benchmark", "clipboard")
    parser.add_argument(
        "--mode", choices=["file", "text"], default="file",
        help="file=CF_HDROP+FileInspector  text=unicode paste (extract=0)",
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING)

    api, pb, rf, fi = build_clients(args.mock)
    exts, sizes = resolve_filters(args.ext, args.size)
    files = collect_files(exts, sizes)
    if not files:
        print("[!] No matching files.")
        sys.exit(1)

    mode = "mock" if api.is_mock else load_settings().get("server", {}).get("ai_base_url", "")
    print(f"[clipboard] mode={args.mode}  files={len(files)}  sizes={sizes}  repeat={args.repeat}  AI={mode}")

    if not args.no_warmup and not api.is_mock:
        warmup_ai(api, pb, rf, fi)

    def run_once(path: Path) -> dict[str, float] | None:
        if args.mode == "text":
            # Text paste: read clipboard text (no FileInspector)
            t0 = time.perf_counter()
            try:
                text = path.read_text(encoding="utf-8")
            except Exception:
                return None
            t_channel = (time.perf_counter() - t0) * 1000
            t_extract = 0.0
        else:
            # File paste: CF_HDROP path resolve + FileInspector
            t0 = time.perf_counter()
            _ = str(path.resolve())   # simulate GetClipboardData path list
            t_channel = (time.perf_counter() - t0) * 1000

            t0 = time.perf_counter()
            try:
                text = fi.extract_from_path(path) or ""
            except Exception:
                return None
            t_extract = (time.perf_counter() - t0) * 1000

        if not text.strip():
            return None

        core = run_dlp_core(text, rf, api, pb, CHANNEL, f"clipboard@{path.suffix.lstrip('.')}")
        return {"channel": t_channel, "extract": t_extract, **core}

    run_bench_loop("hook", CHANNEL, files, run_once, args.repeat, args.block_ms, args.out, "clipboard")


if __name__ == "__main__":
    main()
