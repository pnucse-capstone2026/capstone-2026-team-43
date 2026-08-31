"""
run_bench.py — (legacy) DLP core-only benchmark

Channel-specific benchmarks (with overhead) are in:
  tests/bench_clipboard.py  — hook + extract + DLP core
  tests/bench_mail.py       — mitm multipart + extract + DLP core
  tests/bench_drive.py      — mitm multipart + extract + DLP core
  tests/bench_usb.py        — write settle + extract + DLP core

This script measures DLP core only (no channel overhead).
"""

from __future__ import annotations

import logging
import sys
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

CHANNEL = "bench"


def main() -> None:
    args = make_arg_parser("DLP core benchmark (no channel overhead)", "core").parse_args()
    logging.basicConfig(level=logging.WARNING)

    api, pb, rf, fi = build_clients(args.mock)
    exts, sizes = resolve_filters(args.ext, args.size)
    files = collect_files(exts, sizes)
    if not files:
        print("[!] No matching files.")
        sys.exit(1)

    mode = "mock" if api.is_mock else load_settings().get("server", {}).get("ai_base_url", "")
    print(f"[core] files={len(files)}  sizes={sizes}  repeat={args.repeat}  AI={mode}")

    if not args.no_warmup and not api.is_mock:
        warmup_ai(api, pb, rf, fi)

    import time

    def run_once(path: Path):
        t0 = time.perf_counter()
        try:
            text = fi.extract_from_path(path) or ""
        except Exception:
            return None
        t_extract = (time.perf_counter() - t0) * 1000
        if not text.strip():
            return None
        core = run_dlp_core(text, rf, api, pb, CHANNEL, f"bench@{path.suffix.lstrip('.')}")
        return {"channel": 0.0, "extract": t_extract, **core}

    run_bench_loop("core", CHANNEL, files, run_once, args.repeat, args.block_ms, args.out, "core")


if __name__ == "__main__":
    main()
