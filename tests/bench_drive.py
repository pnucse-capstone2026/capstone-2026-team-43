"""
bench_drive.py — Cloud drive channel benchmark (Google Drive-style multipart)

Measures:
  channel (mitm) = multipart body build + structure parse
  extract        = FileInspector on upload payload
  regex/ai/recv  = shared DLP core

Usage:
  python tests/bench_drive.py
  python tests/bench_drive.py --ext pdf xlsx --size 1mb
  python tests/bench_drive.py --out tests/results/bench_drive.xlsx
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bench_common import (
    build_clients,
    build_drive_multipart,
    collect_files,
    load_settings,
    make_arg_parser,
    parse_multipart_for_bench,
    resolve_filters,
    run_bench_loop,
    run_dlp_core,
    warmup_ai,
)

CHANNEL = "drive_upload"


def main() -> None:
    args = make_arg_parser("Cloud drive channel benchmark", "drive").parse_args()
    logging.basicConfig(level=logging.WARNING)

    api, pb, rf, fi = build_clients(args.mock)
    exts, sizes = resolve_filters(args.ext, args.size)
    files = collect_files(exts, sizes)
    if not files:
        print("[!] No matching files.")
        sys.exit(1)

    mode = "mock" if api.is_mock else load_settings().get("server", {}).get("ai_base_url", "")
    print(f"[drive] files={len(files)}  sizes={sizes}  repeat={args.repeat}  AI={mode}")

    if not args.no_warmup and not api.is_mock:
        warmup_ai(api, pb, rf, fi)

    def run_once(path: Path) -> dict[str, float] | None:
        t0 = time.perf_counter()
        body, ct = build_drive_multipart(path)
        t_build = (time.perf_counter() - t0) * 1000

        t_mitm, t_extract, text = parse_multipart_for_bench(body, ct, fi)
        t_channel = t_build + t_mitm

        if not text.strip():
            return None

        core = run_dlp_core(text, rf, api, pb, CHANNEL, "browser@drive.google.com")
        return {"channel": t_channel, "extract": t_extract, **core}

    run_bench_loop("mitm", CHANNEL, files, run_once, args.repeat, args.block_ms, args.out, "drive")


if __name__ == "__main__":
    main()
