"""
bench_usb.py — USB channel benchmark

Measures:
  channel (settle) = fixed write-settle wait (_WRITE_SETTLE_SEC = 2.0s)
  extract          = FileInspector
  regex/ai/recv    = shared DLP core
  block            = file delete simulation (default 10ms) + popup (--block-ms)

Usage:
  python tests/bench_usb.py
  python tests/bench_usb.py --settle-ms 2000 --block-ms 100
  python tests/bench_usb.py --out tests/results/bench_usb.xlsx
"""

from __future__ import annotations

import logging
import os
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

CHANNEL = "file_guard"
USB_WRITE_SETTLE_MS = 2000.0   # usb_guard_usermode._WRITE_SETTLE_SEC
USB_DELETE_MS       = 10.0     # os.remove overhead estimate


def main() -> None:
    parser = make_arg_parser("USB channel benchmark", "usb")
    parser.add_argument(
        "--settle-ms", type=float, default=USB_WRITE_SETTLE_MS,
        help="Write settle wait (default 2000ms, matches agent code)",
    )
    parser.add_argument(
        "--no-delete", action="store_true",
        help="Exclude os.remove estimate from block time",
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING)

    block_ms = args.block_ms + (0.0 if args.no_delete else USB_DELETE_MS)

    api, pb, rf, fi = build_clients(args.mock)
    exts, sizes = resolve_filters(args.ext, args.size)
    files = collect_files(exts, sizes)
    if not files:
        print("[!] No matching files.")
        sys.exit(1)

    mode = "mock" if api.is_mock else load_settings().get("server", {}).get("ai_base_url", "")
    print(
        f"[usb] files={len(files)}  sizes={sizes}  repeat={args.repeat}  "
        f"settle={args.settle_ms}ms  block={block_ms}ms  AI={mode}"
    )

    if not args.no_warmup and not api.is_mock:
        warmup_ai(api, pb, rf, fi)

    def run_once(path: Path) -> dict[str, float] | None:
        # Fixed write-settle wait (same as agent _inspect_file)
        t0 = time.perf_counter()
        time.sleep(args.settle_ms / 1000.0)
        t_channel = (time.perf_counter() - t0) * 1000

        if not path.is_file():
            return None

        t0 = time.perf_counter()
        try:
            text = fi.extract_from_path(path) or ""
        except Exception:
            return None
        t_extract = (time.perf_counter() - t0) * 1000

        if not text.strip():
            return None

        core = run_dlp_core(text, rf, api, pb, CHANNEL, "usb_copy@E:")
        return {"channel": t_channel, "extract": t_extract, **core}

    run_bench_loop("settle", CHANNEL, files, run_once, args.repeat, block_ms, args.out, "usb")


if __name__ == "__main__":
    main()
