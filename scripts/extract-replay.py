#!/usr/bin/env python3
# Extract a UDP replay script from a pcap.
#
# Reads a pcap via tcpdump, filters by source port (default 41840 — the AWG
# client's ephemeral in awg-udp-nuremberg.pcap), normalizes time to the first
# kept packet, and writes a JSONL file with one {"t_ms": ..., "len": ...} per
# line. The compare-harness generator replays this file verbatim.
#
# Usage:
#   scripts/extract-replay.py \
#       --pcap /tmp/phantun-analysis/pcap/awg-udp-nuremberg.pcap \
#       --src-port 41840 \
#       --max-packets 600 \
#       --out docker/compare/awg-replay.jsonl
import argparse
import json
import re
import subprocess
import sys


LINE_RE = re.compile(
    r"^(?P<ts>\d+\.\d+)\s+IP\s+"
    r"(?P<src>[\d.]+)\.(?P<sport>\d+)\s+>\s+"
    r"(?P<dst>[\d.]+)\.(?P<dport>\d+):\s+UDP,\s+length\s+(?P<len>\d+)"
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--src-port", type=int, required=True)
    ap.add_argument("--max-packets", type=int, default=0,
                    help="0 = no cap")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    proc = subprocess.run(
        ["tcpdump", "-r", args.pcap, "-nn", "-tt", "-q"],
        capture_output=True, text=True, check=True,
    )

    kept: list[tuple[float, int]] = []
    for line in proc.stdout.splitlines():
        m = LINE_RE.match(line)
        if not m:
            continue
        if int(m["sport"]) != args.src_port:
            continue
        kept.append((float(m["ts"]), int(m["len"])))
        if args.max_packets and len(kept) >= args.max_packets:
            break

    if not kept:
        print(f"error: no packets matched src-port {args.src_port}", file=sys.stderr)
        return 1

    t0 = kept[0][0]
    with open(args.out, "w", encoding="utf-8") as fh:
        for ts, ln in kept:
            fh.write(json.dumps({"t_ms": round((ts - t0) * 1000.0, 3), "len": ln}) + "\n")

    duration_ms = (kept[-1][0] - t0) * 1000.0
    total_bytes = sum(ln for _, ln in kept)
    print(
        f"wrote {len(kept)} packets, {total_bytes} payload bytes, "
        f"span {duration_ms:.1f}ms → {args.out}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
