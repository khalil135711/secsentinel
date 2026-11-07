"""Command line interface for SecSentinel.

Exit codes: 0 = nothing found, 1 = findings reported, 2 = usage or I/O error.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import List, Optional

from . import __version__, integrity, logdetect, passaudit


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secsentinel",
        description="Defensive security toolkit: log analysis, file integrity "
        "monitoring and password auditing.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_logs = sub.add_parser("logs", help="detect SSH brute-force attempts in an auth log")
    p_logs.add_argument("logfile", type=Path)
    p_logs.add_argument("--threshold", type=int, default=5,
                        help="failed logins that trigger a finding (default: 5)")
    p_logs.add_argument("--window", type=int, default=60,
                        help="sliding window in seconds (default: 60)")
    p_logs.add_argument("--year", type=int, default=None,
                        help="year of the log (syslog has none; default: current year)")
    p_logs.add_argument("--json", action="store_true", help="machine-readable output")

    p_int = sub.add_parser("integrity", help="file integrity monitoring")
    int_sub = p_int.add_subparsers(dest="action", required=True)
    p_init = int_sub.add_parser("init", help="create a SHA-256 baseline")
    p_chk = int_sub.add_parser("check", help="compare a directory to its baseline")
    for p in (p_init, p_chk):
        p.add_argument("directory", type=Path)
        p.add_argument("--baseline", type=Path, default=Path("integrity-baseline.json"))
        p.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                       help="glob to ignore (repeatable), e.g. '*.log'")
    p_chk.add_argument("--json", action="store_true", help="machine-readable output")

    p_pw = sub.add_parser("passwords", help="audit password strength offline")
    src = p_pw.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", type=Path, help="text file with one password per line")
    src.add_argument("--prompt", action="store_true",
                     help="enter one password without echo")
    p_pw.add_argument("--min-rating", choices=passaudit.RATINGS, default="good",
                      help="rating below this counts as a finding (default: good)")
    p_pw.add_argument("--json", action="store_true", help="machine-readable output")
    return parser


def _cmd_logs(args: argparse.Namespace) -> int:
    with open(args.logfile, encoding="utf-8", errors="replace") as handle:
        events = logdetect.parse_lines(handle, args.year)
    report = logdetect.analyze(events, args.threshold, args.window)
    if args.json:
        print(json.dumps(asdict(report), indent=2))
    else:
        print(logdetect.format_report(report))
    return 1 if report.findings else 0


def _cmd_integrity(args: argparse.Namespace) -> int:
    if args.action == "init":
        count = integrity.save_baseline(args.directory, args.baseline, args.exclude)
        print(f"Baseline written to {args.baseline} ({count} files).")
        return 0
    diff = integrity.check(args.directory, args.baseline, args.exclude)
    if args.json:
        print(json.dumps(asdict(diff), indent=2))
    else:
        print(integrity.format_diff(diff))
    return 0 if diff.clean else 1


def _cmd_passwords(args: argparse.Namespace) -> int:
    if args.prompt:
        passwords: List[str] = [getpass.getpass("Password to audit: ")]
    else:
        text = args.file.read_text(encoding="utf-8", errors="replace")
        passwords = [line.rstrip("\r\n") for line in text.splitlines() if line.strip()]

    floor = passaudit.rating_rank(args.min_rating)
    rows = []
    for number, password in enumerate(passwords, start=1):
        result = passaudit.audit_password(password)
        rows.append({
            "entry": number,
            "masked": passaudit.mask(password),
            **asdict(result),
            "below_minimum": passaudit.rating_rank(result.rating) < floor,
        })

    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        print("SecSentinel - password audit")
        for row in rows:
            flag = "[!]" if row["below_minimum"] else "[ok]"
            print(f"{flag:<4} #{row['entry']:<3} {row['masked']:<12} "
                  f"{row['rating']:<9} {row['entropy_bits']:>5} bits")
            for issue in row["issues"]:
                print(f"       - {issue}")
    return 1 if any(r["below_minimum"] for r in rows) else 0


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    handlers = {"logs": _cmd_logs, "integrity": _cmd_integrity, "passwords": _cmd_passwords}
    try:
        return handlers[args.command](args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
