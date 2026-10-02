"""Command-line interface."""

from __future__ import annotations

import argparse
import glob
import os
import sys

from . import __version__, report
from .analyzer import analyze_bytes
from .parser import EmailParseError

BANNER = f"phishanalyzer {__version__} - phishing email analyser"
FAIL_LEVELS = {"phishing": 60, "suspicious": 30, "low": 10}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phishanalyzer",
        description=f"{BANNER}\nChecks sender authenticity, links and attachments of .eml files. "
                    "Attachments are never executed.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  python -m phishanalyzer suspicious.eml\n"
               "  python -m phishanalyzer inbox_exports/ --summary\n"
               "  python -m phishanalyzer mail.eml --json report.json\n"
               "  python -m phishanalyzer mail.eml --vt          (needs VT_API_KEY env var)\n"
               "  cat mail.eml | python -m phishanalyzer -",
    )
    p.add_argument("inputs", nargs="+", help=".eml file(s), directories (scanned for *.eml) or '-' for stdin")
    p.add_argument("--json", metavar="FILE", help="also write a JSON report to FILE ('-' for stdout only)")
    p.add_argument("--summary", action="store_true", help="one line per email instead of full reports")
    p.add_argument("--all-links", action="store_true", help="list every link, not just suspicious ones")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--vt", action="store_true",
                   help="look up attachment hashes and URLs on VirusTotal (lookups only, nothing is uploaded)")
    p.add_argument("--vt-key", metavar="KEY", help="VirusTotal API key (default: VT_API_KEY env var)")
    p.add_argument("--vt-rate", type=int, default=4, metavar="N", help="VirusTotal requests per minute (default 4)")
    p.add_argument("--vt-max", type=int, default=10, metavar="N", help="max VirusTotal lookups per email (default 10)")
    p.add_argument("--fail-on", choices=list(FAIL_LEVELS),
                   help="exit with code 2 if any email's verdict is at or above this level (for automation)")
    p.add_argument("--version", action="version", version=__version__)
    return p


def expand_inputs(inputs: list[str]) -> list[str]:
    paths: list[str] = []
    for item in inputs:
        if item == "-":
            paths.append(item)
        elif os.path.isdir(item):
            for root, _, files in os.walk(item):
                paths += sorted(os.path.join(root, f) for f in files if f.lower().endswith(".eml"))
        elif any(ch in item for ch in "*?["):
            paths += sorted(glob.glob(item, recursive=True))
        else:
            paths.append(item)
    return paths


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # punycode/homograph text on legacy consoles
        except (AttributeError, ValueError):
            pass
    json_only = args.json == "-"
    log = (lambda *a: None) if json_only else (lambda *a: print(*a, file=sys.stderr))

    vt = None
    if args.vt:
        key = args.vt_key or os.environ.get("VT_API_KEY", "")
        if not key:
            print("error: --vt needs an API key (--vt-key or VT_API_KEY env var); "
                  "get a free one at https://www.virustotal.com", file=sys.stderr)
            return 1

    paths = expand_inputs(args.inputs)
    if not paths:
        print("error: no .eml files found", file=sys.stderr)
        return 1

    reports, errors = [], 0
    for path in paths:
        try:
            if path == "-":
                data = sys.stdin.buffer.read()
            else:
                with open(path, "rb") as fh:
                    data = fh.read()
        except OSError as e:
            print(f"error: {path}: {e.strerror}", file=sys.stderr)
            errors += 1
            continue
        if args.vt:
            from .intel import VirusTotal
            vt = VirusTotal(key, args.vt_rate, args.vt_max, log=log)
        try:
            r = analyze_bytes(data, "stdin" if path == "-" else path, vt)
        except EmailParseError as e:
            print(f"error: {path}: {e}", file=sys.stderr)
            errors += 1
            continue
        reports.append(r)
        if not json_only and not args.summary:
            report.print_report(r, color=not args.no_color, all_links=args.all_links)

    if reports and args.summary and not json_only:
        report.print_summary(reports, color=not args.no_color)
    if reports and len(reports) > 1 and not args.summary and not json_only:
        report.print_summary(reports, color=not args.no_color)

    if args.json and reports:
        data = report.to_json(reports)
        if json_only:
            print(data)
        else:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(data)
            log(f"JSON report written to {args.json}")

    if args.fail_on and any(r.score >= FAIL_LEVELS[args.fail_on] for r in reports):
        return 2
    return 1 if errors and not reports else 0
