"""Console and JSON reporting."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

from .analyzer import Report
from .findings import severity_counts

COLORS = {"CRITICAL": "\033[1;97;41m", "HIGH": "\033[1;31m", "MEDIUM": "\033[33m", "LOW": "\033[36m",
          "INFO": "\033[90m", "bold": "\033[1m", "green": "\033[32m", "red": "\033[1;31m",
          "yellow": "\033[1;33m", "dim": "\033[2m", "reset": "\033[0m"}
VERDICT_STYLE = {"PHISHING / MALICIOUS": "CRITICAL", "SUSPICIOUS": "red", "LOW RISK": "yellow",
                 "NO STRONG INDICATORS": "green"}


class Painter:
    def __init__(self, enabled: bool):
        self.enabled = enabled
        if enabled and os.name == "nt":
            os.system("")  # enables ANSI escape processing in the Windows console

    def __call__(self, text: str, style: str) -> str:
        return f"{COLORS[style]}{text}{COLORS['reset']}" if self.enabled else text


def _size(n: int) -> str:
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def _short(text: str, width: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= width else text[: width - 3] + "..."


def print_report(r: Report, color: bool = True, all_links: bool = False, out=sys.stdout) -> None:
    c = Painter(color and getattr(out, "isatty", lambda: False)())
    w = lambda s="": print(s, file=out)
    s = r.sender

    w(c("=" * 78, "dim"))
    w(c(f" {r.source or 'email'}", "bold"))
    w(c("=" * 78, "dim"))
    counts = severity_counts(r.findings)
    w(f" Verdict    : {c(f' {r.verdict} ', VERDICT_STYLE.get(r.verdict, 'bold'))}   "
      f"Risk score: {c(f'{r.score}/100', 'bold')}")
    w(" Findings   : " + ", ".join(c(f"{n} {k}", k) if n else f"{n} {k}" for k, n in counts.items()))

    w()
    w(c(" SENDER", "bold"))
    rows = [("Subject", r.subject), ("From", s.from_), ("Reply-To", s.reply_to), ("Return-Path", s.return_path),
            ("To", s.to), ("Date", s.date), ("Message-ID", s.message_id), ("Mailer", s.mailer),
            ("Origin IP", s.origin_ip)]
    for label, value in rows:
        if value:
            w(f"  {label:<13}: {_short(value, 62)}")
    if s.auth:
        def fmt(k):
            v = s.auth.get(k, "-")
            style = "green" if v == "pass" else ("HIGH" if v in ("fail", "softfail") else "dim")
            return c(v, style)
        w(f"  {'Auth':<13}: SPF={fmt('spf')}  DKIM={fmt('dkim')}  DMARC={fmt('dmarc')}"
          + (c(f"   (from {s.auth_source})", "dim")))
    else:
        w(f"  {'Auth':<13}: {c('no Authentication-Results header', 'dim')}")
    if s.dkim_domains:
        w(f"  {'DKIM signer':<13}: {', '.join(s.dkim_domains)}")
    if s.hops:
        w(f"  Relay path (oldest first, {len(s.hops)} hops):")
        for i, h in enumerate(s.hops, 1):
            ip = f" [{h.ip}]" if h.ip else ""
            w(c(f"   {i:>2}. {_short(h.from_host or '?', 30)}{ip} -> {_short(h.by_host or '?', 30)}", "dim"))

    w()
    shown = r.links if all_links else [l for l in r.links if l.suspicious] or r.links[:10]
    w(c(f" LINKS ({len(r.links)} found, {sum(l.suspicious for l in r.links)} suspicious)", "bold"))
    for l in shown[:60]:
        mark = c("[!]", "HIGH") if l.suspicious else c("[ ]", "green")
        w(f"  {mark} {_short(l.url, 72)}")
        if l.text and l.text.strip() != l.url:
            w(c(f"      text  : {_short(l.text, 64)}", "dim"))
        if l.unwrapped_from:
            w(c(f"      via   : {_short(l.unwrapped_from, 64)}", "dim"))
        if not l.source.startswith(("body", "html")):
            w(c(f"      from  : {l.source}", "dim"))
        for flag in l.flags:
            w(f"      - {flag}")
    hidden = len(r.links) - len(shown[:60])
    if hidden > 0:
        w(c(f"  ... {hidden} more (use --all-links)", "dim"))

    w()
    w(c(f" ATTACHMENTS ({len(r.attachments)})", "bold"))
    for a in r.attachments:
        mark = c("[!]", "HIGH") if a.flags else c("[ ]", "green")
        dtype = f", content: {a.detected_type}" if a.detected_type else ""
        w(f"  {mark} {a.filename}  ({a.content_type}, {_size(a.size)}{dtype})")
        w(c(f"      sha256: {a.sha256}", "dim"))
        w(c(f"      md5   : {a.md5}", "dim"))
        if a.members:
            w(c(f"      files : {_short(', '.join(a.members[:10]), 64)}", "dim"))
        vt = r.intel.get(a.sha256)
        if vt:
            w(f"      VirusTotal: {vt.get('malicious', 0)} malicious / {vt.get('suspicious', 0)} suspicious"
              if vt.get("known") else "      VirusTotal: not seen before")
        for flag in a.flags:
            w(f"      - {flag}")

    w()
    w(c(" FINDINGS", "bold"))
    if not r.findings:
        w(c("  No indicators found. That does not prove the email is safe.", "green"))
    for f in r.findings:
        tag = c(f"[{f.severity}]", f.severity)
        pad = " " * (12 - len(f.severity) - 2)
        w(f"  {tag}{pad}{f.category:<11}{f.title}")
        if f.detail:
            w(c(f"  {'':22}{f.detail}", "dim"))
        for e in f.evidence[:5]:
            w(c(f"  {'':22}> {_short(e, 80)}", "dim"))
        if len(f.evidence) > 5:
            w(c(f"  {'':22}> ... {len(f.evidence) - 5} more", "dim"))
    w()


def print_summary(reports: list[Report], color: bool = True, out=sys.stdout) -> None:
    c = Painter(color and getattr(out, "isatty", lambda: False)())
    print(c(f"{'SCORE':>5}  {'VERDICT':<22} FILE / SUBJECT", "bold"), file=out)
    for r in sorted(reports, key=lambda r: -r.score):
        print(f"{r.score:>5}  {c(f'{r.verdict:<22}', VERDICT_STYLE.get(r.verdict, 'bold'))} "
              f"{r.source}  {c(_short(r.subject, 50), 'dim')}", file=out)


def to_json(reports: list[Report]) -> str:
    data = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "reports": [r.to_dict() for r in reports],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)
