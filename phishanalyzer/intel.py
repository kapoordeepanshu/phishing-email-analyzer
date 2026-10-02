"""Optional threat-intel enrichment via the VirusTotal v3 API.

Only *lookups* are performed: file hashes and URL ids are queried for existing
reports. Nothing is uploaded or submitted for scanning.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request
from typing import Callable

from .attachments import AttachmentResult
from .findings import Finding
from .links import LinkResult


class VirusTotal:
    API = "https://www.virustotal.com/api/v3"
    GUI = "https://www.virustotal.com/gui"

    def __init__(self, api_key: str, per_minute: int = 4, max_lookups: int = 10,
                 log: Callable[[str], None] | None = None):
        self.key = api_key
        self.interval = 60.0 / per_minute if per_minute > 0 else 0.0
        self.max_lookups = max_lookups
        self.used = 0
        self.stopped = ""
        self.log = log or (lambda msg: None)
        self._last = 0.0

    def _get(self, path: str) -> dict | None:
        """None = not checked, {} = unknown to VirusTotal, else the JSON report."""
        if self.stopped or self.used >= self.max_lookups:
            return None
        wait = self._last + self.interval - time.monotonic()
        if self._last and wait > 0:
            self.log(f"  [vt] rate limit: waiting {wait:.0f}s")
            time.sleep(wait)
        self._last = time.monotonic()
        self.used += 1
        req = urllib.request.Request(self.API + path, headers={"x-apikey": self.key, "accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {}
            self.stopped = {401: "invalid API key", 403: "access denied", 429: "quota exceeded"}.get(
                e.code, f"HTTP {e.code}")
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            self.stopped = f"network error: {e}"
        self.log(f"  [vt] lookups stopped: {self.stopped}")
        return None

    @staticmethod
    def _stats(report: dict) -> dict:
        return report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

    def file(self, sha256: str) -> dict | None:
        report = self._get(f"/files/{sha256}")
        if report is None:
            return None
        return {"known": bool(report), **self._stats(report), "link": f"{self.GUI}/file/{sha256}"}

    def url(self, url: str) -> dict | None:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        report = self._get(f"/urls/{url_id}")
        if report is None:
            return None
        return {"known": bool(report), **self._stats(report), "link": f"{self.GUI}/url/{url_id}"}


def _verdict_finding(kind: str, name: str, result: dict) -> Finding | None:
    mal, sus = result.get("malicious", 0), result.get("suspicious", 0)
    evidence = [f"{name}  ({mal} malicious, {sus} suspicious) {result['link']}"]
    if mal >= 3:
        return Finding("intel", "CRITICAL", f"VirusTotal: {kind} flagged malicious by multiple engines", "", evidence)
    if mal >= 1:
        return Finding("intel", "HIGH", f"VirusTotal: {kind} flagged malicious", "", evidence)
    if sus >= 1:
        return Finding("intel", "MEDIUM", f"VirusTotal: {kind} flagged suspicious", "", evidence)
    return None


def enrich(vt: VirusTotal, attachments: list[AttachmentResult], links: list[LinkResult]) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    results: dict[str, dict] = {}
    for att in attachments:
        r = vt.file(att.sha256)
        if r is not None:
            results[att.sha256] = r
            f = _verdict_finding("attachment", att.filename, r)
            if f:
                findings.append(f)
    # suspicious links first, each URL once
    urls = list(dict.fromkeys(l.url for l in sorted(links, key=lambda l: not l.suspicious) if l.host))
    for url in urls:
        r = vt.url(url if "://" in url else "http://" + url)
        if r is None:
            if vt.stopped or vt.used >= vt.max_lookups:
                break
            continue
        results[url] = r
        f = _verdict_finding("link", url, r)
        if f:
            findings.append(f)
    return findings, results
