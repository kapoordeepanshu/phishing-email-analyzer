"""Run every check against a parsed email and produce a scored report."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from . import __version__, findings as fnd
from .attachments import AttachmentResult, analyze_attachments
from .content import analyze_content
from .headers import SenderInfo, analyze_sender
from .links import LinkResult, analyze_links
from .parser import ParsedEmail, parse_bytes


@dataclass
class Report:
    source: str
    subject: str
    sender: SenderInfo
    links: list[LinkResult]
    attachments: list[AttachmentResult]
    findings: list[fnd.Finding]
    score: int = 0
    verdict: str = ""
    intel: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "tool": f"phishanalyzer {__version__}",
            "source": self.source,
            "subject": self.subject,
            "verdict": self.verdict,
            "score": self.score,
            "summary": fnd.severity_counts(self.findings),
            "sender": asdict(self.sender),
            "findings": [asdict(f) for f in self.findings],
            "links": [{**asdict(l), "suspicious": l.suspicious} for l in self.links],
            "attachments": [asdict(a) for a in self.attachments],
            "intel": self.intel,
        }


def analyze(email: ParsedEmail, source: str = "", vt=None) -> Report:
    sender, sender_findings = analyze_sender(email)
    attachments, att_findings, att_links = analyze_attachments(email.attachments)
    links, link_findings = analyze_links(email.links + att_links)
    all_findings = sender_findings + att_findings + link_findings + analyze_content(email)

    intel = {}
    if vt is not None:
        from .intel import enrich
        intel_findings, intel = enrich(vt, attachments, links)
        all_findings += intel_findings

    merged = fnd.merge(all_findings)
    risk = fnd.score(merged)
    return Report(source, email.subject, sender, links, attachments, merged, risk, fnd.verdict(risk), intel)


def analyze_bytes(data: bytes, source: str = "", vt=None) -> Report:
    return analyze(parse_bytes(data), source, vt)
