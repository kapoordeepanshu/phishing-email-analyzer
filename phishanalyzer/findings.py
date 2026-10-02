"""Finding model, severity weights and verdict scoring."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
WEIGHTS = {"CRITICAL": 45, "HIGH": 20, "MEDIUM": 8, "LOW": 3, "INFO": 0}

# (minimum score, verdict) - checked top to bottom
VERDICTS = [
    (60, "PHISHING / MALICIOUS"),
    (30, "SUSPICIOUS"),
    (10, "LOW RISK"),
    (0, "NO STRONG INDICATORS"),
]


@dataclass
class Finding:
    category: str  # sender | auth | link | attachment | content | intel
    severity: str
    title: str
    detail: str = ""
    evidence: list[str] = field(default_factory=list)


def merge(findings: list[Finding]) -> list[Finding]:
    """Collapse findings with the same category/severity/title, combining their evidence.

    This keeps one bad indicator repeated across 30 links from counting 30 times.
    """
    merged: dict[tuple[str, str, str], Finding] = {}
    for f in findings:
        key = (f.category, f.severity, f.title)
        if key not in merged:
            merged[key] = Finding(f.category, f.severity, f.title, f.detail, [])
        target = merged[key]
        for e in f.evidence:
            if e and e not in target.evidence:
                target.evidence.append(e)
    return sorted(merged.values(), key=lambda f: (SEVERITIES.index(f.severity), f.category, f.title))


def score(findings: list[Finding]) -> int:
    return min(100, sum(WEIGHTS[f.severity] for f in findings))


def verdict(risk_score: int) -> str:
    for threshold, label in VERDICTS:
        if risk_score >= threshold:
            return label
    return VERDICTS[-1][1]


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITIES, 0)
    for f in findings:
        counts[f.severity] += 1
    return counts
