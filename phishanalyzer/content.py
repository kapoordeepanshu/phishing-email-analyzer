"""Body / social-engineering checks."""

from __future__ import annotations

import re

from .findings import Finding
from .parser import ParsedEmail


def _p(*patterns: str) -> list[re.Pattern]:
    return [re.compile(p, re.I) for p in patterns]


THEMES: dict[str, list[re.Pattern]] = {
    "Urgency or pressure language": _p(
        r"\burgent(ly)?\b", r"\bimmediate(ly)?\b", r"\bwithin (24|48|72) hours\b", r"\baction required\b",
        r"\bfinal (notice|warning|reminder)\b", r"\b(will|has been|have been) (be )?(suspended|locked|"
        r"disabled|terminated|deactivated|closed|deleted)\b", r"\bexpir(e|es|ed|ing) (today|soon)\b",
        r"\bunusual (sign-?in|activity|login)\b", r"\bunauthori[sz]ed (access|transaction|login)\b",
        r"\blast chance\b", r"\bavoid (suspension|interruption|termination)\b", r"\bas soon as possible\b",
    ),
    "Request to verify account or enter credentials": _p(
        r"\bverify your (account|identity|information|details|email|mailbox)\b",
        r"\bconfirm your (password|account|identity|details|billing)\b",
        r"\bupdate your (payment|billing|account|card|bank) (details|information|method)\b",
        r"\b(re-?enter|provide|enter) your (password|credentials|login|pin|card)\b",
        r"\breset your password\b", r"\bmailbox (is )?(full|quota|storage)\b",
        r"\bsocial security number\b", r"\bone[- ]time (password|code)\b",
        r"\bvalidate your (account|mailbox|email)\b", r"\bclick (here|below|the link) to (log ?in|sign ?in|verify|"
        r"confirm|restore|unlock|update)\b",
    ),
    "Payment or financial lure": _p(
        r"\bwire transfer\b", r"\bgift ?cards?\b", r"\b(bitcoin|btc|crypto ?currency|usdt|wallet address)\b",
        r"\bpayment (failed|declined|pending|overdue|unsuccessful)\b", r"\b(outstanding|overdue|unpaid) (invoice|"
        r"balance|payment)\b", r"\b(new|updated|change of) (bank|banking|account) details\b",
        r"\btax refund\b", r"\brefund (is )?(pending|available|approved)\b", r"\bpending (transaction|transfer)\b",
        r"\bcustoms (fee|duty|charge)s?\b", r"\bdelivery fee\b",
    ),
    "Prize or reward lure": _p(
        r"\byou(('| ha)ve)? (won|been selected)\b", r"\b(lottery|jackpot|sweepstake)s?\b", r"\bclaim your (prize|"
        r"reward|refund|gift|funds)\b", r"\binheritance\b", r"\bbeneficiary\b", r"\bfree (iphone|gift)\b",
        r"\bcongratulations\b.{0,40}\b(won|winner|selected)\b",
    ),
    "Generic greeting (no real name)": _p(
        r"\bdear (customer|user|client|member|account ?holder|sir|madam|sir/madam|valued|beneficiary|"
        r"friend|e-?mail user|subscriber)\b",
    ),
    "Business-email-compromise style request": _p(
        r"\bare you (available|at your desk)\b", r"\bdo me a (quick )?favou?r\b",
        r"\bkeep (this|it) (confidential|between us)\b", r"\bi need you to (buy|purchase|send|process)\b",
        r"\bkindly (send|process|confirm|reply)\b", r"\bsend me your (whatsapp|cell|mobile|phone) number\b",
    ),
}

ZERO_WIDTH_RE = re.compile("[​‌‍⁠﻿­]")
HIDDEN_CSS_RE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(px|pt|em)?\s*[;\"']"
                           r"|color\s*:\s*#?(fff(fff)?|white)\b[^>]*background(-color)?\s*:\s*#?(fff(fff)?|white)", re.I)


def analyze_content(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []

    def add(severity, title, detail="", evidence=()):
        findings.append(Finding("content", severity, title, detail, list(evidence)))

    body = " ".join([email.subject, email.text, email.html_text])
    norm = re.sub(r"\s+", " ", ZERO_WIDTH_RE.sub("", body))

    hits = {}
    for theme, patterns in THEMES.items():
        found = sorted({m.group(0).lower() for p in patterns for m in p.finditer(norm)})
        if found:
            hits[theme] = found
            add("LOW", theme, "", [", ".join(f'"{f}"' for f in found[:6])])
    if len(hits) >= 3:
        add("MEDIUM", "Several social-engineering themes combined", "", [", ".join(hits)])

    tags = email.html_tags
    if tags.get("password"):
        add("CRITICAL", "Email body contains a password input field")
    if tags.get("form"):
        add("HIGH", "Email body contains an HTML form (data is submitted from the email itself)")
    if tags.get("script"):
        add("MEDIUM", "Email body contains JavaScript")
    if tags.get("iframe"):
        add("MEDIUM", "Email body embeds external content (iframe/object)")
    if tags.get("meta-refresh"):
        add("MEDIUM", "Email body auto-redirects (meta refresh)")
    if email.html and HIDDEN_CSS_RE.search(email.html):
        add("INFO", "HTML contains hidden text (common in newsletters, also used to fool filters)")

    zw = len(ZERO_WIDTH_RE.findall(body))
    if zw >= 5:
        add("MEDIUM", "Zero-width characters inserted into text (filter evasion)", "", [f"{zw} characters"])

    subject = email.subject.strip()
    if re.match(r"^(re|fw|fwd|aw|wg|tr)\s*:", subject, re.I) and not (
            email.header("in-reply-to") or email.header("references")):
        add("LOW", "Subject pretends to be a reply/forward but is not part of a thread", "", [subject])

    images = [a for a in email.attachments if a.content_type.startswith("image/")]
    visible = (email.text.strip() or email.html_text.strip())
    if re.search(r"\bqr[- ]?code\b|\bscan (the|this|below)\b.{0,20}\bcode\b", norm, re.I) and (
            images or tags.get("img")):
        add("MEDIUM", "Possible QR-code phishing (quishing) - QR codes hide links from scanners")
    if tags.get("img") and len(visible) < 40 and not email.attachments:
        add("LOW", "Body is almost entirely images (hides text from filters)")
    elif not visible and images and len(images) <= 2:
        add("LOW", "Body is almost entirely images (hides text from filters)")

    return findings
