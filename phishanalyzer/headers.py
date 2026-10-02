"""Sender / header checks: authentication results, address mismatches and relay path."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

from . import domains
from .findings import Finding
from .parser import ParsedEmail

AUTH_RE = re.compile(r"\b(spf|dkim|dmarc|arc|compauth)\s*=\s*([a-z]+)", re.I)
IP_IN_BRACKETS_RE = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:.]+)\]")
IP_IN_PARENS_RE = re.compile(r"\((?:[^()]*?\s)?\[?((?:\d{1,3}\.){3}\d{1,3})\]?\)")
EMAIL_IN_TEXT_RE = re.compile(r"[\w.+-]+@([\w-]+\.)+[a-z]{2,}", re.I)
SUSPICIOUS_MAILERS = re.compile(r"phpmailer|mass ?mail|sendblaster|atomic ?mail|gammadyne|"
                                r"swiftmailer|python|curl|powershell|leaf ?php|bulk", re.I)


@dataclass
class Hop:
    from_host: str
    by_host: str
    ip: str
    date: str


@dataclass
class SenderInfo:
    from_: str = ""
    from_domain: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    date: str = ""
    message_id: str = ""
    mailer: str = ""
    origin_ip: str = ""
    auth: dict[str, str] = field(default_factory=dict)
    auth_source: str = ""
    dkim_domains: list[str] = field(default_factory=list)
    hops: list[Hop] = field(default_factory=list)  # oldest first


def _domain(addr: str) -> str:
    return addr.rpartition("@")[2].lower().strip("<>[] ") if "@" in addr else ""


def _public_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def parse_auth_results(email: ParsedEmail) -> tuple[dict[str, str], str]:
    """Results from the top-most (receiving server) Authentication-Results header."""
    for header in ("authentication-results", "arc-authentication-results"):
        values = email.header_all(header)
        if values:
            results: dict[str, list[str]] = {}
            for method, result in AUTH_RE.findall(values[0]):
                results.setdefault(method.lower(), []).append(result.lower())
            # several DKIM signatures: one passing is enough
            picked = {m: ("pass" if "pass" in r else r[0]) for m, r in results.items()}
            if picked:
                return picked, header
    spf = email.header("received-spf")
    if spf:
        return {"spf": spf.split()[0].lower()}, "received-spf"
    return {}, ""


def parse_hops(email: ParsedEmail) -> list[Hop]:
    hops = []
    for value in email.header_all("received"):
        body, _, date = value.rpartition(";")
        if not body:
            body, date = value, ""
        m_from = re.search(r"\bfrom\s+(\S+)", body, re.I)
        m_by = re.search(r"\bby\s+(\S+)", body, re.I)
        ip = ""
        for candidate in IP_IN_BRACKETS_RE.findall(body) + IP_IN_PARENS_RE.findall(body):
            try:
                ipaddress.ip_address(candidate)
                ip = candidate
                break
            except ValueError:
                continue
        hops.append(Hop(m_from.group(1) if m_from else "", m_by.group(1).rstrip(";") if m_by else "",
                        ip, date.strip()))
    return list(reversed(hops))  # headers are prepended, so the last one is the oldest


def analyze_sender(email: ParsedEmail) -> tuple[SenderInfo, list[Finding]]:
    findings: list[Finding] = []

    def add(severity, title, detail="", *evidence, category="sender"):
        findings.append(Finding(category, severity, title, detail, [e for e in evidence if e]))

    info = SenderInfo()
    senders = email.from_
    sender = senders[0] if senders else None
    info.from_ = str(sender) if sender else email.header("from")
    info.from_domain = sender.domain if sender else ""
    info.reply_to = ", ".join(str(a) for a in email.reply_to)
    info.return_path = email.return_path
    info.to = ", ".join(str(a) for a in email.to[:5]) + (" ..." if len(email.to) > 5 else "")
    info.date = email.header("date")
    info.message_id = email.header("message-id")
    info.mailer = email.header("x-mailer") or email.header("user-agent")
    info.auth, info.auth_source = parse_auth_results(email)
    info.hops = parse_hops(email)
    for sig in email.header_all("dkim-signature"):
        m = re.search(r"\bd\s*=\s*([^;\s]+)", sig)
        if m:
            info.dkim_domains.append(m.group(1).lower())
    public = [h.ip for h in info.hops if _public_ip(h.ip)]
    xoip = email.header("x-originating-ip").strip("[] ")
    info.origin_ip = public[0] if public else (xoip if _public_ip(xoip) else "")

    # --- From ---------------------------------------------------------------
    if not sender or not sender.email or "@" not in sender.email:
        add("HIGH", "Missing or malformed From address", "", email.header("from"))
    if len(senders) > 1:
        add("MEDIUM", "Multiple From addresses", "", info.from_)

    from_dom = info.from_domain
    from_reg = domains.registered_domain(from_dom)
    if sender:
        m = EMAIL_IN_TEXT_RE.search(sender.name)
        if m:
            shown = _domain(m.group(0))
            if domains.registered_domain(shown) != from_reg:
                add("HIGH", "Display name contains a different email address",
                    "The name shows one address while the message really comes from another.",
                    info.from_)
        brand = domains.brand_mentioned(sender.name)
        if brand and from_dom and not domains.is_official(brand, from_dom):
            sev = "HIGH" if domains.is_freemail(from_dom) else "MEDIUM"
            add(sev, f"Display name claims to be '{brand}' but sender domain is not {brand}'s",
                f"Sender domain {from_dom} is not an official {brand} domain.", info.from_)

    if from_dom:
        look = domains.lookalike_brand(from_dom)
        if look:
            add("HIGH", f"Sender domain imitates {look[0]} ({look[1]})", "", from_dom)
        if "xn--" in from_dom:
            add("HIGH", "Sender domain uses punycode (possible homograph)",
                f"Decodes to: {domains.to_unicode(from_dom)}", from_dom)
        brand = domains.brand_mentioned(from_dom)
        if brand and not domains.is_official(brand, from_dom) and not look:
            add("MEDIUM", f"Sender domain contains brand name '{brand}' but is not official", "", from_dom)
        if from_dom.rsplit(".", 1)[-1] in domains.SUSPICIOUS_TLDS:
            add("MEDIUM", "Sender uses a high-risk top-level domain", "", from_dom)
        if domains.is_freemail(from_dom):
            add("INFO", "Sent from a free webmail account", "", from_dom)

    # --- Reply-To / Return-Path / Message-ID --------------------------------
    for rt in email.reply_to:
        rt_reg = domains.registered_domain(rt.domain)
        if rt.domain and from_reg and rt_reg != from_reg:
            if domains.is_freemail(rt.domain) and not domains.is_freemail(from_dom):
                add("HIGH", "Replies go to a free webmail address, not the sender's domain",
                    "Classic BEC / phishing setup: answers are routed to an attacker mailbox.", str(rt))
            else:
                add("MEDIUM", "Reply-To domain differs from From domain", "", f"{rt} vs {from_dom}")

    rp_dom = _domain(info.return_path)
    if rp_dom and from_reg and domains.registered_domain(rp_dom) != from_reg:
        add("LOW", "Envelope sender (Return-Path) domain differs from From domain",
            "Normal for newsletters/ESPs, suspicious for personal or transactional mail.",
            f"{info.return_path} vs {from_dom}")

    mid_dom = info.message_id.strip("<> ").rpartition("@")[2].lower()
    if not info.message_id:
        add("LOW", "Missing Message-ID header")
    elif mid_dom and from_reg and domains.registered_domain(mid_dom) != from_reg:
        add("INFO", "Message-ID domain differs from From domain", "", info.message_id)

    if info.mailer and SUSPICIOUS_MAILERS.search(info.mailer):
        add("LOW", "Sent with a bulk/scripted mailer", "", info.mailer)

    # --- Date ---------------------------------------------------------------
    if not info.date:
        add("LOW", "Missing Date header")
    else:
        try:
            sent = parsedate_to_datetime(info.date)
            if sent.tzinfo is None:
                sent = sent.replace(tzinfo=timezone.utc)
            if sent - datetime.now(timezone.utc) > timedelta(days=1):
                add("LOW", "Date header is in the future", "", info.date)
        except (TypeError, ValueError, IndexError):
            add("LOW", "Malformed Date header", "", info.date)

    # --- Authentication (SPF / DKIM / DMARC) ---------------------------------
    auth = info.auth
    if not auth:
        add("INFO", "No SPF/DKIM/DMARC results in headers",
            "The message may have been exported without the receiving server's headers; "
            "use the full original source ('Show original' / 'View source').", category="auth")
    else:
        spf, dkim, dmarc = auth.get("spf"), auth.get("dkim"), auth.get("dmarc")
        if spf == "fail":
            add("HIGH", "SPF failed - sending server not authorised for this domain", "", f"spf={spf}",
                category="auth")
        elif spf == "softfail":
            add("MEDIUM", "SPF softfail", "", f"spf={spf}", category="auth")
        elif spf in ("none", "neutral", "permerror", "temperror"):
            add("LOW", f"SPF result: {spf}", "", category="auth")
        if dkim == "fail":
            add("HIGH", "DKIM signature failed - message altered or forged", "", f"dkim={dkim}",
                category="auth")
        elif dkim in ("none", "neutral", "permerror", "temperror", "policy"):
            add("LOW", f"No valid DKIM signature ({dkim})", "", category="auth")
        if dmarc == "fail":
            add("HIGH", "DMARC failed - From domain is likely spoofed", "", f"dmarc={dmarc}",
                category="auth")
        elif dmarc in ("none", "permerror", "temperror", "bestguesspass"):
            add("LOW", f"DMARC result: {dmarc}", "", category="auth")
        if auth.get("compauth") == "fail":
            add("HIGH", "Microsoft composite authentication failed (compauth=fail)", "", category="auth")
        if dkim == "pass" and info.dkim_domains and from_reg and not any(
                domains.registered_domain(d) == from_reg for d in info.dkim_domains):
            add("INFO", "DKIM signed by a different domain than From", "",
                ", ".join(info.dkim_domains), category="auth")

    return info, findings
