"""URL checks: obfuscation, lookalike domains, deceptive link text, risky hosting."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlsplit

from . import domains
from .findings import Finding
from .parser import Link

DANGEROUS_DOWNLOAD_EXT = {
    "exe", "scr", "com", "pif", "cpl", "msi", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse",
    "wsf", "hta", "lnk", "jar", "iso", "img", "vhd", "vhdx", "apk", "dmg", "pkg", "appx", "msix",
    "appinstaller", "reg", "dll", "one", "xll", "url", "library-ms",
}
RISKY_DOWNLOAD_EXT = {"zip", "rar", "7z", "gz", "docm", "xlsm", "pptm", "xlsb", "doc", "xls", "html", "htm", "svg"}
CREDENTIAL_RE = re.compile(r"log-?in|sign-?in|verify|verification|account|secure|update|password|passwd|"
                           r"credential|wallet|banking|webscr|auth|unlock|suspend|confirm|validate|"
                           r"recover|billing|invoice|office365|o365|owa|mfa|2fa", re.I)
SHOWN_URL_RE = re.compile(r"^(?:https?://)?(?:www\.)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})"
                          r"(?:[:/?#]\S*)?$", re.I)
NON_WEB = ("mailto:", "tel:", "sms:", "cid:", "#", "about:blank")


@dataclass
class LinkResult:
    url: str
    host: str
    text: str
    source: str
    unwrapped_from: str = ""
    flags: list[str] = field(default_factory=list)

    @property
    def suspicious(self) -> bool:
        return bool(self.flags)


def _with_scheme(url: str) -> str:
    if re.match(r"^[a-z][a-z0-9+.-]*:", url, re.I):
        return url
    return "http://" + url.lstrip("/")


def unwrap(url: str) -> str:
    """Undo well-known link-protection / redirect wrappers so the real target is checked."""
    try:
        parts = urlsplit(_with_scheme(url))
        host = (parts.hostname or "").lower()
        qs = parse_qs(parts.query)
    except ValueError:
        return url
    if host.endswith("safelinks.protection.outlook.com") and "url" in qs:
        return qs["url"][0]
    if host == "urldefense.com" and "/v3/__" in url:
        m = re.search(r"/v3/__(.+?)__;", url)
        if m:
            return m.group(1)
    if host == "urldefense.proofpoint.com" and "u" in qs:
        return unquote(qs["u"][0].replace("-", "%").replace("_", "/"))
    if host.endswith("google.com") and parts.path == "/url":
        for key in ("q", "url"):
            if key in qs:
                return qs[key][0]
    if host in ("l.facebook.com", "lm.facebook.com") and "u" in qs:
        return qs["u"][0]
    return url


def _embedded_urls(query: str) -> list[str]:
    """URLs hidden in query parameters (open redirects), including base64-encoded ones."""
    found = []
    for values in parse_qs(query).values():
        for v in values:
            v = v.strip()
            if re.match(r"^(https?:)?//", v, re.I):
                found.append(v)
                continue
            if len(v) >= 16 and re.fullmatch(r"[A-Za-z0-9+/_=-]+", v):
                try:
                    decoded = base64.urlsafe_b64decode(v + "=" * (-len(v) % 4)).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    continue
                if re.match(r"^https?://", decoded):
                    found.append(decoded)
    return found


def check_url(url: str, text: str = "", source: str = "body") -> tuple[str, list[tuple[str, str, str]]]:
    """Return (host, [(severity, title, detail), ...]) for a single URL."""
    issues: list[tuple[str, str, str]] = []
    lower = url.lower().strip()
    scheme_match = re.match(r"^([a-z][a-z0-9+.-]*):", lower)
    scheme = scheme_match.group(1) if scheme_match else "http"

    if scheme in ("javascript", "vbscript", "data"):
        issues.append(("HIGH", "Link runs script or embeds data (javascript:/data: URI)", url[:120]))
        return "", issues
    if scheme == "file" or lower.startswith("\\\\"):
        issues.append(("HIGH", "Link to a local/network file (can leak Windows credentials)", ""))
        return "", issues
    if scheme not in ("http", "https", "ftp"):
        return "", issues

    try:
        parts = urlsplit(_with_scheme(url))
        host = (parts.hostname or "").rstrip(".").lower()
    except ValueError:
        issues.append(("MEDIUM", "Malformed URL", ""))
        return "", issues
    if not host:
        return "", issues
    try:
        port = parts.port
    except ValueError:
        port = None

    reg = domains.registered_domain(host)
    path = unquote(parts.path or "")

    if "@" in parts.netloc:
        issues.append(("HIGH", "URL contains '@' - the real destination is the part after it",
                       f"Browser goes to {host}"))
    if domains.is_ip(host):
        issues.append(("HIGH", "Link points to a raw IP address instead of a domain", ""))
    elif re.fullmatch(r"(0x[0-9a-f]+|\d{8,10})", host):
        issues.append(("HIGH", "Obfuscated (hex/decimal) IP address in link", ""))
    else:
        if "xn--" in host or not host.isascii():
            issues.append(("HIGH", "Internationalised (punycode) domain - possible homograph attack",
                           f"Displays as: {domains.to_unicode(host)}"))
        brand = domains.brand_mentioned(host)
        look = domains.lookalike_brand(host)
        if look:
            issues.append(("HIGH", f"Lookalike domain imitating {look[0]} ({look[1]})", ""))
        elif brand and not domains.is_official(brand, host):
            issues.append(("HIGH", f"Brand name '{brand}' used on an unrelated domain",
                           f"{reg} is not an official {brand} domain"))
        tld = reg.rsplit(".", 1)[-1]
        if tld in domains.SUSPICIOUS_TLDS:
            issues.append(("MEDIUM", "Link uses a high-risk top-level domain", f".{tld}"))
        if reg in domains.URL_SHORTENERS or host in domains.URL_SHORTENERS:
            issues.append(("MEDIUM", "URL shortener hides the real destination", ""))
        if any(host == h or host.endswith("." + h) for h in domains.FREE_HOSTING):
            issues.append(("MEDIUM", "Link hosted on a free/abused hosting platform", ""))
        if host.count(".") >= 4:
            issues.append(("LOW", "Unusually deep subdomain chain", ""))

    if port and port not in (80, 443):
        issues.append(("LOW", "Link uses a non-standard port", f":{port}"))

    ext = path.rsplit("/", 1)[-1].rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    if ext in DANGEROUS_DOWNLOAD_EXT:
        issues.append(("HIGH", "Link downloads an executable/script file", f".{ext}"))
    elif ext in RISKY_DOWNLOAD_EXT:
        issues.append(("MEDIUM", "Link downloads an archive/macro document/HTML file", f".{ext}"))

    official = domains.is_any_official(host)
    if not official and CREDENTIAL_RE.search(host + path):
        if scheme == "http":
            issues.append(("MEDIUM", "Login/account-themed link over unencrypted HTTP", ""))
        else:
            issues.append(("LOW", "Login/account-themed URL on a non-brand domain", ""))
    if len(url) > 250 or url.count("%") > 20:
        issues.append(("LOW", "Very long or heavily encoded URL", ""))

    # Deceptive link text: shows one domain, goes to another
    shown = SHOWN_URL_RE.match(text.strip()) if text else None
    if shown:
        shown_host = shown.group(1).lower()
        shown_reg = domains.registered_domain(shown_host)
        if shown_reg != reg and not (domains.is_any_official(shown_host) and official
                                     and domains.brand_mentioned(shown_host) == domains.brand_mentioned(host)):
            sev = "HIGH" if (domains.is_any_official(shown_host) or issues) else "MEDIUM"
            issues.append((sev, "Link text shows a different domain than the real target",
                           f"shows '{shown_host}' but goes to '{host}'"))

    if source == "form":
        issues.append(("HIGH", "HTML form in email submits data to this URL", ""))

    return host, issues


def analyze_links(links: list[Link]) -> tuple[list[LinkResult], list[Finding]]:
    results: list[LinkResult] = []
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def process(url: str, text: str, source: str, wrapped_from: str = "", depth: int = 0) -> None:
        key = (url, text)
        if key in seen or depth > 3:
            return
        seen.add(key)
        host, issues = check_url(url, text, source)
        result = LinkResult(url, host, text, source, wrapped_from)
        for severity, title, detail in issues:
            result.flags.append(title)
            findings.append(Finding("link", severity, title, detail if detail else "", [url]))
        results.append(result)

        inner = unwrap(url)
        if inner != url:
            process(inner, text, source, url, depth + 1)
            return
        try:
            query = urlsplit(_with_scheme(url)).query
        except ValueError:
            return
        for embedded in _embedded_urls(query):
            title = "Link redirects through another site to a hidden URL"
            result.flags.append(title)
            findings.append(Finding("link", "MEDIUM", title, "", [url]))
            process(embedded, "", source, url, depth + 1)

    for link in links:
        url = link.url.strip()
        if not url or url.lower().startswith(NON_WEB):
            continue
        process(url, link.text, link.source)

    # Detail is URL-specific; keep it as evidence so merged findings stay readable
    for f in findings:
        if f.detail:
            f.evidence = [f"{f.evidence[0]}  ({f.detail})"]
            f.detail = ""
    return results, findings
