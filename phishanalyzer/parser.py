"""Parse raw RFC 822 / .eml data into a structure the checks can work with."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.header import decode_header, make_header
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser

URL_RE = re.compile(r"""(?:\b(?:https?|ftp)://|\bwww\.)[^\s<>"'`{}|\\^\[\]]+""", re.IGNORECASE)
_TRAILING = ".,;:!?)]}'\"*>"
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
MAX_PARTS = 500


class EmailParseError(ValueError):
    pass


@dataclass
class Address:
    name: str
    email: str

    @property
    def domain(self) -> str:
        return self.email.rpartition("@")[2].lower().strip("<>[] ") if "@" in self.email else ""

    def __str__(self) -> str:
        return f'"{self.name}" <{self.email}>' if self.name else f"<{self.email}>"


@dataclass
class Link:
    url: str
    text: str = ""       # visible anchor text, for HTML links
    source: str = "body"  # body | html | form | iframe | refresh | attachment:<name>


@dataclass
class Attachment:
    filename: str
    content_type: str
    data: bytes = field(repr=False)
    inline: bool = False


@dataclass
class ParsedEmail:
    headers: list[tuple[str, str]]          # decoded, unfolded, in original order
    raw_headers: list[tuple[str, str]]      # undecoded (needed for address parsing)
    text: str = ""
    html: str = ""
    html_text: str = ""                     # visible text extracted from the HTML part
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    html_tags: dict[str, int] = field(default_factory=dict)
    defects: list[str] = field(default_factory=list)

    def header(self, name: str, default: str = "") -> str:
        values = self.header_all(name)
        return values[0] if values else default

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    def _addresses(self, name: str) -> list[Address]:
        raw = [v for k, v in self.raw_headers if k.lower() == name.lower()]
        out = []
        for display, addr in getaddresses([_unfold(v) for v in raw]):
            if display or addr:
                out.append(Address(_decode(display).strip(), addr.strip()))
        return out

    @property
    def subject(self) -> str:
        return self.header("subject")

    @property
    def from_(self) -> list[Address]:
        return self._addresses("from")

    @property
    def reply_to(self) -> list[Address]:
        return self._addresses("reply-to")

    @property
    def to(self) -> list[Address]:
        return self._addresses("to")

    @property
    def return_path(self) -> str:
        return self.header("return-path").strip().strip("<>").strip()


def _unfold(value: str) -> str:
    return re.sub(r"\r?\n[ \t]+", " ", str(value)).strip()


def _decode(value: str) -> str:
    value = _unfold(value)
    try:
        return str(make_header(decode_header(value)))
    except Exception:  # malformed encoded-words are common in phishing; keep the raw text
        return value


class _HTMLScanner(HTMLParser):
    """Collect links (with their visible text), visible text and risky tags."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.text: list[str] = []
        self.tags: dict[str, int] = {}
        self._anchor: tuple[str, list[str]] | None = None
        self._skip = 0

    def _count(self, key: str) -> None:
        self.tags[key] = self.tags.get(key, 0) + 1

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("a", "area") and a.get("href"):
            if tag == "a":
                self._anchor = (a["href"], [])
            else:
                self.links.append(Link(a["href"].strip(), a.get("alt", ""), "html"))
        elif tag == "form":
            self._count("form")
            if a.get("action"):
                self.links.append(Link(a["action"].strip(), "", "form"))
        elif tag == "input" and a.get("type", "").lower() == "password":
            self._count("password")
        elif tag in ("iframe", "frame", "embed", "object"):
            self._count("iframe")
            src = a.get("src") or a.get("data")
            if src:
                self.links.append(Link(src.strip(), "", "iframe"))
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            self._count("meta-refresh")
            m = re.search(r"url\s*=\s*['\"]?([^'\" >]+)", a.get("content", ""), re.I)
            if m:
                self.links.append(Link(m.group(1), "", "refresh"))
        elif tag == "img":
            self._count("img")
        if tag in ("script", "style"):
            if tag == "script":
                self._count("script")
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._anchor:
            href, parts = self._anchor
            self.links.append(Link(href.strip(), re.sub(r"\s+", " ", "".join(parts)).strip(), "html"))
            self._anchor = None
        elif tag in ("p", "div", "br", "tr", "li", "td", "h1", "h2", "h3"):
            self.text.append("\n")

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._anchor:
            self._anchor[1].append(data)


def extract_urls(text: str) -> list[str]:
    urls = []
    for m in URL_RE.finditer(text):
        url = m.group(0).rstrip(_TRAILING)
        if len(url) > 8:
            urls.append(url)
    return urls


def _url_key(url: str) -> str:
    """Normalise for de-duplication: 'https://www.x.com/a/' == 'www.x.com/a'."""
    return re.sub(r"^(?:[a-z]+://)?(?:www\.)?", "", url.strip().lower()).rstrip("/")


def _decode_part(part: Message) -> str:
    payload = part.get_payload(decode=True) or b""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _filename(part: Message) -> str:
    try:
        name = part.get_filename()
    except Exception:
        name = part.get_param("name")
    if isinstance(name, tuple):  # RFC 2231 tuple from get_param
        name = name[2]
    return _decode(name) if name else ""


def _walk(part: Message, email: ParsedEmail, depth: int = 0) -> None:
    if depth > 25 or len(email.attachments) > MAX_PARTS:
        return
    ctype = part.get_content_type()
    if ctype == "message/rfc822":
        try:
            inner = part.get_payload(0)
            data = inner.as_bytes()
        except Exception:
            data = b""
        email.attachments.append(Attachment(_filename(part) or "attached-message.eml", ctype, data))
        return
    if part.is_multipart():
        payload = part.get_payload()
        for sub in payload if isinstance(payload, list) else []:
            _walk(sub, email, depth + 1)
        return

    filename = _filename(part)
    disposition = part.get_content_disposition()
    if filename or disposition == "attachment" or ctype not in ("text/plain", "text/html"):
        try:
            data = part.get_payload(decode=True) or b""
        except Exception:
            data = b""
        email.attachments.append(Attachment(filename or "(unnamed)", ctype, data, disposition == "inline"))
    elif ctype == "text/html":
        email.html += _decode_part(part) + "\n"
    else:
        email.text += _decode_part(part) + "\n"


def parse_bytes(data: bytes) -> ParsedEmail:
    if data.startswith(_OLE_MAGIC):
        raise EmailParseError("this looks like an Outlook .msg file - save/export the message as .eml "
                              "(Outlook: File > Save As, or drag it into a folder from a webmail client) "
                              "and analyse that instead")
    if not data.strip():
        raise EmailParseError("file is empty")

    msg = BytesParser(policy=policy.default).parsebytes(data)
    raw = [(k, str(v)) for k, v in msg.raw_items()]
    if not raw:
        raise EmailParseError("no email headers found - is this an .eml / raw message source?")

    email = ParsedEmail(headers=[(k, _decode(v)) for k, v in raw], raw_headers=raw)
    email.defects = [type(d).__name__ for d in msg.defects]
    _walk(msg, email)

    if email.html:
        scanner = _HTMLScanner()
        try:
            scanner.feed(email.html)
            scanner.close()
        except Exception:
            pass
        email.html_text = re.sub(r"[ \t\r\f\v]+", " ", "".join(scanner.text)).strip()
        email.html_tags = scanner.tags
        email.links.extend(scanner.links)

    seen = {_url_key(link.url) for link in email.links}
    for url in extract_urls(email.text) + extract_urls(email.html_text):
        if _url_key(url) not in seen:
            seen.add(_url_key(url))
            email.links.append(Link(url, "", "body"))
    return email


def parse_file(path: str) -> ParsedEmail:
    with open(path, "rb") as fh:
        return parse_bytes(fh.read())
