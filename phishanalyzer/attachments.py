"""Attachment checks: dangerous types, disguised files, macros, PDF/HTML/archive internals.

Attachments are only ever read as bytes - nothing is executed or written to disk.
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
import zlib
from dataclasses import dataclass, field

from .findings import Finding
from .parser import Attachment, Link, extract_urls

EXECUTABLE_EXT = {
    "exe", "scr", "com", "pif", "cpl", "msi", "msp", "bat", "cmd", "ps1", "psm1", "vbs", "vbe",
    "js", "jse", "wsf", "wsh", "hta", "lnk", "jar", "reg", "scf", "inf", "dll", "chm", "one",
    "xll", "url", "library-ms", "settingcontent-ms", "appx", "msix", "appinstaller", "application",
    "gadget", "sh", "command", "app", "apk", "dmg", "pkg", "py", "pyw",
}
DISK_IMAGE_EXT = {"iso", "img", "vhd", "vhdx"}
MACRO_EXT = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm", "xlsb"}
OOXML_EXT = MACRO_EXT | {"docx", "dotx", "xlsx", "xltx", "pptx", "potx", "ppsx", "sldx"}
OLE_EXT = {"doc", "dot", "xls", "xlt", "ppt", "pps", "msg"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "cab", "ace", "arj", "lzh", "uue", "z"}
HTML_EXT = {"html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml", "xht"}
DECOY_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png",
             "gif", "csv", "zip", "mp3", "mp4", "wav", "html", "htm", "odt"}
BIDI_CONTROLS = "‪‫‬‭‮⁦⁧⁨⁩‎‏"

MAGIC = [
    (b"MZ", "pe"), (b"\x7fELF", "elf"), (b"%PDF", "pdf"), (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"), (b"Rar!\x1a\x07", "rar"), (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"), (b"MSCF", "cab"), (b"{\\rt", "rtf"), (b"\x89PNG", "png"), (b"\xff\xd8\xff", "jpeg"),
    (b"GIF8", "gif"), (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"), (b"\xcf\xfa\xed\xfe", "macho"),
]
# extension -> content types it may legitimately have
EXPECTED = {
    "pdf": {"pdf"}, "rtf": {"rtf"}, "zip": {"zip"}, "jar": {"zip"}, "rar": {"rar"}, "7z": {"7z"},
    "gz": {"gzip"}, "tgz": {"gzip"}, "cab": {"cab"}, "png": {"png"}, "jpg": {"jpeg"}, "jpeg": {"jpeg"},
    "gif": {"gif"}, "exe": {"pe"}, "dll": {"pe"}, "scr": {"pe"}, "iso": {"iso"}, "html": {"html"},
    "htm": {"html"}, "svg": {"svg", "html"}, "lnk": {"lnk"}, "txt": set(), "csv": set(),
    **{e: {"zip"} for e in OOXML_EXT}, **{e: {"ole", "rtf", "html"} for e in OLE_EXT},
}
PE_EXT = {"exe", "dll", "scr", "com", "pif", "cpl", "sys", "ocx", "drv", "efi", "msi", "mui"}
MAX_SCAN = 25 * 1024 * 1024


@dataclass
class AttachmentResult:
    filename: str
    content_type: str
    size: int
    detected_type: str
    md5: str
    sha1: str
    sha256: str
    flags: list[str] = field(default_factory=list)
    members: list[str] = field(default_factory=list)


def ext_of(name: str) -> str:
    name = name.lower().strip().rstrip(". ")
    tail = name.rsplit("/", 1)[-1]
    return tail.rsplit(".", 1)[1] if "." in tail else ""


def detect_type(data: bytes) -> str:
    for sig, kind in MAGIC:
        if data.startswith(sig):
            return kind
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    head = data[:2048].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if head.startswith(b"<svg") or (head.startswith(b"<?xml") and b"<svg" in head):
        return "svg"
    if head.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<script", b"<meta")) or b"<html" in head:
        return "html"
    return ""


class _Collector:
    def __init__(self, att: AttachmentResult):
        self.att = att
        self.findings: list[Finding] = []
        self.links: list[Link] = []

    def add(self, severity: str, title: str, detail: str = "", evidence: str = "") -> None:
        self.findings.append(Finding("attachment", severity, title, detail, [evidence or self.att.filename]))
        if title not in self.att.flags:
            self.att.flags.append(title)

    def urls(self, text: str, kind: str) -> None:
        for url in extract_urls(text)[:200]:
            self.links.append(Link(url, "", f"attachment:{self.att.filename}"))


def _check_name(c: _Collector, name: str, label: str | None = None) -> None:
    """Filename tricks; used for attachments and for files inside archives."""
    where = label or name
    ext = ext_of(name)
    parts = [p for p in name.lower().strip().split(".")[1:] if p]
    if any(ch in name for ch in BIDI_CONTROLS):
        c.add("CRITICAL", "Filename uses right-to-left override to hide its real extension", "", where)
    if ext in EXECUTABLE_EXT and len(parts) >= 2 and parts[-2].strip() in DECOY_EXT:
        c.add("CRITICAL", "Double extension disguises an executable (e.g. invoice.pdf.exe)", "", where)
    elif ext in EXECUTABLE_EXT and re.search(r"\s{3,}[^.]*\.\w+$", name):
        c.add("CRITICAL", "Filename padded with spaces to hide an executable extension", "", where)


def _check_zip(c: _Collector, data: bytes) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()[:2000]
    except (zipfile.BadZipFile, OSError, ValueError):
        c.add("MEDIUM", "Corrupt or malformed archive (may be crafted to evade scanners)")
        return
    c.att.members = [i.filename for i in infos]
    if any(i.flag_bits & 0x1 for i in infos):
        c.add("HIGH", "Password-protected archive (contents hidden from security scanners)")
    total = sum(i.file_size for i in infos)
    if total > 1_000_000_000 or (len(data) and total / len(data) > 200):
        c.add("MEDIUM", "Archive has an extreme compression ratio (possible zip bomb)")
    flagged = False
    for i in infos:
        e = ext_of(i.filename)
        label = f"{c.att.filename} -> {i.filename}"
        _check_name(c, i.filename, label)
        if e in EXECUTABLE_EXT or e in DISK_IMAGE_EXT:
            c.add("CRITICAL", "Archive contains an executable, script or disk image", "", label)
        elif e in MACRO_EXT:
            c.add("HIGH", "Archive contains a macro-enabled Office document", "", label)
        elif e in HTML_EXT:
            c.add("HIGH", "Archive contains an HTML/SVG file", "", label)
        elif e in ARCHIVE_EXT:
            c.add("MEDIUM", "Nested archive (archive inside an archive)", "", label)
        else:
            continue
        flagged = True
    if not flagged:
        c.add("LOW", "Archive attachment")


def _check_ooxml(c: _Collector, data: bytes) -> None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = zf.namelist()
    except (zipfile.BadZipFile, OSError, ValueError):
        c.add("MEDIUM", "Corrupt Office document (may be crafted to evade scanners)")
        return
    lower = [n.lower() for n in names]
    if any(n.endswith("vbaproject.bin") for n in lower):
        c.add("HIGH", "Office document contains VBA macros")
    if any("/activex/" in n for n in lower):
        c.add("MEDIUM", "Office document contains ActiveX controls")
    if any("/embeddings/" in n and not n.endswith((".xlsx", ".docx", ".png", ".emf", ".wmf")) for n in lower):
        c.add("MEDIUM", "Office document contains embedded OLE objects")
    for name in names:
        info = zf.getinfo(name)
        if info.file_size > 5_000_000:
            continue
        low = name.lower()
        if low.endswith(".rels"):
            xml = zf.read(name).decode("utf-8", "replace")
            for rel in re.findall(r"<Relationship\b[^>]*>", xml):
                if 'TargetMode="External"' not in rel:
                    continue
                target = (re.search(r'Target="([^"]*)"', rel) or [None, ""])[1]
                rtype = (re.search(r'Type="([^"]*)"', rel) or [None, ""])[1]
                if re.search(r"attachedTemplate|oleObject|frame|subDocument", rtype, re.I):
                    c.add("HIGH", "Remote template / external object injection",
                          "Document loads content from a remote server when opened.", f"{c.att.filename} -> {target}")
                if target.lower().startswith(("http", "\\\\", "file:")):
                    c.links.append(Link(target, "", f"attachment:{c.att.filename}"))
        elif low in ("word/document.xml", "xl/sharedstrings.xml") or re.match(r"ppt/slides/slide\d+\.xml", low):
            xml = zf.read(name).decode("utf-8", "replace")
            if re.search(r"\bDDE(AUTO)?\b", xml):
                c.add("HIGH", "Office document contains DDE field (runs commands without macros)")


def _check_ole(c: _Collector, data: bytes) -> None:
    blob = data[:MAX_SCAN]
    low = blob.lower()
    if b"_vba_project" in low or "_VBA_PROJECT".encode("utf-16le") in blob or b"\x00attribut\x00e" in low:
        c.add("HIGH", "Office document contains VBA macros")
        autos = [k for k in (b"autoopen", b"auto_open", b"document_open", b"workbook_open", b"autoexec",
                             b"document_close", b"auto_close") if k in low]
        if autos:
            c.add("CRITICAL", "Macro runs automatically when the document is opened", "",
                  f"{c.att.filename}: {', '.join(a.decode() for a in autos)}")
        sus = [k for k in (b"wscript.shell", b"powershell", b"urldownloadtofile", b"shell(", b"createobject",
                           b"msxml2.xmlhttp", b"adodb.stream", b"cmd.exe", b"mshta", b"regsvr32") if k in low]
        if sus:
            c.add("HIGH", "Macro code references download/execution functions", "",
                  f"{c.att.filename}: {', '.join(s.decode() for s in sus)}")
    if b"equation native" in low or b"equation.3" in low:
        c.add("HIGH", "Embedded Equation Editor object (exploited by CVE-2017-11882)")


def _pdf_blob(data: bytes) -> bytes:
    """Raw PDF plus best-effort inflated streams, with #xx name obfuscation decoded."""
    chunks = [data[:MAX_SCAN]]
    budget = MAX_SCAN
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", data[:MAX_SCAN], re.S):
        if budget <= 0:
            break
        try:
            out = zlib.decompressobj().decompress(m.group(1), budget)
        except zlib.error:
            continue
        budget -= len(out)
        chunks.append(out)
    blob = b"\n".join(chunks)
    return re.sub(rb"#([0-9a-fA-F]{2})", lambda m: bytes([int(m.group(1), 16)]), blob)


def _check_pdf(c: _Collector, data: bytes) -> None:
    blob = _pdf_blob(data)
    has_js = re.search(rb"/(JavaScript|JS)\b", blob)
    auto = re.search(rb"/(OpenAction|AA)\b", blob)
    if re.search(rb"/Launch\b", blob):
        c.add("CRITICAL", "PDF can launch external programs (/Launch action)")
    if has_js and auto:
        c.add("CRITICAL", "PDF runs JavaScript automatically when opened")
    elif has_js:
        c.add("HIGH", "PDF contains JavaScript")
    if re.search(rb"/EmbeddedFiles?\b", blob):
        c.add("MEDIUM", "PDF contains embedded files")
    if re.search(rb"/SubmitForm\b", blob):
        c.add("MEDIUM", "PDF form submits data to a remote server")
    if re.search(rb"/XFA\b", blob):
        c.add("LOW", "PDF uses XFA forms")
    uris = [u.decode("latin-1").strip() for u in re.findall(rb"/URI\s*\(([^)]{1,2000})\)", blob)]
    for uri in dict.fromkeys(uris):
        c.links.append(Link(uri, "", f"attachment:{c.att.filename}"))
    pages = len(re.findall(rb"/Type\s*/Page\b(?!s)", blob))
    if uris and pages <= 1 and len(set(uris)) <= 3:
        c.add("MEDIUM", "Single-page PDF built around a link (common PDF phishing lure)", "",
              f"{c.att.filename} -> {uris[0]}")


def _check_html(c: _Collector, data: bytes, kind: str) -> None:
    src = data[:MAX_SCAN].decode("utf-8", "replace")
    low = src.lower()
    c.add("HIGH", f"{kind.upper()} attachment (common credential-phishing / HTML smuggling vector)")
    if "<form" in low or re.search(r"type\s*=\s*['\"]?password", low):
        c.add("CRITICAL", "HTML attachment contains a login/password form")
    if ("atob(" in low or "base64," in low) and any(k in low for k in ("new blob", "createobjecturl",
                                                                       "mssaveoropenblob", "download=")):
        c.add("CRITICAL", "HTML smuggling - attachment builds and drops a file in the browser")
    if kind == "svg" and "<script" in low:
        c.add("HIGH", "SVG image contains JavaScript")
    if any(k in low for k in ("eval(", "unescape(", "fromcharcode", "document.write(atob", "\\x68\\x74\\x74\\x70")):
        c.add("HIGH", "Obfuscated JavaScript in HTML attachment")
    if any(k in low for k in ("window.location", "location.href", "location.replace", "http-equiv=\"refresh\"",
                              "http-equiv='refresh'", "http-equiv=refresh")):
        c.add("MEDIUM", "HTML attachment redirects the browser to a website")
    if re.search(r"(api\.telegram\.org/bot|discord(app)?\.com/api/webhooks|formspree\.io|submit-form\.com)", low):
        c.add("CRITICAL", "HTML attachment exfiltrates data to Telegram/Discord/form service")
    c.urls(src, "html")


def _check_rtf(c: _Collector, data: bytes) -> None:
    low = data[:MAX_SCAN].lower()
    if b"\\objdata" in low or b"\\objupdate" in low:
        c.add("HIGH", "RTF document contains embedded OLE objects")
    if b"equation" in low and b"\\objdata" in low:
        c.add("HIGH", "Embedded Equation Editor object (exploited by CVE-2017-11882)")


def analyze_attachments(attachments: list[Attachment]) -> tuple[list[AttachmentResult], list[Finding], list[Link]]:
    results, findings, links = [], [], []
    for a in attachments:
        data = a.data
        kind = detect_type(data)
        res = AttachmentResult(a.filename, a.content_type, len(data), kind,
                               hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest(),
                               hashlib.sha256(data).hexdigest())
        c = _Collector(res)
        name, ext = a.filename, ext_of(a.filename)

        _check_name(c, name)
        if ext in DISK_IMAGE_EXT or kind == "iso":
            c.add("HIGH", "Disk image attachment (used to bypass Mark-of-the-Web protections)")
        elif ext in EXECUTABLE_EXT:
            c.add("CRITICAL", f"Executable or script attachment (.{ext})")
        if kind == "pe" and ext not in PE_EXT:
            c.add("CRITICAL", f"Windows executable disguised as .{ext or 'unknown'} file")
        elif kind in ("elf", "macho") and ext not in ("", "bin", "so", "dylib"):
            c.add("HIGH", f"{kind.upper()} executable disguised as .{ext or 'unknown'} file")
        elif kind and ext in EXPECTED and EXPECTED[ext] and kind not in EXPECTED[ext]:
            c.add("HIGH", "File content does not match its extension", f".{ext} file is actually {kind.upper()}")
        if ext in MACRO_EXT:
            c.add("HIGH", f"Macro-enabled Office document (.{ext})")

        if a.content_type == "message/rfc822":
            c.add("INFO", "Attached email message - save it and analyse it separately")
            c.urls(data.decode("utf-8", "replace"), "eml")
        elif kind == "zip" and ext in OOXML_EXT:
            _check_ooxml(c, data)
        elif kind == "zip":
            _check_zip(c, data)
        elif kind == "ole" or (not kind and ext in OLE_EXT):
            _check_ole(c, data)
        elif kind == "pdf":
            _check_pdf(c, data)
        elif kind in ("html", "svg") or ext in HTML_EXT:
            _check_html(c, data, kind or ("svg" if ext == "svg" else "html"))
        elif kind == "rtf":
            _check_rtf(c, data)
        elif kind in ("rar", "7z", "gzip", "cab") or ext in ARCHIVE_EXT:
            c.add("MEDIUM", "Archive attachment that could not be inspected (RAR/7z/...)")
        elif a.content_type.startswith("text/") or ext in ("ics", "txt", "csv", "vcf"):
            c.urls(data[:MAX_SCAN].decode("utf-8", "replace"), "text")

        results.append(res)
        findings += c.findings
        links += c.links
    return results, findings, links
