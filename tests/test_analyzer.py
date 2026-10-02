import io
import json
import os
import sys
import unittest
import zipfile
from contextlib import redirect_stdout
from email.message import EmailMessage

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "samples"))

from phishanalyzer import cli, domains  # noqa: E402
from phishanalyzer.analyzer import analyze_bytes  # noqa: E402
from phishanalyzer.attachments import analyze_attachments  # noqa: E402
from phishanalyzer.links import check_url, unwrap  # noqa: E402
from phishanalyzer.parser import Attachment, EmailParseError, parse_bytes  # noqa: E402
import generate_samples  # noqa: E402


def titles(report):
    return {f.title for f in report.findings}


def url_titles(url, text=""):
    return {title for _, title, _ in check_url(url, text)[1]}


def simple_email(**headers) -> EmailMessage:
    m = EmailMessage()
    m["From"] = headers.pop("From", '"Alice" <alice@example.com>')
    m["To"] = "bob@example.org"
    m["Subject"] = headers.pop("Subject", "Hello")
    m["Date"] = "Wed, 30 Sep 2026 08:00:00 +0000"
    m["Message-ID"] = "<1@example.com>"
    for k, v in headers.items():
        m[k.replace("_", "-")] = v
    m.set_content("Hi Bob, see you tomorrow.")
    return m


class SampleVerdicts(unittest.TestCase):
    def test_phishing_samples_flagged(self):
        for build in (generate_samples.phishing_paypal, generate_samples.html_attachment_lure):
            r = analyze_bytes(bytes(build()))
            self.assertEqual(r.verdict, "PHISHING / MALICIOUS", build.__name__)

    def test_legitimate_sample_clean(self):
        r = analyze_bytes(bytes(generate_samples.legitimate_newsletter()))
        self.assertEqual(r.score, 0, [f.title for f in r.findings])

    def test_paypal_sample_key_indicators(self):
        t = titles(analyze_bytes(bytes(generate_samples.phishing_paypal())))
        self.assertIn("Double extension disguises an executable (e.g. invoice.pdf.exe)", t)
        self.assertIn("Sender domain imitates paypal (homoglyph/character substitution)", t)
        self.assertIn("Replies go to a free webmail address, not the sender's domain", t)
        self.assertIn("DMARC failed - From domain is likely spoofed", t)
        self.assertIn("Link text shows a different domain than the real target", t)


class Domains(unittest.TestCase):
    def test_registered_domain(self):
        self.assertEqual(domains.registered_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(domains.registered_domain("login.paypal.com"), "paypal.com")

    def test_lookalikes(self):
        self.assertEqual(domains.lookalike_brand("paypa1.com")[0], "paypal")
        self.assertEqual(domains.lookalike_brand("rnicrosoft-login.net")[0], "microsoft")
        self.assertEqual(domains.lookalike_brand("xn--pypal-4ve.com")[0], "paypal")  # Cyrillic 'а'
        self.assertEqual(domains.lookalike_brand("netfllx.com")[0], "netflix")
        for legit in ("paypal.com", "microsoft.com", "example.com", "github.com", "amazonaws.com"):
            self.assertIsNone(domains.lookalike_brand(legit), legit)


class Links(unittest.TestCase):
    def test_official_link_is_clean(self):
        self.assertEqual(url_titles("https://www.paypal.com/signin", "www.paypal.com"), set())

    def test_ip_and_userinfo(self):
        self.assertIn("Link points to a raw IP address instead of a domain", url_titles("http://1.2.3.4/x"))
        self.assertIn("URL contains '@' - the real destination is the part after it",
                      url_titles("https://paypal.com@evil.example/login"))

    def test_mismatched_text(self):
        self.assertIn("Link text shows a different domain than the real target",
                      url_titles("https://evil.example/a", "https://www.mybank.com"))

    def test_unwrap_safelinks(self):
        wrapped = ("https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Fx"
                   "&data=abc")
        self.assertEqual(unwrap(wrapped), "https://evil.example/x")

    def test_dangerous_download(self):
        self.assertIn("Link downloads an executable/script file", url_titles("https://cdn.example/setup.exe"))


class Attachments(unittest.TestCase):
    def _flags(self, name, data, ctype="application/octet-stream"):
        results, _, links = analyze_attachments([Attachment(name, ctype, data)])
        return set(results[0].flags), links

    def test_disguised_executable(self):
        flags, _ = self._flags("report.pdf", b"MZ" + b"\x00" * 64)
        self.assertIn("Windows executable disguised as .pdf file", flags)

    def test_ooxml_macro_and_remote_template(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("word/document.xml", "<w:document/>")
            z.writestr("word/vbaProject.bin", b"\x00")
            z.writestr("word/_rels/settings.xml.rels",
                       '<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/'
                       'officeDocument/2006/relationships/attachedTemplate" Target="http://evil.example/t.dotm" '
                       'TargetMode="External"/></Relationships>')
        flags, links = self._flags("offer.docm", buf.getvalue())
        self.assertIn("Office document contains VBA macros", flags)
        self.assertIn("Remote template / external object injection", flags)
        self.assertIn("http://evil.example/t.dotm", [l.url for l in links])

    def test_encrypted_zip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("invoice.js", b"x")
        data = bytearray(buf.getvalue())
        # zipfile can't write encrypted entries; set the "encrypted" flag bit in the central directory
        cd = data.find(b"PK\x01\x02")
        data[cd + 8] |= 0x1
        flags, _ = self._flags("docs.zip", bytes(data))
        self.assertIn("Password-protected archive (contents hidden from security scanners)", flags)
        self.assertIn("Archive contains an executable, script or disk image", flags)

    def test_pdf_javascript_and_links(self):
        pdf = (b"%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n"
               b"2 0 obj << /S /JavaScript /JS (app.alert(1)) >> endobj\n"
               b"3 0 obj << /Type /Page /Annots [<< /A << /URI (https://evil.example/login) >> >>] >> endobj\n")
        flags, links = self._flags("statement.pdf", pdf, "application/pdf")
        self.assertIn("PDF runs JavaScript automatically when opened", flags)
        self.assertIn("https://evil.example/login", [l.url for l in links])

    def test_rtlo_filename(self):
        flags, _ = self._flags("invoice‮fdp.exe", b"MZ")
        self.assertIn("Filename uses right-to-left override to hide its real extension", flags)


class Parsing(unittest.TestCase):
    def test_outlook_msg_rejected_with_help(self):
        with self.assertRaises(EmailParseError):
            parse_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100)

    def test_encoded_headers_decoded(self):
        m = simple_email(Subject="=?utf-8?b?w4RyZ2VyIGltIEJ1cm8=?=")
        self.assertEqual(parse_bytes(bytes(m)).subject, "Ärger im Buro")

    def test_plain_email_clean(self):
        m = simple_email(Authentication_Results="mx; spf=pass; dkim=pass header.d=example.com; dmarc=pass")
        r = analyze_bytes(bytes(m))
        self.assertEqual(r.verdict, "NO STRONG INDICATORS", [f.title for f in r.findings])

    def test_display_name_brand_from_freemail(self):
        m = simple_email(From='"Netflix Billing" <netflix.billing.team@gmail.com>')
        self.assertIn("Display name claims to be 'netflix' but sender domain is not netflix's",
                      titles(analyze_bytes(bytes(m))))


class Cli(unittest.TestCase):
    def test_json_output_and_fail_on(self):
        path = os.path.join(ROOT, "samples", "phishing_paypal.eml")
        with open(path, "wb") as fh:
            fh.write(bytes(generate_samples.phishing_paypal()))
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main([path, "--json", "-", "--fail-on", "suspicious"])
        self.assertEqual(code, 2)
        data = json.loads(out.getvalue())
        self.assertEqual(data["reports"][0]["verdict"], "PHISHING / MALICIOUS")


if __name__ == "__main__":
    unittest.main()
