"""Domain helpers: registered-domain extraction, brand impersonation and lookalike detection.

No public-suffix list is bundled, so ``registered_domain`` is an approximation that
handles common multi-level suffixes (co.uk, com.au, ...). Good enough for heuristics.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata

MULTI_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz",
    "co.jp", "ne.jp", "or.jp", "co.in", "net.in", "org.in", "gov.in", "co.za", "org.za",
    "com.br", "net.br", "org.br", "com.mx", "com.ar", "com.co", "com.cn", "net.cn", "org.cn",
    "com.hk", "com.sg", "com.tw", "com.tr", "co.kr", "or.kr", "com.my", "com.ph", "com.pk",
    "com.ng", "com.eg", "com.sa", "co.il", "co.id", "co.th", "com.vn", "com.ua", "com.pl",
}

FREEMAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "ymail.com", "aol.com", "icloud.com", "me.com", "mac.com", "proton.me",
    "protonmail.com", "gmx.com", "gmx.net", "gmx.de", "gmx.ch", "web.de", "mail.com",
    "mail.ru", "yandex.com", "yandex.ru", "zoho.com", "tutanota.com", "tuta.io",
    "qq.com", "163.com", "126.com", "seznam.cz", "bluewin.ch", "libero.it", "orange.fr",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "country",
    "kim", "work", "rest", "cam", "icu", "buzz", "monster", "cyou", "sbs", "cfd", "lol",
    "quest", "support", "fit", "loan", "win", "bid", "date", "racing", "download", "stream",
    "review", "party", "trade", "accountant", "men", "gdn", "ru.com", "su", "best", "bar",
}

URL_SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "bit.do",
    "v.gd", "shorte.st", "adf.ly", "lnkd.in", "qrco.de", "short.io", "tiny.one", "rotf.lol",
}

# Legit platforms that are heavily abused to host phishing pages
FREE_HOSTING = (
    "firebaseapp.com", "web.app", "pages.dev", "workers.dev", "netlify.app", "vercel.app",
    "github.io", "herokuapp.com", "glitch.me", "000webhostapp.com", "weebly.com",
    "wixsite.com", "blogspot.com", "sites.google.com", "forms.gle", "ipfs.io", "dweb.link",
    "r2.dev", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "azurewebsites.net",
    "blob.core.windows.net", "web.core.windows.net", "storage.googleapis.com",
    "firebasestorage.googleapis.com", "s3.amazonaws.com", "translate.goog", "replit.app",
    "square.site", "webflow.io", "framer.app", "notion.site", "typedream.app", "jimdosite.com",
)

_MS = ("microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com",
       "office365.com", "sharepoint.com", "onedrive.com", "msn.com", "azure.com", "bing.com",
       "skype.com", "microsoft365.com", "windows.com", "msauth.net", "aka.ms")
_GOOGLE = ("google.com", "gmail.com", "googlemail.com", "youtube.com", "googleusercontent.com",
           "gstatic.com", "withgoogle.com", "g.co", "goo.gl", "google.co.uk", "google.de")
_APPLE = ("apple.com", "icloud.com", "me.com", "apple.news")
_META = ("facebook.com", "fb.com", "facebookmail.com", "meta.com", "instagram.com", "whatsapp.com",
         "whatsapp.net", "messenger.com")
_AMAZON = ("amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es",
           "amazon.ca", "amazon.co.jp", "amazon.in", "amazon.com.au", "amazonaws.com",
           "amazonses.com", "a2z.com", "aws.amazon.com")

# brand keyword -> official registered domains
BRANDS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypal.me", "paypalobjects.com"),
    "microsoft": _MS, "office365": _MS, "outlook": _MS, "onedrive": _MS, "sharepoint": _MS,
    "google": _GOOGLE, "gmail": _GOOGLE,
    "apple": _APPLE, "icloud": _APPLE,
    "amazon": _AMAZON,
    "netflix": ("netflix.com", "netflix.net", "nflxext.com"),
    "facebook": _META, "instagram": _META, "whatsapp": _META,
    "linkedin": ("linkedin.com", "lnkd.in"),
    "dropbox": ("dropbox.com", "dropboxmail.com"),
    "docusign": ("docusign.com", "docusign.net"),
    "adobe": ("adobe.com", "adobesign.com", "echosign.com"),
    "dhl": ("dhl.com", "dhl.de", "dhl.ch", "dhl.co.uk"),
    "fedex": ("fedex.com",),
    "usps": ("usps.com",),
    "chase": ("chase.com", "jpmorgan.com"),
    "wellsfargo": ("wellsfargo.com",),
    "bankofamerica": ("bankofamerica.com", "bofa.com"),
    "coinbase": ("coinbase.com",),
    "binance": ("binance.com",),
    "metamask": ("metamask.io",),
    "ebay": ("ebay.com", "ebay.co.uk", "ebay.de"),
    "steam": ("steampowered.com", "steamcommunity.com"),
    "spotify": ("spotify.com",),
    "postfinance": ("postfinance.ch",),
    "swisscom": ("swisscom.ch", "swisscom.com"),
    "wetransfer": ("wetransfer.com",),
}

# Look-alike characters (Cyrillic/Greek/digits) mapped to the Latin letter they imitate
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "ӏ": "l", "һ": "h", "ԛ": "q", "ԝ": "w", "ɡ": "g",
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "κ": "k", "ı": "i",
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "$": "s", "@": "a",
})


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registered_domain(host: str) -> str:
    host = host.lower().strip().strip(".")
    if not host or is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def to_unicode(host: str) -> str:
    """Decode punycode (xn--) labels so homographs become visible."""
    out = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        out.append(label)
    return ".".join(out)


def skeleton(text: str) -> str:
    s = unicodedata.normalize("NFKC", text.lower()).translate(_CONFUSABLES)
    for a, b in (("rn", "m"), ("vv", "w"), ("cl", "d"), ("i", "l"), ("-", ""), ("_", "")):
        s = s.replace(a, b)
    return s


def _osa_distance(a: str, b: str) -> int:
    """Optimal string alignment distance (Levenshtein + adjacent transpositions)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def is_official(brand: str, domain: str) -> bool:
    reg = registered_domain(domain)
    official = BRANDS.get(brand, ())
    if reg in official or domain.lower() in official:
        return True
    # paypal.de, amazon.fr ... : brand is the whole second-level label on a normal TLD
    sld, _, tld = reg.partition(".")
    return sld == brand and tld not in SUSPICIOUS_TLDS


def is_any_official(domain: str) -> bool:
    return any(is_official(b, domain) for b in BRANDS)


def brand_mentioned(text: str) -> str | None:
    """Brand keyword appearing in a hostname or display name."""
    low = text.lower()
    tokens = set(re.split(r"[^a-z0-9]+", low))
    squashed = re.sub(r"[^a-z0-9]", "", low)
    for brand in BRANDS:
        if brand in tokens or (len(brand) >= 6 and brand in squashed):
            return brand
    return None


def lookalike_brand(domain: str) -> tuple[str, str] | None:
    """Return (brand, technique) if the registered domain imitates a known brand."""
    reg = registered_domain(domain)
    if not reg or is_ip(reg) or is_any_official(reg):
        return None
    label = to_unicode(reg).split(".")[0]
    # check the whole label and each hyphenated word: "paypa1-support" -> "paypa1"
    candidates = [label] + [t for t in re.split(r"[-_]", label) if len(t) >= 4]
    for word in candidates:
        skel = skeleton(word)
        for brand in BRANDS:
            if word == brand:
                continue
            brand_skel = skeleton(brand)
            if skel == brand_skel or (len(brand) >= 6 and brand_skel in skel and brand not in word):
                return brand, "homoglyph/character substitution"
            if len(brand) >= 6 and _osa_distance(word, brand) == 1:
                return brand, "typosquatting (one character off)"
    return None


def is_freemail(domain: str) -> bool:
    return domain.lower() in FREEMAIL
