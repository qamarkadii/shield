"""
Citizen link check: someone pastes a suspicious link (from an SMS, WhatsApp, email).

Shield never opens the link (that would be unsafe). It judges it from the outside:
- the domain score (lookalike rules + ML model)
- red flags in the full link (IP address instead of a name, '@' tricks, link shorteners,
  look-alike Unicode letters, very long links, login/payment paths)
- whether the domain is already on a known phishing list (if the feeds are downloaded)
"""

import ipaddress
import os
import re
import unicodedata
from urllib.parse import urlparse

from .scoring import score_domain

DATA = os.path.join(os.path.dirname(__file__), "..", "..", "data")
FEEDS = os.path.join(DATA, "feeds")

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
              "ow.ly", "shorturl.at", "s.id", "rebrand.ly", "tiny.cc", "t.ly", "lnkd.in"}

_known = None


def known_phishing() -> set:
    """Domains from downloaded phishing feeds + the real UAE fakes dataset."""
    global _known
    if _known is not None:
        return _known
    found = set()
    paths = [os.path.join(FEEDS, f) for f in os.listdir(FEEDS)] if os.path.isdir(FEEDS) else []
    paths.append(os.path.join(DATA, "uae_phishing_domains_real.csv"))
    for p in paths:
        if not os.path.isfile(p):
            continue
        with open(p, encoding="utf-8", errors="ignore") as f:
            for line in f:
                v = line.strip().split(",")[0].lower()
                if not v or v.startswith("#") or v == "domain":
                    continue
                if "://" in v:
                    v = urlparse(v).hostname or ""
                found.add(v[4:] if v.startswith("www.") else v)
    _known = found
    return _known


def reload_known():
    global _known
    _known = None
    return len(known_phishing())


def check_link(raw: str) -> dict:
    raw = raw.strip()
    url = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else "http://" + raw
    p = urlparse(url)
    host = (p.hostname or "").lower().rstrip(".")
    if not host:
        return {"error": "That doesn't look like a link or domain."}

    extra, lead, bonus = [], [], 0
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    if is_ip:
        result = {"domain": host, "registered_domain": host, "score": 0, "verdict": "low risk",
                  "brand": None, "ml_probability": None, "reasons": []}
        bonus += 40
        extra.append("Uses a raw IP address instead of a website name")
    else:
        result = score_domain(host)

    if result.get("verdict") == "official":
        result.update(url=raw, known_phishing=False)
        return result

    if "@" in p.netloc:
        bonus += 30
        extra.append("Contains '@', a trick that hides the real destination")
    if host in SHORTENERS or result.get("registered_domain") in SHORTENERS:
        bonus += 25
        extra.append("Shortened link: the real destination is hidden. Don't open it; ask the sender or check the official app")
    if host.startswith("xn--") or ".xn--" in host:
        bonus += 30
        try:
            shown = host.encode("ascii").decode("idna")
            folded = unicodedata.normalize("NFKD", shown).encode("ascii", "ignore").decode()
            lead.append(f"Uses look-alike foreign letters: it displays as '{shown}'")
            imitated = score_domain(folded)
            if imitated.get("brand"):
                result["brand"] = imitated["brand"]
                bonus += 25
                lead.append(f"Imitates {imitated['brand']} ('{folded}')")
        except Exception:
            lead.append("Uses look-alike foreign letters (punycode) to imitate a real name")
    if len(raw) > 120:
        bonus += 5
        extra.append("Unusually long link")
    if re.search(r"(login|signin|verify|update|pay|payment|fine|refund|otp|card|bank|kyc)", p.path.lower() + p.query.lower()):
        bonus += 10
        extra.append("The link leads to a login, payment or verification page")
    if raw.lower().startswith("http://"):
        bonus += 5
        extra.append("Not encrypted (http, not https)")

    known = host in known_phishing() or result.get("registered_domain") in known_phishing()
    if known:
        bonus += 60

    result["score"] = min(100, result.get("score", 0) + bonus)
    # most important first: known list, then the domain itself, then link details
    result["reasons"] = (["Already listed in a public phishing database"] if known else []) \
        + lead + result.get("reasons", []) + extra
    s = result["score"]
    result["verdict"] = "high risk" if s >= 60 else "suspicious" if s >= 30 else "low risk"
    result["url"] = raw
    result["known_phishing"] = known
    result["advice"] = ("Do not open this link or enter any details. If it claims to be a government "
                        "service, open the official app or type the official website yourself."
                        if s >= 30 else
                        "No strong warning signs found, but stay careful: never share OTP codes or card details from a link.")
    return result
