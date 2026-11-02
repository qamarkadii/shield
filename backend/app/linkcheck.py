"""
Citizen link check: someone pastes a suspicious link (from an SMS, WhatsApp, email).

Shield never opens the link (that would be unsafe). It judges it from the outside:
- the domain score (lookalike rules + ML model)
- red flags in the full link (IP address instead of a name, '@' tricks, link shorteners,
  look-alike Unicode letters, very long links, login/payment paths)
- whether the domain is already on a known phishing list (if the feeds are downloaded)
- a UAE brand named in the PATH of a link on a site that isn't the brand's
  (hacked-site.com/aramex/login): 96 of the real UAE fakes collected in Nov 2026 look like this
- optionally (facts_budget) the domain's public records: registration age etc. (enrich.py),
  from DNS / registration directories only - the site itself is not contacted
"""

import ipaddress
import os
import re
import unicodedata
from urllib.parse import urlparse

from .features import _match, _tokens, split_domain
from .registry import UAE_BRANDS
from .scoring import assess, score_domain

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


LEVELS = ["no warning signs", "unknown", "suspicious", "high risk"]


def _raise(result, level):
    """Raise the level (never lower it). 'official' / unknown values are replaced."""
    current = result.get("verdict")
    if current not in LEVELS or LEVELS.index(level) > LEVELS.index(current):
        result["verdict"] = level


def path_brand(path: str):
    """A UAE brand named as a whole word (or word start) in the link's path/query, 5+ letters."""
    for t in _tokens(path.lower()):
        for k in sorted(UAE_BRANDS, key=len, reverse=True):
            if len(k) >= 5 and _match(t, k) in ("exact", "prefix"):
                return UAE_BRANDS[k]
    return None


def check_link(raw: str, facts_budget: float | None = None) -> dict:
    """Score the domain (learned model), then add link-level FACTS and labelled RULES.
    None of them changes the learned score; they can only raise the level, and each says why."""
    raw = raw.strip()
    if not raw or len(raw) > 2000:
        return {"error": "Please paste a link or domain (up to 2,000 characters)."}
    url = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else "http://" + raw
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower().rstrip(".")
    except ValueError:
        return {"error": "That doesn't look like a valid link."}
    if not host or ("." not in host and ":" not in host):
        return {"error": "That doesn't look like a link or domain."}

    facts, rules, notes = [], [], []
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    if is_ip:
        result = {"domain": host, "registered_domain": host, "score": None, "verdict": "unknown",
                  "brand": None, "ml_probability": None, "reasons": [], "signals": []}
        rules.append("Rule: uses a raw IP address instead of a website name. Official UAE services always use their own named domain.")
        _raise(result, "suspicious")
    else:
        result = assess(host, tls=False, budget=facts_budget) if facts_budget else score_domain(host)

    shown = None
    if not is_ip and (host.startswith("xn--") or ".xn--" in host):
        try:
            shown = host.encode("ascii").decode("idna")
            folded = unicodedata.normalize("NFKD", shown).encode("ascii", "ignore").decode()
            imitated = score_domain(folded)
            facts.append(f"Fact: uses foreign look-alike letters; it displays as '{shown}'")
            if imitated.get("verdict") == "official" or imitated.get("brand"):
                b = imitated.get("brand") or folded
                rules.append(f"Rule: foreign letters make it look like {b} ('{folded}'). Impersonation by design.")
                result["brand"] = b
                _raise(result, "high risk")
        except Exception:
            facts.append("Fact: uses foreign letters (punycode) in the name")

    if result.get("verdict") == "official" and "@" not in p.netloc:
        result.update(url=raw, known_phishing=False, facts=[], rules=[], notes=[],
                      advice="This is the official website according to Shield's registry. "
                             "Still never share OTP codes, and check the address bar matches exactly.")
        return result

    if "@" in p.netloc:
        before = p.netloc.split("@")[0]
        rules.append(f"Rule: the link starts with '{before}@', a trick: the browser actually goes to {host}.")
        _raise(result, "suspicious")

    reg = result.get("registered_domain") or host
    if host in SHORTENERS or reg in SHORTENERS:
        # the score would judge the shortening service, not the hidden destination
        facts.append("Fact: shortened link. The real destination is hidden, so Shield cannot check it "
                     "(Shield never opens links to find out).")
        result.update(score=None, verdict="unknown", signals=[], rule=None,
                      reasons=[], brand=None)

    known = host in known_phishing() or reg in known_phishing()
    if known:
        facts.insert(0, "Fact: listed in a public phishing database (Phishing.Database / OpenPhish)")
        _raise(result, "high risk")

    pb = None if is_ip else path_brand(p.path + "?" + p.query)
    if pb and result.get("verdict") != "official":
        name, official = pb
        _, reg_d = split_domain(host)
        if not any(reg_d == o or reg_d.endswith("." + o) for o in official):
            rules.append(f"Rule: the link's path names {name}, but the site is {reg_d}, not {', '.join(official)}. "
                         f"Real {name} pages are only on its own domain.")
            result["brand"] = result.get("brand") or name
            _raise(result, "suspicious")
    if re.search(r"(login|signin|verify|update|pay|payment|fine|refund|otp|card|bank|kyc)", (p.path + p.query).lower()):
        notes.append("The link points to a login, payment or verification page")
    if raw.lower().startswith("http://"):
        notes.append("Not encrypted (http instead of https)")

    result["reasons"] = facts + rules + result.get("reasons", [])
    result.update(url=raw, known_phishing=known, facts=facts, rules=rules + ([result["rule"]] if result.get("rule") else []),
                  notes=notes)
    v = result["verdict"]
    result["advice"] = {
        "high risk": "Do not open this link or enter any details. If it claims to be a government service, "
                     "open the official app or type the official website yourself, and report the message.",
        "suspicious": "Be careful: this link shows warning signs. Don't enter passwords, card details or OTP codes. "
                      "Use the official app or website instead.",
        "unknown": "Shield can't check where this link really goes. Don't open it unless you trust the sender; "
                   "use the official app or website instead.",
        "no warning signs": "Shield found no warning signs, but that does not prove the link is safe. "
                            "Never share OTP codes or card details from a link in a message.",
    }.get(v, "")
    return result
