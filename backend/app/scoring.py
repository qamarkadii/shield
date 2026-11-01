"""
Shield scoring: lookalike rules + ML model -> risk score 0-100 with reasons.

The rules catch what the ML model misses (clean-looking fakes such as
emirates-post.org), and the model catches generic phishing patterns.
"""

import os
import re

import joblib
import tldextract

# Offline: use the suffix list bundled with tldextract (no network call)
_extract = tldextract.TLDExtract(suffix_list_urls=())

# Brand keyword -> the brand's real registered domains.
# VERIFY every domain on the entity's official website before the demo.
BRANDS = {
    "salik":        ("Salik", ["salik.ae"]),
    "uaepass":      ("UAE PASS", ["uaepass.ae"]),
    "dubaipolice":  ("Dubai Police", ["dubaipolice.gov.ae"]),
    "adpolice":     ("Abu Dhabi Police", ["adpolice.gov.ae"]),
    "emiratespost": ("Emirates Post", ["emiratespost.ae"]),
    "etisalat":     ("Etisalat (e&)", ["etisalat.ae", "eand.com"]),
    "eimae":        ("Etisalat (e&) webmail", ["eim.ae"]),
    "aramex":       ("Aramex", ["aramex.com"]),
    "emiratesnbd":  ("Emirates NBD", ["emiratesnbd.com"]),
    "adcb":         ("ADCB", ["adcb.com"]),
    "mashreq":      ("Mashreq", ["mashreq.com", "mashreqbank.com"]),
    "rta":          ("RTA", ["rta.ae"]),
    "tdra":         ("TDRA", ["tdra.gov.ae"]),
}

# Short keywords that appear inside normal words: only match as a whole token
SHORT = {"rta", "adcb", "tdra"}

SUSPICIOUS_TLDS = {"xyz", "top", "icu", "live", "shop", "sbs", "cfd", "online",
                   "site", "click", "info", "buzz", "rest", "cyou", "one"}

FREE_HOSTS = ("000webhostapp.com", "webflow.io", "workers.dev", "pages.dev",
              "github.io", "firebaseapp.com", "web.app", "repl.co", "ewp.live",
              "duckdns.org", "ddns.net", "r2.dev", "umbler.net", "easywp.com")

HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})

_MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "ml", "domain_model.joblib")
_model = None


def _load_model():
    global _model
    if _model is None and os.path.exists(_MODEL_PATH):
        _model = joblib.load(_MODEL_PATH)
    return _model


def reload_model():
    """Load the model file again (after retraining)."""
    global _model
    _model = None
    return _load_model() is not None


UAE_TERMS = ("dubai", "abudhabi", "sharjah", "ajman", "fujairah", "rasalkhaimah",
             "ummalquwain", "emirates", "uae")


def uae_reason(domain: str):
    """Why a live domain belongs on the UAE watch (None = not UAE-related)."""
    d = domain.lower().rstrip(".")
    if d == "ae" or d.endswith(".ae"):
        return ".ae domain"
    if mentions_brand(d):
        return "mentions a watched UAE brand"
    flat = re.sub(r"[-.]", "", d)
    tokens = set(re.split(r"[-.]", d))
    for term in UAE_TERMS:
        if (term == "uae" and term in tokens) or (term != "uae" and term in flat):
            return f"mentions '{term}'"
    return None


def mentions_brand(domain: str) -> bool:
    """Cheap pre-filter for the live stream: does this name mention a watched brand?"""
    d = domain.lower()
    flat = re.sub(r"[-.]", "", d)
    unglyphed = flat.translate(HOMOGLYPHS).replace("rn", "m")
    tokens = set(re.split(r"[-.]", d))
    for key in BRANDS:
        if key in SHORT:
            if key in tokens:
                return True
        elif key in flat or key in unglyphed:
            return True
    return False


def _clean(domain: str) -> str:
    d = domain.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d).split("/")[0].split(":")[0]
    return d[4:] if d.startswith("www.") else d


def score_domain(domain: str) -> dict:
    d = _clean(domain)
    ext = _extract(d)
    registered = ".".join(p for p in (ext.domain, ext.suffix) if p)
    flat = re.sub(r"[-.]", "", d)                 # "emirates-post.org" -> "emiratespostorg"
    unglyphed = flat.translate(HOMOGLYPHS).replace("rn", "m")
    tokens = set(re.split(r"[-.]", d))

    score, reasons, brand_hit = 0, [], None

    for key, (name, official) in BRANDS.items():
        if key in SHORT:
            found = key in tokens
            glyph = False
        else:
            found = key in flat
            glyph = not found and key in unglyphed
        if not (found or glyph):
            continue
        if registered in official:
            return {"domain": d, "score": 0, "verdict": "official",
                    "brand": name, "reasons": [f"Official {name} domain"]}
        brand_hit = name
        if glyph:
            score += 55
            reasons.append(f"Imitates '{key}' using look-alike characters (e.g. 0 for o)")
        elif ext.subdomain and key in ext.subdomain.replace("-", "").replace(".", "") \
                and key not in ext.domain.replace("-", ""):
            score += 55
            reasons.append(f"Puts the {name} name in front of an unrelated domain ({registered})")
        else:
            score += 50
            reasons.append(f"Uses the {name} name on a domain {name} does not own ({registered})")
        break

    # only the registered part + subdomains, never the official suffix (e.g. gov.uk)
    labels = [l for l in (ext.subdomain.split(".") + [ext.domain]) if l]
    if not (ext.suffix == "ae" or ext.suffix.endswith(".ae")) and \
            any(l in ("ae", "gov") or l.endswith("-ae") or l.startswith("ae-") for l in labels):
        score += 35
        reasons.append(f"Puts '.ae' / 'gov' inside the name to look like a UAE address, but the real domain is {registered}")
    if ext.suffix.split(".")[-1] in SUSPICIOUS_TLDS:
        score += 10
        reasons.append(f"Uses a top-level domain often abused by scammers (.{ext.suffix})")
    if any(d.endswith(h) for h in FREE_HOSTS):
        score += 10
        reasons.append("Hosted on a free hosting or site-builder service")
    if d.count("-") >= 3:
        score += 5
        reasons.append("Unusually many hyphens")
    if re.search(r"(login|verify|secure|update|pay|bill|kyc|track|parcel|refund|fine)", d):
        score += 10
        reasons.append("Contains a pressure or payment word (login, pay, verify...)")

    model = _load_model()
    ml_prob = None
    if model is not None:
        vec, clf = model
        ml_prob = float(clf.predict_proba(vec.transform([d]))[0][1])
        score += round(ml_prob * 35)
        if ml_prob >= 0.5:
            reasons.append(f"ML model rates it as phishing-like ({ml_prob:.0%})")

    score = min(score, 100)
    verdict = "high risk" if score >= 60 else "suspicious" if score >= 30 else "low risk"
    return {"domain": d, "registered_domain": registered, "score": score,
            "verdict": verdict, "brand": brand_hit, "ml_probability": ml_prob,
            "reasons": reasons}
