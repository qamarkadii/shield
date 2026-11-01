"""
Features: the warning signs Shield measures for one domain.

The SAME code is used when training the risk model and when scoring live
domains, so the model is never scored on signs computed differently from how
it learned them.

Each feature is 0/1 (or a number) and has a plain-language description.
How much each one matters is NOT decided here: the risk model learns the
weights from labelled data (ml/train_baseline.py).
"""

import re

import tldextract

_extract = tldextract.TLDExtract(suffix_list_urls=())   # offline, bundled suffix list

HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})

LURE_WORDS = ("login", "signin", "verify", "verification", "secure", "security", "update",
              "account", "pay", "payment", "bill", "billing", "invoice", "kyc", "track",
              "tracking", "parcel", "delivery", "refund", "fine", "fines", "support", "unlock",
              "confirm", "wallet", "reward", "gift", "prize", "otp", "auth", "recover")

RISKY_TLDS = {"xyz", "top", "icu", "live", "shop", "sbs", "cfd", "online", "site", "click",
              "info", "buzz", "rest", "cyou", "one", "monster", "store", "vip", "work", "support"}

FREE_HOSTS = ("000webhostapp.com", "webflow.io", "workers.dev", "pages.dev", "github.io",
              "firebaseapp.com", "web.app", "repl.co", "ewp.live", "duckdns.org", "ddns.net",
              "r2.dev", "umbler.net", "easywp.com", "weebly.com", "wixsite.com", "framer.app",
              "framer.media", "netlify.app", "vercel.app", "glitch.me", "herokuapp.com",
              "blogspot.com", "sites.google.com", "webcindario.com", "codeanyapp.com",
              "tempurl.host", "serv00.net", "usrfiles.com", "page.link", "appspot.com")

# Global brands most often impersonated in our training data. Used so the risk
# model can LEARN how much each impersonation pattern matters (UAE brands are rare
# in public phishing data). A brand's own domains (e.g. amazon.co.uk) are official.
GLOBAL_BRANDS = {
    "paypal": [], "apple": ["icloud.com"], "icloud": ["apple.com"], "microsoft": ["live.com", "office.com", "outlook.com"],
    "office365": ["office.com", "microsoft.com"], "outlook": ["live.com", "microsoft.com", "office.com"],
    "onedrive": ["live.com", "microsoft.com"], "google": [], "gmail": ["google.com"], "amazon": [],
    "netflix": [], "facebook": [], "instagram": [], "whatsapp": [], "linkedin": [], "dropbox": [],
    "docusign": [], "adobe": [], "dhl": [], "fedex": [], "usps": [], "chase": [], "wellsfargo": [],
    "bankofamerica": [], "coinbase": [], "binance": [], "metamask": [], "blockchain": [],
    "steamcommunity": ["steampowered.com"], "roblox": [], "allegro": [], "santander": [], "itau": [],
    "bradesco": [], "caixa": [], "ameli": [], "laposte": [], "americanexpress": [], "amex": [],
    "booking": [], "airbnb": [], "telegram": [], "tiktok": [], "spotify": [], "ebay": [],
    "walmart": [], "costco": [], "verizon": [], "comcast": [], "xfinity": ["comcast.com"],
}

# Brands this short collide with normal words, so they must be a whole word
SHORT_BRAND_LEN = 4


def clean(domain: str) -> str:
    d = domain.strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d).split("/")[0].split("?")[0].split("#")[0]
    d = d.split("@")[-1].split(":")[0].rstrip(".")
    return d[4:] if d.startswith("www.") else d


def split_domain(d: str):
    ext = _extract(d)
    registered = ".".join(p for p in (ext.domain, ext.suffix) if p)
    return ext, registered


def _has_lure(tokens) -> bool:
    return any(t.startswith(w) or t.endswith(w) or t.endswith(w + "s") for t in tokens for w in LURE_WORDS)


def _tokens(text: str):
    return [t for t in re.split(r"[^a-z0-9]+", text) if t]


def _match(token: str, key: str) -> str | None:
    """How a single word contains a brand key: exact / prefix / homoglyph, or None.
    Prefix only counts when the brand starts the word and the rest is a real addition
    (>=3 letters or contains digits), so 'salika' != 'salik' and 'hyderabadpolice'
    does not contain 'adpolice'."""
    def check(t):
        if t == key:
            return "exact"
        if len(key) > SHORT_BRAND_LEN and t.startswith(key):
            rest = t[len(key):]
            if len(rest) >= 3 or any(c.isdigit() for c in rest):
                return "prefix"
        if len(key) > SHORT_BRAND_LEN and t.endswith(key):
            rest = t[:-len(key)]
            if rest in ("my", "e", "i", "ae", "uae", "secure", "login", "www", "online", "the"):
                return "prefix"
        return None
    m = check(token)
    if m:
        return m
    g = token.translate(HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
    if g != token and check(g):
        return "homoglyph"
    return None


def find_brand(d: str, ext, registered: str, brands: dict):
    """brands: {key: (display_name, [official registered domains])}.
    Returns (key, name, how, where) for the first brand found, or None.
    how: exact/prefix/homoglyph; where: 'domain' (registered label) or 'subdomain'."""
    dom_tokens = _tokens(ext.domain)
    sub_tokens = _tokens(ext.subdomain)
    joined_dom = ext.domain.replace("-", "")
    for key, (name, official) in brands.items():
        for where, toks in (("domain", dom_tokens + [joined_dom]), ("subdomain", sub_tokens)):
            for t in toks:
                how = _match(t, key)
                if how:
                    return key, name, how, where
    return None


BRAND_SUFFIXES = {"com", "net", "org", "co", "io", "co.uk", "de", "fr", "it", "es", "nl", "pl", "ca",
                  "com.au", "co.jp", "jp", "in", "co.in", "com.br", "com.mx", "ae", "sa", "com.sa",
                  "com.tr", "se", "ch", "at", "be", "ie", "sg", "com.sg", "co.za", "cn", "com.cn"}


def is_official(registered: str, key: str, official: list, global_brand=False) -> bool:
    if registered in official:
        return True
    if global_brand:
        label, _, suffix = registered.partition(".")
        # brands own their country sites (amazon.co.uk), not paypal.xyz
        return label == key and suffix in BRAND_SUFFIXES
    return False


def one_edit_apart(a: str, b: str) -> bool:
    """True if a and b differ by exactly one inserted, deleted or changed letter."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) > len(b):
        a, b = b, a
    i = j = diff = 0
    while i < len(a) and j < len(b):
        if a[i] != b[j]:
            diff += 1
            if diff > 1:
                return False
            if len(a) == len(b):
                i += 1
            j += 1
        else:
            i += 1
            j += 1
    return diff + (len(b) - j) + (len(a) - i) <= 1


def find_typo(ext, brands: dict):
    """Registered name one letter away from a brand (uaepas, emiratespostt). Brands >= 6 letters only."""
    label = re.sub(r"[^a-z0-9]", "", ext.domain)
    for key, (name, official) in brands.items():
        if len(key) >= 6 and one_edit_apart(label, key):
            return key, name
    return None


FEATURE_NAMES = [
    "ml_logit",                # text model's score (log-odds), from character patterns
    "brand_typosquat",         # registered name IS the brand, just re-spelled (emirates-post.org)
    "brand_with_lure",         # brand + a lure word (salik-pay, etisalat-bills)
    "brand_in_subdomain",      # brand only in front of an unrelated domain (aramex.valeriair.com)
    "brand_homoglyph",         # brand written with look-alike characters (sa1ik)
    "brand_other_mention",     # brand name used with other words, no lure (etisalatspeedtest)
    "fake_country_label",      # '.ae' / 'gov' inside a foreign domain
    "risky_tld",
    "free_host",
    "many_hyphens",
    "lure_word",
    "deep_subdomain",          # 3+ levels in front of the registered domain
    "digits_in_name",
]


def extract(domain: str, uae_brands: dict, ml_logit: float = 0.0) -> dict:
    """Returns {"features": {...}, "brand": name|None, "official": bool, "registered": str, "domain": str}."""
    d = clean(domain)
    ext, registered = split_domain(d)
    f = dict.fromkeys(FEATURE_NAMES, 0.0)
    f["ml_logit"] = ml_logit
    brand_name, official = None, False

    hit = find_brand(d, ext, registered, uae_brands)
    is_global = False
    if hit is None:
        typo = find_typo(ext, uae_brands)
        if typo:
            hit = (typo[0], typo[1], "typo", "domain")
    if hit is None:
        gb = {k: (k, v) for k, v in GLOBAL_BRANDS.items()}
        hit = find_brand(d, ext, registered, gb)
        if hit is None:
            typo = find_typo(ext, gb)
            hit = (typo[0], typo[1], "typo", "domain") if typo else None
        is_global = hit is not None
    if hit:
        key, brand_name, how, where = hit
        off_list = (uae_brands[key][1] if not is_global else GLOBAL_BRANDS[key])
        if is_official(registered, key, off_list, global_brand=is_global) or \
                any(registered.endswith("." + o) for o in off_list):
            official = True
        else:
            all_tokens = _tokens(d)
            # lure word anywhere, or glued to the brand inside one word (etisalat+ebills)
            glued = [t.translate(HOMOGLYPHS).replace(key, " ", 1) for t in all_tokens
                     if key in t.translate(HOMOGLYPHS)]
            has_lure = _has_lure(all_tokens) or any(w in rest for rest in glued for w in LURE_WORDS)
            stripped = re.sub(r"[^a-z]", "", ext.domain.translate(HOMOGLYPHS))
            if how == "homoglyph":
                f["brand_homoglyph"] = 1
            elif how == "typo":
                f["brand_typosquat"] = 1
            elif where == "subdomain":
                f["brand_in_subdomain"] = 1
            elif stripped == key or stripped in (key + "ae", "ae" + key, key + "uae"):
                f["brand_typosquat"] = 1
            elif has_lure:
                f["brand_with_lure"] = 1
            else:
                f["brand_other_mention"] = 1

    labels = [l for l in ext.subdomain.split(".") + [ext.domain] if l]
    if not (ext.suffix == "ae" or ext.suffix.endswith(".ae")) and \
            any(l in ("ae", "gov") or l.endswith("-ae") or l.startswith("ae-") for l in labels):
        f["fake_country_label"] = 1
    f["risky_tld"] = float(ext.suffix.split(".")[-1] in RISKY_TLDS)
    f["free_host"] = float(any(d == h or d.endswith("." + h) for h in FREE_HOSTS))
    f["many_hyphens"] = float(d.count("-") >= 3)
    brand_keys = set(uae_brands) | set(GLOBAL_BRANDS)
    f["lure_word"] = float(_has_lure([t for t in _tokens(d) if t not in brand_keys]))   # 'paypal' isn't 'pay
    f["deep_subdomain"] = float(len([s for s in ext.subdomain.split(".") if s]) >= 3)
    f["digits_in_name"] = float(sum(c.isdigit() for c in ext.domain) >= 3)
    return {"features": f, "brand": brand_name if (hit and not is_global) else (f"{brand_name} (global brand)" if hit else None),
            "official": official, "registered": registered, "domain": d, "ext": ext}


DESCRIBE = {
    "ml_logit": "Its text patterns resemble known phishing domains (ML text model)",
    "brand_typosquat": "Is the {brand} name re-spelled on a domain {brand} does not own ({registered})",
    "brand_with_lure": "Combines the {brand} name with a lure word (pay, login, bill...) on a domain {brand} does not own",
    "brand_in_subdomain": "Puts the {brand} name in front of an unrelated domain ({registered})",
    "brand_homoglyph": "Imitates the {brand} name with look-alike characters (e.g. 1 for l, 0 for o)",
    "brand_other_mention": "Uses the {brand} name on a domain {brand} does not own (no lure words; could be a fan or partner site)",
    "fake_country_label": "Puts '.ae' or 'gov' inside the name to look official, but the real domain is {registered}",
    "risky_tld": "Uses an ending often abused by scammers (.{suffix})",
    "free_host": "Hosted on a free hosting or site-builder service",
    "many_hyphens": "Unusually many hyphens",
    "lure_word": "Contains a lure word (login, pay, verify, refund...)",
    "deep_subdomain": "Many layers in front of the real domain",
    "digits_in_name": "Many digits in the name",
}
