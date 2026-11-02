"""
Features: the warning signs Shield measures for one domain.

The SAME code is used when training the risk model and when scoring live
domains, so the model is never scored on signs computed differently from how
it learned them.

Each feature is 0/1 (or a number) and has a plain-language description.
How much each one matters is NOT decided here: the risk model learns that
from labelled data (ml/model.py).

Two features need data the model brings with it (`ctx`):
  tld_risk    learned phishing log-odds of the domain ending (replaces a hand-made list)
  popularity  how popular the owning site is (Tranco rank); 0 for tenants of hosting platforms
"""

import math
import re
import unicodedata

import tldextract

_extract = tldextract.TLDExtract(suffix_list_urls=())   # offline, bundled suffix list
# Same list, but hosting platforms (github.io, web.app ...) count as endings, so
# 'x.web.app' is owned by 'x.web.app' and not by Google.
_extract_private = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

# Two digit maps: '1' can stand for 'l' (sa1ik) or 'i' (etisa1at is 'l', 1nstagram is 'i').
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"})
HOMOGLYPHS_I = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"})

# Non-Latin letters that look Latin (used in punycode / IDN look-alikes)
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "ь": "b", "к": "k", "м": "m",
    "т": "t", "н": "h", "в": "b", "ο": "o", "α": "a", "ν": "v", "τ": "t", "κ": "k", "ι": "i",
    "ρ": "p", "ε": "e", "ɡ": "g", "ı": "i", "ⅼ": "l", "ɩ": "i", "ɑ": "a",
})

LURE_WORDS = ("login", "signin", "verify", "verification", "secure", "security", "update",
              "account", "pay", "payment", "bill", "billing", "invoice", "kyc", "track",
              "tracking", "parcel", "delivery", "refund", "fine", "fines", "support", "unlock",
              "confirm", "wallet", "reward", "gift", "prize", "otp", "auth", "recover")

FREE_HOSTS = ("000webhostapp.com", "webflow.io", "workers.dev", "pages.dev", "github.io",
              "firebaseapp.com", "web.app", "repl.co", "ewp.live", "duckdns.org", "ddns.net",
              "r2.dev", "umbler.net", "easywp.com", "weebly.com", "wixsite.com", "framer.app",
              "framer.media", "netlify.app", "vercel.app", "glitch.me", "herokuapp.com",
              "blogspot.com", "sites.google.com", "webcindario.com", "codeanyapp.com",
              "tempurl.host", "serv00.net", "usrfiles.com", "page.link", "appspot.com",
              "weeblysite.com", "godaddysites.com", "myportfolio.com", "gitbook.io", "surge.sh",
              "webwave.dev", "cf-ipfs.com", "infura-ipfs.io", "dweb.link", "mybluehost.me",
              "square.site", "wordpress.com", "jimdosite.com", "strikingly.com", "carrd.co")

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
_GLOBAL = {k: (k, v) for k, v in GLOBAL_BRANDS.items()}

# Brands this short collide with normal words, so they must be a whole word
SHORT_BRAND_LEN = 4
VOWELS = set("aeiou")


def clean(domain: str) -> str:
    d = domain.strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d).split("/")[0].split("?")[0].split("#")[0]
    d = d.split("@")[-1].split(":")[0].rstrip(".")
    return d[4:] if d.startswith("www.") else d


def split_domain(d: str):
    ext = _extract(d)
    registered = ".".join(p for p in (ext.domain, ext.suffix) if p)
    return ext, registered


def private_owner(d: str) -> str:
    """Registered domain where hosting platforms count as endings: 'x.web.app' -> 'x.web.app'."""
    ext = _extract_private(d)
    return ".".join(p for p in (ext.domain, ext.suffix) if p) or d


def owner(d: str, platforms=frozenset()) -> str:
    """Who controls this name. On a multi-tenant platform (weeblysite.com) that is the
    tenant (shop.weeblysite.com), otherwise the registered domain. Used to keep one
    owner's names on one side of every train/test split, and for popularity."""
    o = private_owner(d)
    if (o in platforms or o in FREE_HOSTS) and d != o and d.endswith("." + o):
        return d[: -len(o) - 1].split(".")[-1] + "." + o
    return o


def platform_of(d: str, platforms=frozenset()):
    """The hosting platform a name lives on ('vercel.app' for react-docs.vercel.app), or None."""
    pe, ie = _extract_private(d), _extract(d)
    if pe.suffix and pe.suffix != ie.suffix and d != pe.suffix:
        return pe.suffix
    o = private_owner(d)
    if (o in platforms or o in FREE_HOSTS) and d != o and d.endswith("." + o):
        return o
    return None


def text_input(d: str, platforms=frozenset(), mask=False) -> str:
    """What the character text model reads. With mask=True: the tenant's own name with the
    platform replaced by a marker ('react-docs.~h'), the platform's risk then coming only
    from tld_risk. Tested on Nov 1 and NOT used: real legit hostnames flagged 1.97% -> 3.26%,
    legit free-host tenants 46% -> 70%, because the per-platform rate is dominated by
    phishing feeds and the text model lost useful context."""
    p = platform_of(d, platforms) if mask else None
    return d[: -len(p)] + "~h" if p else d


def ending(d: str, ext, platforms=frozenset()) -> str:
    """Ending used for tld_risk: the hosting platform if any, else the public suffix."""
    return platform_of(d, platforms) or ext.suffix


def fold_unicode(d: str) -> str:
    """Decode punycode labels and map look-alike letters to Latin (xn--slik-... -> salik)."""
    if "xn--" not in d:
        return d
    out = []
    for label in d.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except Exception:
                pass
        label = label.translate(CONFUSABLES)
        label = unicodedata.normalize("NFKD", label).encode("ascii", "ignore").decode()
        out.append(label)
    return ".".join(out)


def _has_lure(tokens) -> bool:
    return any(t.startswith(w) or t.endswith(w) or t.endswith(w + "s") for t in tokens for w in LURE_WORDS)


def _tokens(text: str):
    return [t for t in re.split(r"[^a-z0-9]+", text) if t]


def _deglyph(t: str):
    """Look-alike readings of a word (digits and letter pairs that imitate letters)."""
    out = []
    for table in (HOMOGLYPHS, HOMOGLYPHS_I):
        g = t.translate(table).replace("rn", "m").replace("vv", "w")
        if g != t and g not in out:
            out.append(g)
    return out


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
    for g in _deglyph(token):
        if check(g):
            return "homoglyph"
    return None


_HOW_RANK = {"exact": 0, "prefix": 1, "homoglyph": 2}


def find_brand(d: str, ext, registered: str, brands: dict):
    """brands: {key: (display_name, [official registered domains])}.
    Returns the BEST (key, name, how, where): registered name before subdomain, exact
    before prefix before look-alike, longer brand before shorter. None if no brand.
    how: exact/prefix/homoglyph; where: 'domain' (registered label) or 'subdomain'."""
    dom_tokens = _tokens(ext.domain)
    sub_tokens = _tokens(ext.subdomain)
    joined_dom = ext.domain.replace("-", "")
    best, best_rank = None, None
    for key, (name, official) in brands.items():
        for wi, (where, toks) in enumerate((("domain", dom_tokens + [joined_dom]), ("subdomain", sub_tokens))):
            for t in toks:
                how = _match(t, key)
                if how:
                    rank = (wi, _HOW_RANK[how], -len(key))
                    if best_rank is None or rank < best_rank:
                        best, best_rank = (key, name, how, where), rank
    return best


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


def close_spelling(a: str, b: str) -> bool:
    """True if a and b differ by exactly one inserted, deleted or changed letter, or two
    neighbouring letters swapped (aramxe) - the Damerau edits behind most typo-squats."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    if len(a) > len(b):
        a, b = b, a
    i = j = diff = 0
    while i < len(a) and j < len(b):
        if a[i] != b[j]:
            diff += 1
            if diff > 1:
                return False
            j += 1
        else:
            i += 1
            j += 1
    return True


one_edit_apart = close_spelling   # old name


def find_typo(ext, brands: dict):
    """Registered name one edit away from a brand (uaepas, emiratespostt, aramxe). Brands >= 6 letters only."""
    label = re.sub(r"[^a-z0-9]", "", ext.domain)
    for key, (name, official) in brands.items():
        if len(key) >= 6 and close_spelling(label, key):
            return key, name
    return None


FEATURE_NAMES = [
    "ml_logit",                # text model's score (log-odds), from character patterns
    "brand_typosquat",         # registered name IS the brand, just re-spelled (emirates-post.org)
    "brand_with_lure",         # brand + a lure word (salik-pay, etisalat-bills)
    "brand_in_subdomain",      # brand only in front of an unrelated domain (aramex.valeriair.com)
    "brand_homoglyph",         # brand written with look-alike characters (sa1ik, Cyrillic 'а')
    "brand_other_mention",     # brand name used with other words, no lure (etisalatspeedtest)
    "fake_country_label",      # '.ae' / 'gov' inside a foreign domain
    "tld_risk",                # learned phishing log-odds of the ending (ctx)
    "free_host",
    "many_hyphens",
    "lure_word",
    "deep_subdomain",          # 3+ levels in front of the registered domain
    "digits_in_name",
    "punycode",                # non-Latin letters (xn--) in the name
    "name_entropy",            # how random the letters look (bits per character)
    "host_length",             # characters before the ending
    "consonant_run",           # longest run of consonants (random strings: 'xkqzt')
    "popularity",              # 0..1 from Tranco rank of the owner (ctx); 0 = not a known popular site
]

# Which way each feature may push the risk (1 = only up, -1 = only down, 0 = learned freely).
MONOTONIC = {"ml_logit": 1, "brand_typosquat": 1, "brand_with_lure": 1, "brand_in_subdomain": 1,
             "brand_homoglyph": 1, "brand_other_mention": 1, "fake_country_label": 1, "tld_risk": 1,
             "free_host": 1, "punycode": 1, "popularity": -1}

BINARY = {"brand_typosquat", "brand_with_lure", "brand_in_subdomain", "brand_homoglyph", "brand_other_mention",
          "fake_country_label", "free_host", "many_hyphens", "lure_word", "deep_subdomain", "digits_in_name",
          "punycode"}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


def _consonant_run(s: str) -> int:
    best = cur = 0
    for ch in s:
        if ch.isalpha() and ch not in VOWELS and ch != "y":
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


def tld_risk_value(suffix: str, table) -> float:
    """Learned log-odds of the ending, relative to average. Full ending first (com.br), then last label."""
    if not table:
        return 0.0
    rates = table["logodds"]
    if suffix in rates:
        return rates[suffix]
    last = suffix.split(".")[-1]
    return rates.get(last, table.get("default", 0.0))


def popularity_value(d: str, ranks, platforms=frozenset()) -> tuple:
    """(0..1 score, rank or None). Tenants of hosting platforms never inherit the platform's rank."""
    if not ranks:
        return 0.0, None
    o = owner(d, platforms)
    r = ranks.get(o)
    if r is None:
        return 0.0, None
    return max(0.0, 1.0 - math.log10(r) / 6.0), r      # rank 1 -> 1.0, rank 1,000,000 -> 0.0


def extract(domain: str, uae_brands: dict, ml_logit: float = 0.0, ctx=None) -> dict:
    """Returns {"features": {...}, "brand": name|None, "official": bool, "registered": str, "domain": str, ...}.
    ctx (optional): {"tld_table": ..., "ranks": {...}, "platforms": set} for tld_risk / popularity."""
    d = clean(domain)
    ext, registered = split_domain(d)
    f = dict.fromkeys(FEATURE_NAMES, 0.0)
    f["ml_logit"] = ml_logit
    brand_name, official = None, False

    # look-alike foreign letters: search brands in the Latin reading of the name
    folded = fold_unicode(d)
    f["punycode"] = float("xn--" in d)
    fext = _extract(folded) if folded != d else ext

    def search(brands):
        h = find_brand(d, ext, registered, brands)
        if h is None and folded != d:
            h = find_brand(folded, fext, registered, brands)
            if h:
                h = (h[0], h[1], "homoglyph", h[3])
        if h is None:
            t = find_typo(fext, brands)
            h = (t[0], t[1], "typo", "domain") if t else None
        return h

    hit = search(uae_brands)
    is_global = False
    if hit is None:
        hit = search(_GLOBAL)
        is_global = hit is not None
    if hit:
        key, brand_name, how, where = hit
        off_list = (uae_brands[key][1] if not is_global else GLOBAL_BRANDS[key])
        if is_official(registered, key, off_list, global_brand=is_global) or \
                any(registered.endswith("." + o) for o in off_list):
            official = True
        else:
            all_tokens = _tokens(folded)
            # lure word anywhere, or glued to the brand inside one word (etisalat+ebills)
            glued = [t.translate(HOMOGLYPHS).replace(key, " ", 1) for t in all_tokens
                     if key in t.translate(HOMOGLYPHS)]
            has_lure = _has_lure(all_tokens) or any(w in rest for rest in glued for w in LURE_WORDS)
            stripped = re.sub(r"[^a-z]", "", fext.domain.translate(HOMOGLYPHS))
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

    # 'ae'/'gov' label inside a foreign name: in the registered name (ae-payonline.com) or
    # in the MIDDLE of the name (my-pay.ae.add-on.shop). A leftmost label is a normal
    # regional site (ae.company.com, ae-en.company.com) and does not count - except on a
    # hosting platform, where the leftmost label IS the chosen name (x-ae.umbler.net).
    subs = [l for l in ext.subdomain.split(".") if l]
    looks = lambda l: l in ("ae", "gov") or l.endswith("-ae") or l.startswith("ae-")
    if not (ext.suffix == "ae" or ext.suffix.endswith(".ae")) and \
            (looks(ext.domain) or any(looks(l) for l in subs[0 if platform_of(d) else 1:])):
        f["fake_country_label"] = 1
    f["free_host"] = float(any(d == h or d.endswith("." + h) for h in FREE_HOSTS))
    f["many_hyphens"] = float(folded.replace("xn--", "").count("-") >= 3)
    brand_keys = set(uae_brands) | set(GLOBAL_BRANDS)
    f["lure_word"] = float(_has_lure([t for t in _tokens(folded) if t not in brand_keys]))   # 'paypal' isn't 'pay'
    f["deep_subdomain"] = float(len([s for s in ext.subdomain.split(".") if s]) >= 3)
    f["digits_in_name"] = float(sum(c.isdigit() for c in ext.domain) >= 3)
    name = d[: -len(ext.suffix) - 1] if ext.suffix and d.endswith("." + ext.suffix) else d
    letters = re.sub(r"[^a-z0-9]", "", name)
    f["name_entropy"] = round(_entropy(letters), 3)
    f["host_length"] = float(min(len(name), 120))
    f["consonant_run"] = float(_consonant_run(name))
    rank = None
    end = ending(d, ext, ctx.get("platforms", frozenset())) if ctx and ctx.get("mask_platforms") else ext.suffix
    if ctx:
        f["tld_risk"] = tld_risk_value(end, ctx.get("tld_table"))
        f["popularity"], rank = popularity_value(d, ctx.get("ranks"), ctx.get("platforms", frozenset()))
    return {"features": f, "brand": brand_name if (hit and not is_global) else (f"{brand_name} (global brand)" if hit else None),
            "official": official, "registered": registered, "domain": d, "ext": ext, "rank": rank, "ending": end,
            "shown_as": folded if folded != d else None}


DESCRIBE = {
    "ml_logit": "Its text patterns resemble known phishing domains (ML text model)",
    "brand_typosquat": "Is the {brand} name re-spelled on a domain {brand} does not own ({registered})",
    "brand_with_lure": "Combines the {brand} name with a lure word (pay, login, bill...) on a domain {brand} does not own",
    "brand_in_subdomain": "Puts the {brand} name in front of an unrelated domain ({registered})",
    "brand_homoglyph": "Imitates the {brand} name with look-alike characters (e.g. 1 for l, 0 for o, Cyrillic letters)",
    "brand_other_mention": "Uses the {brand} name on a domain {brand} does not own (no lure words; could be a fan or partner site)",
    "fake_country_label": "Puts '.ae' or 'gov' inside the name to look official, but the real domain is {registered}",
    "tld_risk": "Uses an ending or host (.{suffix}) that is common among phishing domains in the training data",
    "free_host": "Hosted on a free hosting or site-builder service",
    "many_hyphens": "Unusually many hyphens",
    "lure_word": "Contains a lure word (login, pay, verify, refund...)",
    "deep_subdomain": "Many layers in front of the real domain",
    "digits_in_name": "Many digits in the name",
    "punycode": "Uses non-Latin letters in the name (shown as {shown})",
    "name_entropy": "The name looks randomly generated",
    "host_length": "Unusually long name",
    "consonant_run": "Long run of consonants (looks machine-generated)",
    "popularity": "Belongs to a popular, established website (Tranco rank {rank})",
}

# Wording when a sign LOWERS the risk
DESCRIBE_LOW = {
    "tld_risk": "Uses a common, lower-risk ending (.{suffix})",
}
