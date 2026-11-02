"""
Synthetic UAE-brand impersonations, for TRAINING ONLY.

Public phishing data has very few fakes of UAE brands (re-spelled brand names: about
1 in 20,000 training domains), so the model could not learn how much those patterns
matter and needed a hand rule. These generated examples (dnstwist-style) let it learn
real weights for typo-squats, look-alike letters, brand + lure, brand in a subdomain
and fake '.ae' labels.

They are NEVER used for evaluation: every reported number comes from real domains.
Generated names that collide with an official domain or a held-out owner are dropped.
"""

import random

import pandas as pd

KEYBOARD = {
    "a": "qsz", "b": "vgn", "c": "xvd", "d": "sfe", "e": "wrd", "f": "dgr", "g": "fht", "h": "gjy",
    "i": "uok", "j": "hku", "k": "jli", "l": "kop", "m": "nj", "n": "bmh", "o": "ipl", "p": "ol",
    "q": "wa", "r": "eft", "s": "adw", "t": "rgy", "u": "yij", "v": "cbf", "w": "qes", "x": "zcs",
    "y": "tuh", "z": "xa",
}
DIGIT_LOOK = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5", "t": "7", "b": "8", "g": "9"}
CYRILLIC_LOOK = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у", "i": "і"}
LURES = ["pay", "payment", "login", "secure", "verify", "update", "account", "fines", "fine", "bill",
         "bills", "refund", "track", "tracking", "delivery", "parcel", "kyc", "otp", "support", "portal",
         "online", "service", "wallet", "reward", "gift", "unlock", "confirm", "auth", "recharge", "topup"]
TLDS = ["com"] * 6 + ["net"] * 2 + ["org", "info", "xyz", "top", "online", "shop", "live", "cc", "icu", "site",
                                    "app", "me", "co", "vip", "click", "support", "help", "services", "pro"]
CARRIERS = ["valeriair", "brandsoptima", "globalnet", "cloudserve", "mysrv", "hostpoint", "netcore",
            "webzone", "digitalhub", "primehost", "secure-node", "fastweb", "techway", "srv-mail"]


def _typos(key, rnd):
    i = rnd.randrange(len(key))
    kind = rnd.choice(["omit", "double", "swap", "key", "vowel"])
    if kind == "omit":
        return key[:i] + key[i + 1:]
    if kind == "double":
        return key[:i] + key[i] + key[i:]
    if kind == "swap" and i < len(key) - 1:
        return key[:i] + key[i + 1] + key[i] + key[i + 2:]
    if kind == "key" and key[i] in KEYBOARD:
        return key[:i] + rnd.choice(KEYBOARD[key[i]]) + key[i + 1:]
    vowels = "aeiou"
    spots = [j for j, c in enumerate(key) if c in vowels]
    if spots:
        j = rnd.choice(spots)
        return key[:j] + rnd.choice(vowels.replace(key[j], "")) + key[j + 1:]
    return key + key[-1]


def _homoglyph(key, rnd):
    if rnd.random() < 0.3:
        spots = [j for j, c in enumerate(key) if c in CYRILLIC_LOOK]
        if spots:
            j = rnd.choice(spots)
            uni = key[:j] + CYRILLIC_LOOK[key[j]] + key[j + 1:]
            return uni.encode("idna").decode("ascii")
    spots = [j for j, c in enumerate(key) if c in DIGIT_LOOK]
    if not spots:
        return None
    for j in rnd.sample(spots, min(len(spots), rnd.choice([1, 1, 2]))):
        key = key[:j] + DIGIT_LOOK[key[j]] + key[j + 1:]
    return key


def _sep(rnd):
    return rnd.choice(["-", "", "-", "."])


def one(key, rnd):
    tld = rnd.choice(TLDS)
    lure = rnd.choice(LURES)
    p = rnd.random()
    short = len(key) <= 4
    if p < 0.22 and not short:                       # re-spelled brand
        name = _typos(key, rnd)
        return f"{name}.{tld}" if rnd.random() < 0.6 else f"{name}-{lure}.{tld}"
    if p < 0.38 and not short:                       # look-alike letters
        name = _homoglyph(key, rnd)
        if not name:
            return None
        return f"{name}.{tld}" if rnd.random() < 0.5 else f"{name}-{lure}.{tld}"
    if p < 0.62:                                     # brand + lure
        s = _sep(rnd).replace(".", "-")
        a, b = (key, lure) if rnd.random() < 0.7 else (lure, key)
        extra = rnd.choice(["", "", "-ae", "-uae", "ae", "-online", "-gov"])
        return f"{a}{s}{b}{extra}.{tld}"
    if p < 0.80:                                     # brand in front of an unrelated domain
        carrier = rnd.choice(CARRIERS) + rnd.choice(["", str(rnd.randint(1, 99))])
        mid = rnd.choice(["", f"{lure}.", f"{lure}-{rnd.randint(10, 999)}."])
        return f"{key}.{mid}{carrier}.{tld}"
    if p < 0.92:                                     # fake '.ae' / gov label
        form = rnd.choice([f"{key}.ae-{lure}.{tld}", f"{key}-ae.{tld}", f"{key}.gov-ae.{tld}",
                           f"{lure}.{key}.ae.{rnd.choice(CARRIERS)}.{tld}", f"ae-{key}-{lure}.{tld}"])
        return form
    # deep chain on a free host
    host = rnd.choice(["web.app", "pages.dev", "vercel.app", "netlify.app", "weeblysite.com",
                       "firebaseapp.com", "github.io", "workers.dev"])
    return f"{key}{_sep(rnd).replace('.', '-')}{lure}{rnd.randint(1, 9999)}.{host}"


def generate(uae_brands, n=3000, seed=13, exclude_owners=frozenset(), platforms=frozenset()):
    """DataFrame(domain, is_phishing=1, source='synthetic_uae')."""
    from backend.app.features import extract, owner
    rnd = random.Random(seed)
    keys = sorted(uae_brands)
    seen, out = set(), []
    tries = 0
    while len(out) < n and tries < n * 20:
        tries += 1
        d = one(rnd.choice(keys), rnd)
        if not d or d in seen:
            continue
        seen.add(d)
        if owner(d, platforms) in exclude_owners:
            continue
        info = extract(d, uae_brands)
        if info["official"] or not info["brand"] or "(global brand)" in info["brand"]:
            continue
        out.append(d)
    return pd.DataFrame({"domain": out, "is_phishing": 1, "source": "synthetic_uae"})
