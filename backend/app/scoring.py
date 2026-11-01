"""
Shield scoring: how one domain gets its score, level and reasons.

1. Official check (fact): the domain belongs to a registered UAE brand -> "official".
2. Learned score: the risk model (ml/model.py) turns the warning signs into a
   probability. score = 100 x probability. Nothing is added on top.
3. Level:
   - "high risk"        learned score >= the High threshold (0.5% false alarms on legit data)
   - "suspicious"       learned score >= the Suspicious threshold (3% false alarms), OR the
                        UAE-impersonation RULE fires (see below)
   - "no warning signs" otherwise. This is NOT "safe": Shield cannot prove a site is safe.
4. UAE-impersonation rule (not learned): if a domain imitates a REGISTERED UAE brand
   (look-alike letters, re-spelling, brand + lure word, brand in front of an unrelated
   domain, fake '.ae'), it is always sent for analyst review. Public phishing data has
   too few of these patterns to learn their weight, and for government brands review is
   a policy choice. The rule never changes the score; it is shown as "Rule".
5. Reasons: each warning sign's learned effect (weight x value), largest first.
"""

import math
import os

import joblib

from .features import DESCRIBE, FEATURE_NAMES, clean, extract, split_domain
from .registry import UAE_BRANDS

_MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "ml", "domain_model.joblib")
_model = None

IMPERSONATION = ("brand_typosquat", "brand_with_lure", "brand_in_subdomain", "brand_homoglyph")
HOW = {"brand_typosquat": "the name is re-spelled",
       "brand_with_lure": "the name is combined with a lure word",
       "brand_in_subdomain": "the name is placed in front of an unrelated domain",
       "brand_homoglyph": "the name is written with look-alike characters",
       "fake_country_label": "'.ae' is placed inside a foreign domain"}


def _load_model():
    global _model
    if _model is None and os.path.exists(_MODEL_PATH):
        m = joblib.load(_MODEL_PATH)
        _model = m if isinstance(m, dict) and "combiner" in m else None   # old format -> retrain
    return _model


def reload_model():
    global _model
    _model = None
    return _load_model() is not None


def model_info():
    m = _load_model()
    if not m:
        return None
    return {"trained_at": m["trained_at"], "thresholds": m["thresholds"], "weights": m["weights"],
            "results": m.get("results"), "train_rows": m.get("train_rows")}


# ---------- UAE watch helpers (used by the live radar) ----------

UAE_TERMS = ("dubai", "abudhabi", "sharjah", "ajman", "fujairah", "rasalkhaimah",
             "ummalquwain", "emirates", "uae")


def mentions_brand(domain: str) -> bool:
    r = extract(domain, UAE_BRANDS)
    b = r["brand"]
    return bool(b) and "(global brand)" not in b


def uae_reason(domain: str):
    """Why a live domain belongs on the UAE watch (None = not UAE-related)."""
    import re
    d = domain.lower().rstrip(".")
    if d == "ae" or d.endswith(".ae"):
        return ".ae domain"
    flat = re.sub(r"[-.]", "", d)
    tokens = set(re.split(r"[-.]", d))
    for term in UAE_TERMS:
        if (term == "uae" and term in tokens) or (term != "uae" and term in flat):
            return f"mentions '{term}'"
    if mentions_brand(d):
        return "mentions a watched UAE brand"
    return None


# ---------- scoring ----------

def _reason_text(key, info, suffix):
    return DESCRIBE[key].format(brand=info["brand"] or "the brand", registered=info["registered"], suffix=suffix)


def score_domain(domain: str) -> dict:
    d = clean(domain)
    if not d:
        return {"domain": domain, "score": 0, "verdict": "unknown", "reasons": ["Not a valid domain"], "brand": None}
    ext, registered = split_domain(d)
    model = _load_model()

    probe = extract(d, UAE_BRANDS)
    brand = probe["brand"]
    if probe["official"] and brand and "(global brand)" not in brand:
        return {"domain": d, "registered_domain": registered, "score": 0, "verdict": "official",
                "brand": brand, "ml_probability": None, "reasons": [f"Official {brand} domain (registry)"],
                "rule": None, "signals": []}

    if model is None:
        return {"domain": d, "registered_domain": registered, "score": None, "verdict": "unknown",
                "brand": brand, "ml_probability": None, "rule": None, "signals": [],
                "reasons": ["Risk model not trained yet: run python ml\\train_baseline.py"]}

    vec, tc, comb, th = model["vec"], model["text_clf"], model["combiner"], model["thresholds"]
    text_p = float(tc.predict_proba(vec.transform([d]))[0][1])
    text_p_c = min(max(text_p, 1e-6), 1 - 1e-6)
    info = extract(d, UAE_BRANDS, math.log(text_p_c / (1 - text_p_c)))
    x = [info["features"][k] for k in FEATURE_NAMES]
    p = float(comb.predict_proba([x])[0][1])
    score = min(int(100 * p), 99)          # never 100: no model is certain

    # explain: each sign's learned effect on the log-odds
    signals = []
    for k, v in zip(FEATURE_NAMES, x):
        if not v:
            continue
        w = model["weights"][k]
        effect = w * v
        if k == "ml_logit":
            text = f"{DESCRIBE[k]}: {text_p:.0%} phishing-like"
        else:
            text = _reason_text(k, info, ext.suffix)
            text += f" (learned effect: x{math.exp(w):.1f} odds)" if w > 0.05 else " (learned effect: little or none)"
        signals.append({"feature": k, "effect": round(effect, 2), "text": text})
    signals.sort(key=lambda s: s["effect"], reverse=True)

    is_uae_brand = brand and "(global brand)" not in brand
    rule = None
    fired = [k for k in IMPERSONATION if info["features"][k]]
    if is_uae_brand and (fired or info["features"]["fake_country_label"]):
        what = fired[0] if fired else "fake_country_label"
        rule = (f"Rule: imitates {brand}, a registered UAE brand ({HOW[what]}; real domain: {registered}). "
                f"Always sent for analyst review.")
    elif info["features"]["fake_country_label"]:
        rule = "Rule: puts '.ae' / 'gov' inside a foreign domain to look official. Sent for analyst review."

    if p >= th["high"]:
        verdict = "high risk"
    elif p >= th["suspicious"] or rule:
        verdict = "suspicious"
    else:
        verdict = "no warning signs"

    reasons = ([rule] if rule else []) + [s["text"] for s in signals if s["effect"] > 0.3]
    if verdict == "no warning signs" and not reasons:
        reasons = ["No warning signs found in the name. This does not prove the site is safe."]
    return {"domain": d, "registered_domain": registered, "score": score, "verdict": verdict,
            "brand": brand.replace(" (global brand)", "") if brand else None,
            "ml_probability": round(text_p, 3), "probability": round(p, 4),
            "thresholds": {k: round(v, 3) for k, v in th.items()},
            "rule": rule, "signals": signals, "reasons": reasons}
