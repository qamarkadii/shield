"""
Shield scoring: how one domain gets its score, level and reasons.

1. Official check (fact): the domain belongs to a registered UAE brand -> "official".
2. Learned score: the risk model (ml/model.py) turns the warning signs into a
   calibrated probability. score = 100 x probability at 50/50 prevalence (for ranking);
   live_probability = the same at the expected live rate of phishing (1%), i.e. the
   honest "chance this one is phishing". Nothing is added on top.
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
5. Reasons: each warning sign's learned effect on the log-odds: the model's output with
   the sign vs. with it switched off (works for the tree-based combiner too), largest first.
"""

import math
import os
import hashlib
import io

import joblib

import numpy as np

from . import riskmodel
from .features import DESCRIBE, DESCRIBE_LOW, FEATURE_NAMES, clean, extract, split_domain, uae_term_in
from .registry import UAE_BRANDS

_MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "ml", "domain_model.joblib")
_model = None
_model_sha256 = None

IMPERSONATION = ("brand_typosquat", "brand_with_lure", "brand_in_subdomain", "brand_homoglyph")
HOW = {"brand_typosquat": "the name is re-spelled",
       "brand_with_lure": "the name is combined with a lure word",
       "brand_in_subdomain": "the name is placed in front of an unrelated domain",
       "brand_homoglyph": "the name is written with look-alike characters",
       "fake_country_label": "'.ae' is placed inside a foreign domain"}


def _load_model():
    global _model, _model_sha256
    if _model is None and os.path.exists(_MODEL_PATH):
        with open(_MODEL_PATH, 'rb') as f:
            raw = f.read()
        m = joblib.load(io.BytesIO(raw))
        ok = isinstance(m, dict) and m.get("version") == riskmodel.BUNDLE_VERSION
        _model = m if ok else None   # old format -> retrain
        _model_sha256 = hashlib.sha256(raw).hexdigest() if ok else None
    return _model


def reload_model():
    global _model, _model_sha256
    _model = None
    _model_sha256 = None
    return _load_model() is not None


def model_info():
    m = _load_model()
    if not m:
        return None
    return {"model_sha256": _model_sha256, "trained_at": m["trained_at"], "thresholds": m["thresholds"], "weights": m["weights"],
            "combiner": m.get("combiner_kind"), "results": m.get("results"), "train_rows": m.get("train_rows"),
            "data": m.get("data_summary")}


# ---------- UAE watch helpers (used by the live radar) ----------

def mentions_brand(domain: str) -> bool:
    r = extract(domain, UAE_BRANDS)
    b = r["brand"]
    return bool(b) and "(global brand)" not in b


def uae_reason(domain: str):
    """Why a live domain belongs on the UAE watch (None = not UAE-related)."""
    d = domain.lower().rstrip(".")
    if d == "ae" or d.endswith(".ae"):
        return ".ae domain"
    term = uae_term_in(d) or ("emirates" if any(t.startswith("emirates") or t.endswith("emirates")
                                                 for t in d.replace("-", ".").split(".")) else None)
    if term:
        return f"mentions '{term}'"
    if mentions_brand(d):
        return "mentions a watched UAE brand"
    return None


# ---------- scoring ----------

def _reason_text(key, info, suffix, effect=1.0):
    return (DESCRIBE_LOW if effect < 0 and key in DESCRIBE_LOW else DESCRIBE)[key].format(brand=(info["brand"] or "the brand").replace(" (global brand)", ""),
                                registered=info["registered"], suffix=suffix,
                                rank=f"{info['rank']:,}" if info.get("rank") else "?",
                                shown=info.get("shown_as") or info["domain"])


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
                "reasons": ["Risk model not trained yet (or trained by an older version): run python ml\train_baseline.py"]}

    p_raw, p_bal, X, infos = riskmodel.predict(model, [d])
    p_raw, p_bal, x, info = float(p_raw[0]), float(p_bal[0]), X[0], infos[0]
    p_live = float(riskmodel.calibrated(model, np.array([p_raw]), model["live_prevalence"])[0])
    text_p = float(riskmodel.sigmoid(x[0]))
    score = min(int(round(100 * p_bal)), 99)          # never 100: no model is certain
    raw_th = model["raw_thresholds"]

    # explain: each sign's learned effect on the log-odds (with vs. without it)
    effects = riskmodel.ablation_effects(model, X)[0]
    signals = []
    for k, v, e in zip(FEATURE_NAMES, x, effects):
        if e == 0:
            continue
        if k == "ml_logit":
            text = f"{DESCRIBE[k]}: {text_p:.0%} phishing-like"
        elif riskmodel.is_binary(k) or k in ("popularity", "tld_risk"):
            text = _reason_text(k, info, info.get("ending") or ext.suffix, e)
        elif e > 0:
            text = DESCRIBE[k]
        else:
            continue          # 'normal-looking name' isn't worth listing
        if k != "ml_logit":
            text += (f" (learned effect: x{math.exp(e):.1f} odds)" if e > 0.05 else
                     f" (learned effect: /{math.exp(-e):.1f} odds)" if e < -0.05 else " (learned effect: little or none)")
        signals.append({"feature": k, "effect": round(float(e), 2), "text": text})
    signals.sort(key=lambda s: s["effect"], reverse=True)

    is_uae_brand = brand and "(global brand)" not in brand
    rule = None
    fired = [k for k in IMPERSONATION if info["features"][k]]
    if is_uae_brand and (fired or info["features"]["fake_country_label"]):
        what = fired[0] if fired else "fake_country_label"
        official = next((", ".join(doms) for name, doms in UAE_BRANDS.values() if name == brand), "?")
        rule = (f"Rule: imitates {brand}, a registered UAE brand ({HOW[what]}; this site: {registered}, "
                f"official: {official}). Always sent for analyst review.")
    elif info["features"]["fake_country_label"]:
        rule = "Rule: puts '.ae' / 'gov' inside a foreign domain to look official. Sent for analyst review."

    if p_raw >= raw_th["high"]:
        verdict = "high risk"
    elif p_raw >= raw_th["suspicious"] or rule:
        verdict = "suspicious"
    else:
        verdict = "no warning signs"

    reasons = ([rule] if rule else []) + [s["text"] for s in signals if s["effect"] > 0.3]
    if verdict == "no warning signs" and not reasons:
        reasons = ["No warning signs found in the name. This does not prove the site is safe."]
    return {"domain": d, "registered_domain": registered, "score": score, "verdict": verdict,
            "brand": brand.replace(" (global brand)", "") if brand else None,
            "ml_probability": round(text_p, 3), "probability": round(p_bal, 4),
            "live_probability": round(p_live, 4),
            "thresholds": {k: round(v, 3) for k, v in model["thresholds"].items()},
            "rule": rule, "signals": signals, "reasons": reasons}


# ---------- name + domain facts (enrich.py, ml/train_facts.py) ----------

_FACTS_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "ml", "facts_model.joblib")
_facts_model = None


def facts_model():
    global _facts_model
    if _facts_model is None and os.path.exists(_FACTS_PATH):
        m = joblib.load(_FACTS_PATH)
        _facts_model = m if isinstance(m, dict) and m.get("version") == 1 else None
    return _facts_model


def reload_facts_model():
    global _facts_model
    _facts_model = None
    return facts_model() is not None


def assess(domain: str, tls: bool = False, budget: float | None = None) -> dict:
    """score_domain() plus what the internet says about the domain (age, registrar, certificate,
    hosting). With a trained facts model the level is re-decided on name + facts together.
    budget: give up on the facts after this many seconds (citizen site) and keep the name result."""
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as FTimeout
    from . import enrich
    r = score_domain(domain)
    if r["verdict"] in ("official", "unknown") or r.get("score") is None:
        return r
    pool = ThreadPoolExecutor(1)
    fut = pool.submit(enrich.facts, r["domain"], tls)
    try:
        fx = fut.result(timeout=budget)
    except FTimeout:
        r["facts"] = {"timed_out": True}
        return r
    finally:
        pool.shutdown(wait=False)
    r["facts"] = fx
    fm = facts_model()
    rd = fx.get("rdap") or {}
    if not (fm and (fx.get("dns") or {}).get("resolves")):
        if rd.get("age_days") is not None:
            r["reasons"].append(f"Domain registered {rd['age_days']} days ago ({rd.get('created')})")
        return r
    vec = enrich.fact_vector(fx)
    x = np.array([[riskmodel.logit(np.array([r["probability"]]))[0]] + [vec[k] for k in enrich.FACT_NAMES]])
    p = float(fm["clf"].predict_proba(x)[0, 1])
    w = dict(zip(fm["names"], fm["clf"].coef_[0]))
    th = fm["thresholds"]
    level = "high risk" if p >= th["high"] else "suspicious" if p >= th["suspicious"] else "no warning signs"
    if r.get("rule") and level == "no warning signs":
        level = "suspicious"
    cert = fx.get("certificate") or {}
    fsig = []
    for k in enrich.FACT_NAMES:
        if k == "age_days_log" or not vec[k]:
            continue
        eff = float(w[k]) * vec[k]
        if abs(eff) < 0.1:
            continue
        text = enrich.FACT_DESCRIBE[k].format(age=rd.get("age_days"), issuer=cert.get("issuer") or "?",
                                              n=cert.get("names_covered"))
        fsig.append({"feature": k, "effect": round(eff, 2),
                     "text": text + (f" (learned effect: x{math.exp(eff):.1f} odds)" if eff > 0
                                     else f" (learned effect: /{math.exp(-eff):.1f} odds)")})
    if rd.get("age_days") is not None:
        eff = float(w["age_days_log"]) * (vec["age_days_log"] - 2.5)
        fsig.append({"feature": "age_days_log", "effect": round(eff, 2),
                     "text": f"Domain registered {rd['age_days']} days ago ({rd.get('created')})"})
    fsig.sort(key=lambda s: -s["effect"])
    r["fact_signals"] = fsig
    r["name_verdict"] = r["verdict"]
    r["verdict"] = level
    r["combined_probability"] = round(p, 4)
    r["score"] = min(int(round(100 * p)), 99)
    r["reasons"] = r["reasons"] + [s["text"] for s in fsig if s["effect"] > 0.3]
    if level == "no warning signs":
        r["reasons"] = [x for x in r["reasons"] if not x.startswith("No warning signs")] or \
            ["No warning signs found in the name or the domain's records. This does not prove the site is safe."]
    return r
