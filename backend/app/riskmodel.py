"""
Risk model inference, shared by training (ml/model.py) and live scoring (scoring.py),
so a domain is always turned into numbers the same way.

The model bundle (ml/domain_model.joblib, built by ml/model.py) holds:
  vec, text_clf      character n-gram text model  -> ml_logit
  tld_table          learned phishing log-odds per ending -> tld_risk
  platforms          multi-tenant hosting platforms (tenants never inherit popularity)
  combiner           sklearn classifier over FEATURE_NAMES -> raw probability
  calib              Platt scaling of the raw probability (fitted on a held-out slice)
  raw_thresholds     cut-offs on the raw probability (false-alarm budget)
"""

import math

import numpy as np

from .features import BINARY, FEATURE_NAMES, extract, text_input
from .popularity import load_ranks
from .registry import UAE_BRANDS

BUNDLE_VERSION = 2


def logit(p):
    p = np.clip(np.asarray(p, dtype=float), 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p))


def sigmoid(z):
    return 1.0 / (1.0 + np.exp(-np.asarray(z, dtype=float)))


def text_logits(vec, text_clf, domains, platforms=frozenset(), mask=False):
    return logit(text_clf.predict_proba(vec.transform([text_input(d, platforms, mask) for d in domains]))[:, 1])


def context(bundle):
    return {"tld_table": bundle["tld_table"],
            "ranks": load_ranks() if bundle.get("uses_popularity") else None,
            "platforms": bundle["platforms"], "mask_platforms": bundle.get("mask_platforms", False)}


def feature_rows(domains, ml_logits, ctx):
    """Matrix in FEATURE_NAMES order, plus each domain's extract() info."""
    rows, infos = [], []
    for d, lg in zip(domains, ml_logits):
        info = extract(d, UAE_BRANDS, float(lg), ctx)
        rows.append([info["features"][k] for k in FEATURE_NAMES])
        infos.append(info)
    return np.array(rows, dtype=float), infos


def raw_proba(bundle, X):
    return bundle["combiner"].predict_proba(np.asarray(X, dtype=float))[:, 1]


def calibrated(bundle, p_raw, prevalence=0.5):
    """Calibrated probability if `prevalence` of all domains were phishing.
    0.5 = balanced (the 0-100 score); bundle['live_prevalence'] = expected live rate."""
    c = bundle["calib"]
    z = c["a"] * logit(p_raw) + c["b"] - math.log(c["prevalence"] / (1 - c["prevalence"]))
    return sigmoid(z + math.log(prevalence / (1 - prevalence)))


def predict(bundle, domains):
    """Score many domains. Returns (raw p, balanced calibrated p, X, infos)."""
    domains = list(domains)
    lg = text_logits(bundle["vec"], bundle["text_clf"], domains, bundle["platforms"], bundle.get("mask_platforms", False))
    X, infos = feature_rows(domains, lg, context(bundle))
    p = raw_proba(bundle, X)
    return p, calibrated(bundle, p), X, infos


def ablation_effects(bundle, X):
    """Each feature's effect on the log-odds for each row: model with the feature
    at its reference value (0 for yes/no signs, typical legit value for numbers)
    vs. as observed. Works for any combiner (no need for linear weights).
    Returns array (rows, features); 0 where the feature equals its reference."""
    X = np.asarray(X, dtype=float)
    ref = np.array([bundle["reference"][k] for k in FEATURE_NAMES])
    base = logit(raw_proba(bundle, X))
    eff = np.zeros_like(X)
    for j in range(X.shape[1]):
        changed = X[:, j] != ref[j]
        if not changed.any():
            continue
        Xa = X[changed].copy()
        Xa[:, j] = ref[j]
        eff[changed, j] = base[changed] - logit(raw_proba(bundle, Xa))
    return eff


def is_binary(k):
    return k in BINARY
