"""
Shield risk model: how the score is calculated (and why it's legitimate).

Two stages, trained on SEPARATE slices of the training data:

  1. Text model (slice A, 70%): character patterns of the domain -> phishing-likeness.
     TF-IDF of 2-5 character pieces + logistic regression.
  2. Risk combiner (slice B1): a logistic regression over the warning-sign features in
     backend/app/features.py (brand typo-squat, brand + lure word, look-alike letters,
     risky ending, free hosting, ... and the text model's output). It LEARNS how much
     each sign matters. Because slice B was never seen by the text model, the combiner
     doesn't over-trust it.
  3. Thresholds (slice B2): "High risk" and "Suspicious" cut-offs are set so that only
     0.5% / 3% of legitimate domains in B2 would reach them.

score = 100 x probability from the combiner. The probability assumes phishing and
legitimate domains are equally common (the training data is balanced); in the real
world phishing is much rarer, which is why the LEVEL (from the false-alarm-controlled
thresholds) matters more than the raw number.
"""

import math
import os
import sys
import time

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
MODEL_PATH = os.path.join(HERE, "domain_model.joblib")
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from backend.app.features import FEATURE_NAMES, extract  # noqa: E402
from backend.app.registry import UAE_BRANDS              # noqa: E402
from common import COMMON_SUBDOMAINS, augment_legit      # noqa: E402

SEED = 42
FPR_HIGH, FPR_SUSPICIOUS = 0.005, 0.03


def _logit(p):
    p = np.clip(p, 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p))


def feature_matrix(domains, vec, text_clf):
    p = text_clf.predict_proba(vec.transform(domains))[:, 1]
    rows = []
    for d, lg in zip(domains, _logit(p)):
        f = extract(d, UAE_BRANDS, float(lg))["features"]     # once per domain
        rows.append([f[k] for k in FEATURE_NAMES])
    return np.array(rows)


def build(train: pd.DataFrame, log=print, seed=SEED):
    """train: columns domain, is_phishing. Returns the model bundle (dict)."""
    t0 = time.time()
    train = train.drop_duplicates("domain").reset_index(drop=True)
    a, b = train_test_split(train, test_size=0.30, random_state=seed, stratify=train.is_phishing)
    b1, b2 = train_test_split(b, test_size=0.40, random_state=seed, stratify=b.is_phishing)
    a, b1, b2 = augment_legit(a, seed=seed), augment_legit(b1, seed=seed + 1), augment_legit(b2, seed=seed + 2)
    log(f"Slices: text model {len(a)}, combiner {len(b1)}, thresholds {len(b2)}")

    vec = TfidfVectorizer(analyzer="char", ngram_range=(2, 5), min_df=3,
                          max_features=300000, sublinear_tf=True)
    text_clf = LogisticRegression(max_iter=2000, C=4)
    text_clf.fit(vec.fit_transform(a.domain), a.is_phishing)
    log("Text model trained. Extracting warning signs for the combiner ...")

    X1 = feature_matrix(b1.domain.tolist(), vec, text_clf)
    combiner = LogisticRegression(max_iter=2000, C=1.0)
    combiner.fit(X1, b1.is_phishing)

    X2 = feature_matrix(b2.domain.tolist(), vec, text_clf)
    p2 = combiner.predict_proba(X2)[:, 1]
    legit_p = p2[b2.is_phishing.values == 0]
    thresholds = {"high": float(np.quantile(legit_p, 1 - FPR_HIGH)),
                  "suspicious": float(np.quantile(legit_p, 1 - FPR_SUSPICIOUS))}
    weights = {k: float(w) for k, w in zip(FEATURE_NAMES, combiner.coef_[0])}
    log(f"Thresholds (from false-alarm targets): {thresholds}")
    return {"vec": vec, "text_clf": text_clf, "combiner": combiner, "features": FEATURE_NAMES,
            "weights": weights, "intercept": float(combiner.intercept_[0]), "thresholds": thresholds,
            "trained_at": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()) + " UTC",
            "train_rows": int(len(train)), "seconds": round(time.time() - t0)}


def level(p, th):
    return "high risk" if p >= th["high"] else "suspicious" if p >= th["suspicious"] else "no warning signs"


def evaluate(bundle, log=print):
    """Honest evaluation on data never used for training or thresholds."""
    import random
    test = pd.read_csv(os.path.join(DATA, "shield_test_domains.csv"))
    uae = pd.read_csv(os.path.join(DATA, "uae_phishing_domains_real.csv"))
    vec, tc, comb, th = bundle["vec"], bundle["text_clf"], bundle["combiner"], bundle["thresholds"]

    def probs(domains):
        return comb.predict_proba(feature_matrix(list(domains), vec, tc))[:, 1]

    p = probs(test.domain)
    y = test.is_phishing.values
    out = {"auc": round(float(roc_auc_score(y, p)), 3)}
    for name in ("suspicious", "high"):
        pred = (p >= th[name]).astype(int)
        tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
        out[f"at_{name}"] = {"precision": round(precision_score(y, pred), 3),
                             "recall": round(recall_score(y, pred), 3),
                             "f1": round(f1_score(y, pred), 3),
                             "false_positive_rate": round(fp / (fp + tn), 4),
                             "confusion": {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)}}
    rnd = random.Random(7)
    hosts = [f"{rnd.choice(COMMON_SUBDOMAINS)}.{d}" for d in test[test.is_phishing == 0].domain]
    ph = probs(hosts)
    out["legit_hostnames_flagged_suspicious_or_higher"] = round(float((ph >= th["suspicious"]).mean()), 4)
    out["legit_hostnames_flagged_high"] = round(float((ph >= th["high"]).mean()), 4)
    pu = probs(uae.domain)
    levels = [level(x, th) for x in pu]
    out["uae_fakes"] = {"high risk": levels.count("high risk"), "suspicious": levels.count("suspicious"),
                        "no warning signs": levels.count("no warning signs"), "total": len(levels)}
    out["uae_missed"] = [d for d, l in zip(uae.domain, levels) if l == "no warning signs"]
    out["score_distribution_uae"] = {"min": int(100 * pu.min()), "median": int(100 * np.median(pu)), "max": int(100 * pu.max()),
                                     "at_100": int((np.round(100 * pu) >= 100).sum())}
    for k, v in out.items():
        log(f"  {k}: {v}")
    return out


def weights_table(bundle):
    rows = []
    for k in bundle["features"]:
        w = bundle["weights"][k]
        rows.append({"feature": k, "weight": round(w, 3),
                     "odds_multiplier": round(math.exp(w), 2) if k != "ml_logit" else None})
    return rows
