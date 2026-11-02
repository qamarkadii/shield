"""
Shield risk model v2: how the score is calculated (and why it's legitimate).

Data
  * Base labelled domains (data/shield_training_domains.csv).
  * REAL legitimate hostnames (console.aws.amazon.com, x.github.io) from the Umbrella top-1M,
    under well-established Tranco top-100k sites - live certificates look like this.
  * Synthetic UAE-brand impersonations (ml/synth_uae.py) - training only, never evaluated on.
  * Analyst labels (retrain.py), weighted x ANALYST_WEIGHT.
  * Every row has an OWNER (registered domain, or the tenant on a hosting platform:
    shop.weeblysite.com). Rows whose owner appears in ANY evaluation set are removed, and
    every split below keeps one owner on one side - so the test can't be passed by
    recognising a site seen in training.

Model (stacked, out-of-fold)
  1. Text model: TF-IDF of 2-5 character pieces + logistic regression (C tuned on a
     grouped validation split). Trained 5x on 4/5 of the owners; each row gets the score
     from the model that did NOT see it (out-of-fold). The final text model uses all rows.
  2. tld_risk: learned phishing log-odds per ending, also out-of-fold.
  3. Combiner over the warning-sign features (backend/app/features.py), trained on the
     out-of-fold values: gradient-boosted trees with monotonic constraints (brand signs
     can only raise risk, popularity can only lower it) vs. scaled logistic regression;
     the one with lower log-loss on the held-out slice is kept.
  4. Held-out slice (15% of owners, real rows only):
     - thresholds: "High risk" / "Suspicious" cut-offs so only 0.5% / 3% of its
       legitimate domains reach them;
     - calibration (Platt scaling), so score 70 means ~70% (at 50/50 prevalence) and
       `live_probability` gives the chance at the expected live rate (1%).
"""

import math
import os
import sys
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, log_loss, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupKFold, GroupShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
MODEL_PATH = os.path.join(HERE, "domain_model.joblib")
FROZEN_UAE = os.path.join(DATA, "uae_holdout_frozen.csv")
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from backend.app import riskmodel                                         # noqa: E402
from backend.app.features import (FEATURE_NAMES, MONOTONIC, clean, extract,  # noqa: E402
                                  owner, text_input, tld_risk_value)
from backend.app.popularity import load_ranks                             # noqa: E402
from backend.app.registry import UAE_BRANDS                               # noqa: E402
from common import (augment_legit, detect_platforms, legit_hostname_fpr,   # noqa: E402
                    precision_at, real_legit_hostnames, wilson)
import synth_uae                                                          # noqa: E402

SEED = 42
FPR_HIGH, FPR_SUSPICIOUS = 0.005, 0.03
LIVE_PREVALENCE = 0.01          # assumed share of phishing among live certificate names
ANALYST_WEIGHT = 25.0
N_REAL_HOSTS = 40_000
N_SYNTH_UAE = 3_000
TEXT_C_GRID = (1.0, 4.0, 16.0)
MASK_PLATFORMS = False          # see features.text_input: tested, made free-host false alarms worse
SANITY = ["react-docs.vercel.app", "my-portfolio.netlify.app", "team-blog.github.io",
          "eu-west-1.console.aws.amazon.com", "a1b2c3.cloudfront.net", "careers.dubaiholding.com",
          "login.microsoftonline.com", "shop.alfuttaim.ae", "bestpizza-dubai.com",
          "emirates-post.org", "aramex.valeriair.com", "salik-pay.com", "xn--slik-53d.com"]


# ---------- data ----------

def load_eval_sets():
    test = pd.read_csv(os.path.join(DATA, "shield_test_domains.csv"))
    uae = pd.read_csv(os.path.join(DATA, "uae_phishing_domains_real.csv"))
    frozen = pd.read_csv(FROZEN_UAE) if os.path.exists(FROZEN_UAE) else pd.DataFrame(columns=["domain"])
    for df in (test, uae, frozen):
        df["domain"] = df.domain.map(clean)
    return test, uae, frozen


def held_out_owners(platforms):
    test, uae, frozen = load_eval_sets()
    return {owner(d, platforms) for d in pd.concat([test.domain, uae.domain, frozen.domain])}


def _static(domains, ranks, platforms):
    """Features that don't depend on the fitted models (+ each domain's ending)."""
    ctx = {"tld_table": None, "ranks": ranks, "platforms": platforms, "mask_platforms": MASK_PLATFORMS}
    rows, suffixes = [], []
    for d in domains:
        info = extract(d, UAE_BRANDS, 0.0, ctx)
        rows.append([info["features"][k] for k in FEATURE_NAMES])
        suffixes.append(info["ending"])
    return np.array(rows, dtype=float), suffixes


def tld_table(suffixes, y, w, m=50.0):
    """Smoothed phishing log-odds per ending, relative to the average (0 = average)."""
    df = pd.DataFrame({"s": suffixes, "y": y, "w": w})
    df["last"] = df.s.str.split(".").str[-1]
    prior = float(np.average(df.y, weights=df.w))
    lo = {}
    for col in ("last", "s"):                # full ending overrides its last label
        g = df.assign(wy=df.w * df.y).groupby(col)[["wy", "w"]].sum()
        rate = (g.wy + m * prior) / (g.w + m)
        z = np.log(rate / (1 - rate)) - math.log(prior / (1 - prior))
        lo.update({k: round(float(v), 4) for k, v in z.items() if k})
    return {"logodds": lo, "prior": prior, "default": 0.0}


def _tld_column(suffixes, table):
    return np.array([tld_risk_value(s, table) for s in suffixes])


def _text_model(C):
    vec = TfidfVectorizer(analyzer="char", ngram_range=(2, 5), min_df=3, max_features=300000,
                          sublinear_tf=True)
    return vec, LogisticRegression(max_iter=2000, C=C)


def tune_text_C(fit, T, seed, log):
    """Pick C on a grouped validation split of a 80k-row sample (owners never shared).
    T: TF-IDF matrix of fit (its vocabulary uses no labels, so sharing it doesn't leak)."""
    idx = np.random.default_rng(seed).choice(len(fit), min(80_000, len(fit)), replace=False)
    s = fit.iloc[idx]
    tr, va = next(GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed).split(s, groups=s.owner))
    best = None
    for C in TEXT_C_GRID:
        _, clf = _text_model(C)
        clf.fit(T[idx[tr]], s.is_phishing.iloc[tr], sample_weight=s.weight.iloc[tr])
        p = clf.predict_proba(T[idx[va]])[:, 1]
        ll = log_loss(s.is_phishing.iloc[va], p)
        log(f"  text model C={C}: grouped validation log-loss {ll:.4f}")
        if best is None or ll < best[1]:
            best = (C, ll)
    return best[0]


def _combiners(seed):
    cst = [MONOTONIC.get(k, 0) for k in FEATURE_NAMES]
    return {
        "gradient_boosting": HistGradientBoostingClassifier(
            max_iter=400, learning_rate=0.06, max_leaf_nodes=31, min_samples_leaf=40,
            l2_regularization=1.0, monotonic_cst=cst, early_stopping=True,
            validation_fraction=0.1, n_iter_no_change=25, random_state=seed),
        "logistic_regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000, C=1.0)),
    }


def _fit(model, X, y, w):
    if hasattr(model, "steps"):
        model.fit(X, y, logisticregression__sample_weight=w)
    else:
        model.fit(X, y, sample_weight=w)
    return model


# ---------- build ----------

def build(train: pd.DataFrame, log=print, seed=SEED):
    """train: columns domain, is_phishing [, weight, source]. Returns the model bundle (dict)."""
    t0 = time.time()
    train = train.copy()
    train["domain"] = train.domain.map(clean)
    train = train[train.domain.str.contains(".", regex=False)]
    if "weight" not in train:
        train["weight"] = 1.0
    if "source" not in train:
        train["source"] = "base"
    train["weight"] = train.weight.fillna(1.0)
    train["source"] = train.source.fillna("base")
    train = train.drop_duplicates("domain", keep="first").reset_index(drop=True)

    ranks = load_ranks()
    log(f"Popularity list: {len(ranks):,} sites" if ranks else
        "Popularity list missing (data/lists/tranco.zip) - popularity feature off")
    test, uae, frozen = load_eval_sets()
    platforms = detect_platforms(pd.concat([train.domain, test.domain, uae.domain]))
    log(f"Detected {len(platforms)} multi-tenant hosting platforms")
    train["owner"] = [owner(d, platforms) for d in train.domain]
    held = held_out_owners(platforms)

    # real legitimate hostnames: training part (eval part is used only in evaluate())
    phish_owners = set(train.owner[train.is_phishing == 1])
    real = real_legit_hostnames(ranks, platforms, exclude_owners=held | phish_owners)
    real_train = real[~real["eval"] & ~real.owner.isin(held)]
    real_train = real_train.sample(min(N_REAL_HOSTS, len(real_train)), random_state=seed)
    log(f"Real legitimate hostnames: {len(real_train):,} for training, "
        f"{int(real['eval'].sum()):,} reserved for evaluation (their owners are never trained on)")

    purged = train.owner.isin(held | set(real.owner[real["eval"]]))
    log(f"Removed {int(purged.sum()):,} training rows whose owner is in an evaluation set (leakage)")
    train = train[~purged]

    synth = synth_uae.generate(UAE_BRANDS, n=N_SYNTH_UAE, seed=seed, exclude_owners=held, platforms=platforms)
    synth["weight"] = 1.0
    log(f"Synthetic UAE impersonations (training only): {len(synth):,}")

    extra = pd.concat([real_train.assign(is_phishing=0, weight=1.0, source="real_host")[
                           ["domain", "is_phishing", "weight", "source", "owner"]],
                       synth.assign(owner=[owner(d, platforms) for d in synth.domain])], ignore_index=True)
    data = pd.concat([train, extra], ignore_index=True).drop_duplicates("domain", keep="first").reset_index(drop=True)

    # held-out slice for thresholds + calibration: real rows only, whole owners
    cand = data[data.source.isin(["base", "real_host"])]
    _, hi = next(GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=seed).split(cand, groups=cand.owner))
    hold_idx = cand.index[hi]
    hold_owners = set(data.owner[hold_idx])
    hold = data.loc[hold_idx].reset_index(drop=True)
    fit = data[~data.owner.isin(hold_owners)].reset_index(drop=True)
    fit = augment_legit(fit, seed=seed)
    log(f"Rows: fit {len(fit):,} (incl. augmented copies), held-out {len(hold):,} "
        f"(phishing share {hold.is_phishing.mean():.2f})")

    log("Extracting warning signs ...")
    S_fit, suf_fit = _static(fit.domain, ranks, platforms)
    S_hold, suf_hold = _static(hold.domain, ranks, platforms)
    y, w = fit.is_phishing.values, fit.weight.values
    i_lg, i_tld = FEATURE_NAMES.index("ml_logit"), FEATURE_NAMES.index("tld_risk")

    # Character vocabulary + IDF built ONCE (no labels involved) and shared by every fit:
    # rebuilding it per fold was most of the training time.
    vec, _ = _text_model(1.0)
    T = vec.fit_transform([text_input(d, platforms, MASK_PLATFORMS) for d in fit.domain]).tocsr()
    C = tune_text_C(fit, T, seed, log)
    log(f"Text model: C={C}; out-of-fold scores (5 folds by owner) ...")
    X_fit = S_fit.copy()
    for k, (tr, va) in enumerate(GroupKFold(n_splits=5, shuffle=True, random_state=seed).split(fit, groups=fit.owner)):
        _, clf = _text_model(C)
        clf.fit(T[tr], y[tr], sample_weight=w[tr])
        X_fit[va, i_lg] = riskmodel.logit(clf.predict_proba(T[va])[:, 1])
        X_fit[va, i_tld] = _tld_column([suf_fit[i] for i in va],
                                       tld_table([suf_fit[i] for i in tr], y[tr], w[tr]))
        log(f"  fold {k + 1}/5 done")
    _, text_clf = _text_model(C)
    text_clf.fit(T, y, sample_weight=w)
    ttable = tld_table(suf_fit, y, w)

    X_hold = S_hold.copy()
    X_hold[:, i_lg] = riskmodel.text_logits(vec, text_clf, hold.domain, platforms, MASK_PLATFORMS)
    X_hold[:, i_tld] = _tld_column(suf_hold, ttable)
    yh = hold.is_phishing.values

    log("Training combiners ...")
    scores, best = {}, None
    for name, m in _combiners(seed).items():
        _fit(m, X_fit, y, w)
        ph = m.predict_proba(X_hold)[:, 1]
        scores[name] = {"holdout_log_loss": round(float(log_loss(yh, ph)), 4),
                        "holdout_auc": round(float(roc_auc_score(yh, ph)), 4)}
        log(f"  {name}: {scores[name]}")
        if best is None or scores[name]["holdout_log_loss"] < scores[best[0]]["holdout_log_loss"]:
            best = (name, m, ph)
    kind, combiner, p_hold = best
    log(f"Kept combiner: {kind}")

    legit_p = p_hold[yh == 0]
    raw_th = {"high": float(np.quantile(legit_p, 1 - FPR_HIGH)),
              "suspicious": float(np.quantile(legit_p, 1 - FPR_SUSPICIOUS))}
    platt = LogisticRegression(C=1e6, max_iter=1000).fit(riskmodel.logit(p_hold).reshape(-1, 1), yh)
    calib = {"a": float(platt.coef_[0][0]), "b": float(platt.intercept_[0]),
             "prevalence": float(yh.mean())}

    legit_rows = X_hold[yh == 0]
    reference = {k: (0.0 if k in ("ml_logit", "tld_risk", "popularity") or riskmodel.is_binary(k)
                     else float(np.median(legit_rows[:, j]))) for j, k in enumerate(FEATURE_NAMES)}

    bundle = {"version": riskmodel.BUNDLE_VERSION, "vec": vec, "text_clf": text_clf, "text_C": C,
              "tld_table": ttable, "platforms": platforms, "uses_popularity": bool(ranks),
              "mask_platforms": MASK_PLATFORMS,
              "combiner": combiner, "combiner_kind": kind, "combiner_scores": scores,
              "features": FEATURE_NAMES, "reference": reference, "calib": calib,
              "live_prevalence": LIVE_PREVALENCE, "raw_thresholds": raw_th,
              "trained_at": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()) + " UTC",
              "train_rows": int(len(fit)),
              "data_summary": {"base_rows": int((data.source == "base").sum()),
                               "real_hostnames": int((data.source == "real_host").sum()),
                               "synthetic_uae": int((data.source == "synthetic_uae").sum()),
                               "analyst": int((data.source == "analyst").sum()),
                               "fresh_feed": int((data.source == "feed").sum()),
                               "purged_for_leakage": int(purged.sum()),
                               "heldout_rows": int(len(hold)), "platforms": len(platforms)}}
    bundle["thresholds"] = {k: float(riskmodel.calibrated(bundle, np.array([v]))[0]) for k, v in raw_th.items()}
    bundle["weights"] = effects_table(bundle, X_hold, yh)
    bundle["seconds"] = round(time.time() - t0)
    bundle["_real_eval"] = real[real["eval"]].domain.tolist()
    log(f"Thresholds (score 0-100): suspicious {100 * bundle['thresholds']['suspicious']:.0f}, "
        f"high {100 * bundle['thresholds']['high']:.0f}")
    return bundle


def effects_table(bundle, X, y, n=6000, seed=SEED):
    """Average learned effect of each sign (log-odds) on held-out rows where it is present."""
    rng = np.random.default_rng(seed)
    idx = rng.choice(len(X), min(n, len(X)), replace=False)
    eff = riskmodel.ablation_effects(bundle, X[idx])
    Xs = X[idx]
    ref = np.array([bundle["reference"][k] for k in FEATURE_NAMES])
    out = {}
    for j, k in enumerate(FEATURE_NAMES):
        on = Xs[:, j] != ref[j]
        out[k] = {"avg_effect": round(float(eff[on, j].mean()), 3) if on.any() else 0.0,
                  "present_in": round(float(on.mean()), 4)}
    return out


def level(p, th):
    return "high risk" if p >= th["high"] else "suspicious" if p >= th["suspicious"] else "no warning signs"


# ---------- evaluation ----------

def _flags(bundle, domains, name):
    p, _, _, _ = riskmodel.predict(bundle, domains)
    return (p >= bundle["raw_thresholds"][name]).astype(int)


def evaluate(bundle, log=print):
    """Honest evaluation on data never used for training, thresholds or calibration."""
    test, uae, frozen = load_eval_sets()
    th = bundle["raw_thresholds"]
    p, pc, _, infos = riskmodel.predict(bundle, test.domain)
    y = test.is_phishing.values
    out = {"auc": round(float(roc_auc_score(y, p)), 3)}
    for name in ("suspicious", "high"):
        pred = (p >= th[name]).astype(int)
        tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
        rec, fpr = tp / (tp + fn), fp / (fp + tn)
        out[f"at_{name}"] = {"precision": round(precision_score(y, pred), 3),
                             "recall": round(float(rec), 3), "recall_ci": wilson(tp, tp + fn),
                             "f1": round(f1_score(y, pred), 3),
                             "false_positive_rate": round(float(fpr), 4), "fpr_ci": wilson(fp, fp + tn),
                             f"precision_at_{LIVE_PREVALENCE:.0%}_phishing": precision_at(LIVE_PREVALENCE, rec, fpr),
                             "confusion": {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)}}
    out["live_prevalence_assumed"] = LIVE_PREVALENCE
    out["calibration_brier"] = round(float(np.mean((pc - y) ** 2)), 4)

    # legit test domains that are NOT popular sites (the long tail live certificates come from)
    unpop = np.array([inf["features"]["popularity"] == 0 for inf in infos]) & (y == 0)
    out["legit_not_popular_flagged"] = {"n": int(unpop.sum()),
                                        "suspicious_or_higher": round(float((p[unpop] >= th["suspicious"]).mean()), 4),
                                        "high": round(float((p[unpop] >= th["high"]).mean()), 4)}
    legit = test[test.is_phishing == 0].domain.tolist()
    out["legit_hostnames_flagged_suspicious_or_higher"] = round(
        legit_hostname_fpr(lambda h: _flags(bundle, h, "suspicious"), legit), 4)
    out["legit_hostnames_flagged_high"] = round(
        legit_hostname_fpr(lambda h: _flags(bundle, h, "high"), legit), 4)

    real_eval = bundle.get("_real_eval") or []
    if real_eval:
        pr, _, _, rinf = riskmodel.predict(bundle, real_eval)
        fh = np.array([inf["features"]["free_host"] == 1 for inf in rinf])
        out["real_legit_hostnames"] = {"n": len(real_eval),
                                       "suspicious_or_higher": round(float((pr >= th["suspicious"]).mean()), 4),
                                       "high": round(float((pr >= th["high"]).mean()), 4),
                                       "free_host_n": int(fh.sum()),
                                       "free_host_suspicious_or_higher":
                                           round(float((pr[fh] >= th["suspicious"]).mean()), 4) if fh.any() else None}

    def uae_block(df):
        pu, pcu, _, _ = riskmodel.predict(bundle, df.domain)
        levels = [level(x, th) for x in pu]
        caught = len(levels) - levels.count("no warning signs")
        return pu, pcu, levels, {"high risk": levels.count("high risk"), "suspicious": levels.count("suspicious"),
                                 "no warning signs": levels.count("no warning signs"), "total": len(levels),
                                 "detection_rate_ci": wilson(caught, len(levels))}

    pu, pcu, levels, out["uae_fakes"] = uae_block(uae)
    out["uae_fakes"]["note"] = "development set: seen while designing the rules, so optimistic"
    out["uae_missed"] = [d for d, l in zip(uae.domain, levels) if l == "no warning signs"]
    out["score_distribution_uae"] = {"min": int(100 * pcu.min()), "median": int(100 * np.median(pcu)),
                                     "max": min(99, int(100 * pcu.max())),
                                     "at_99": int((np.round(100 * pcu) >= 99).sum())}
    if len(frozen):
        out["uae_frozen_holdout"] = uae_block(frozen)[3]

    ps, pcs, _, _ = riskmodel.predict(bundle, SANITY)
    out["sanity_examples"] = {d: f"{level(a, th)} ({min(99, int(100 * b))})" for d, a, b in zip(SANITY, ps, pcs)}
    out["combiner"] = {"kept": bundle["combiner_kind"], **bundle["combiner_scores"]}
    for k, v in out.items():
        log(f"  {k}: {v}")
    return out


def weights_table(bundle):
    rows = []
    for k in bundle["features"]:
        e = bundle["weights"][k]
        rows.append({"feature": k, "avg_effect": e["avg_effect"], "present_in": e["present_in"],
                     "odds_multiplier": round(math.exp(e["avg_effect"]), 2)})
    return rows
