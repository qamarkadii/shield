"""
Train Shield's risk model and write an honest evaluation report.

Run from the repo folder (with .venv active):
    python backend\\scripts\\download_data.py   (once: top-sites lists for popularity + real hostnames)
    python ml\\train_baseline.py

Creates:
    ml/domain_model.joblib   the model used by the app
    ml/model_report.json     all evaluation numbers
    docs/model_card.md       readable summary (data, method, results, limits)

How the score is calculated: see ml/model.py.
"""

import json
import os
import random
import sys
from collections import Counter

import joblib
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from model import (DATA, LIVE_PREVALENCE, MODEL_PATH, ROOT, build, evaluate,  # noqa: E402
                   load_eval_sets, weights_table)

DESCRIPTIONS = {
    "ml_logit": "Text model score (character patterns), log-odds",
    "brand_typosquat": "Registered name is the brand re-spelled (emirates-post.org)",
    "brand_with_lure": "Brand + lure word on a domain the brand doesn't own (salik-pay)",
    "brand_in_subdomain": "Brand placed in front of an unrelated domain (aramex.valeriair.com)",
    "brand_homoglyph": "Brand written with look-alike characters (sa1ik, Cyrillic letters)",
    "brand_other_mention": "Brand name with other words, no lure (could be a partner/fan site)",
    "fake_country_label": "'.ae' / 'gov' inside a foreign domain",
    "tld_risk": "Learned risk of the ending (.xyz, .top ...)",
    "free_host": "Free hosting / site-builder",
    "many_hyphens": "3+ hyphens",
    "lure_word": "Lure word (login, pay, verify ...)",
    "deep_subdomain": "3+ subdomain levels",
    "digits_in_name": "3+ digits in the name",
    "punycode": "Non-Latin letters (xn--)",
    "name_entropy": "Random-looking letters (entropy)",
    "host_length": "Name length",
    "consonant_run": "Long consonant run",
    "popularity": "Owner is a popular site (Tranco rank)",
}
PCT = f"precision_at_{LIVE_PREVALENCE:.0%}_phishing"


def _pct(v):
    return "n/a" if v is None else f"{v:.2%}"


def write_model_card(bundle, results, path):
    w = weights_table(bundle)
    ds = bundle["data_summary"]
    s, h = results["at_suspicious"], results["at_high"]
    rl = results.get("real_legit_hostnames") or {}
    lp = results["legit_not_popular_flagged"]
    u = results["uae_fakes"]
    lines = [
        "# Shield risk model — model card",
        "",
        f"Trained {bundle['trained_at']} on {bundle['train_rows']:,} rows ({bundle['seconds']} s). "
        "Generated automatically by `ml/train_baseline.py`.",
        "",
        "## Data",
        "",
        f"- Base: `data/shield_training_domains.csv` (PhiUSIIL 2024, CC BY 4.0; Phishing.Database, MIT; top-10k list): {ds['base_rows']:,} rows used.",
        f"- **Real legitimate hostnames** (Cisco Umbrella top-1M under Tranco top-100k sites, plus popular hosting tenants): {ds['real_hostnames']:,}.",
        f"- **Synthetic UAE impersonations** (`ml/synth_uae.py`, training only, never evaluated on): {ds['synthetic_uae']:,}.",
        f"- Analyst labels (weight ×25): {ds['analyst']:,}. Fresh feed domains: {ds['fresh_feed']:,}.",
        f"- **Leakage removed:** {ds['purged_for_leakage']:,} training rows whose *owner* (registered domain, or tenant on one of "
        f"{ds['platforms']} detected hosting platforms) appears in an evaluation set. All splits keep each owner on one side.",
        "- Test: `data/shield_test_domains.csv` (10,000, 50/50). UAE: `data/uae_phishing_domains_real.csv` (66 real fakes).",
        "",
        "## Method",
        "",
        f"1. **Text model**: character 2–5-grams + logistic regression, C={bundle['text_C']} (tuned on a grouped split). "
        "5-fold out-of-fold scores (folds by owner) feed the combiner; the final text model uses all rows.",
        "2. **Ending risk**: learned, smoothed phishing log-odds per ending (out-of-fold too).",
        f"3. **Combiner**: `{bundle['combiner_kind']}` (kept for lower held-out log-loss; scores: "
        + "; ".join(f"{k} {v}" for k, v in bundle["combiner_scores"].items())
        + "). Gradient boosting uses monotonic constraints: brand/hosting signs can only raise risk, popularity only lower it.",
        f"4. **Held-out slice** ({ds['heldout_rows']:,} real rows, separate owners): *Suspicious* / *High risk* cut-offs at 3% / 0.5% "
        "false alarms on its legitimate domains, and Platt calibration of the score.",
        "",
        f"**Score** = 100 × calibrated probability if half of all domains were phishing (for ranking). **live_probability** = the same "
        f"at the expected live rate ({LIVE_PREVALENCE:.0%}). The **level** is the decision.",
        "",
        "## Learned effects",
        "",
        "Average effect on the log-odds on held-out rows where the sign is present (model with vs. without it).",
        "",
        "| Warning sign | Present in | Avg effect (log-odds) | Odds × |",
        "|---|---|---|---|",
    ]
    for r in w:
        lines.append(f"| {DESCRIPTIONS.get(r['feature'], r['feature'])} | {r['present_in']:.1%} | {r['avg_effect']} | {r['odds_multiplier']}× |")
    lines += [
        "",
        "## Results (never used in training, thresholds or calibration)",
        "",
        f"AUC: **{results['auc']}** · Brier score (calibration): {results['calibration_brier']}",
        "",
        f"| Level | Precision (50/50 test) | **Precision at {LIVE_PREVALENCE:.0%} phishing** | Recall [95% CI] | F1 | False-positive rate [95% CI] |",
        "|---|---|---|---|---|---|",
        f"| Suspicious or higher | {s['precision']} | **{s[PCT]}** | {s['recall']} {s['recall_ci']} | {s['f1']} | {s['false_positive_rate']:.2%} {s['fpr_ci']} |",
        f"| High risk | {h['precision']} | **{h[PCT]}** | {h['recall']} {h['recall_ci']} | {h['f1']} | {h['false_positive_rate']:.2%} {h['fpr_ci']} |",
        "",
        f"Confusion at Suspicious: TP {s['confusion']['tp']}, FP {s['confusion']['fp']}, TN {s['confusion']['tn']}, FN {s['confusion']['fn']}.",
        "",
        "False alarms on legitimate names (Suspicious or higher / High risk):",
        "",
        f"- Legit test domains that are **not** popular sites ({lp['n']:,}): {_pct(lp['suspicious_or_higher'])} / {_pct(lp['high'])}",
        f"- Legit test domains written as hostnames with **unseen** subdomains (careers., console. ...): "
        f"{_pct(results['legit_hostnames_flagged_suspicious_or_higher'])} / {_pct(results['legit_hostnames_flagged_high'])}",
        f"- **Real** legitimate hostnames of owners never trained on ({rl.get('n', 0):,}): "
        f"{_pct(rl.get('suspicious_or_higher'))} / {_pct(rl.get('high'))}; of which on hosting platforms ({rl.get('free_host_n', 0)}): "
        f"{_pct(rl.get('free_host_suspicious_or_higher'))}",
        "",
        f"66 real UAE fakes, **model alone**: {u['high risk']} High risk, {u['suspicious']} Suspicious, {u['no warning signs']} missed "
        f"(detection 95% CI {u['detection_rate_ci']}; missed: {', '.join(results['uae_missed']) or 'none'}). "
        "*Development set: these were looked at while designing the rules, so this is optimistic.*",
        "",
        "**Full app (model + labelled UAE-impersonation rules)**: "
        + (f"{results['with_rules']['uae_fakes']['high risk']} High risk, {results['with_rules']['uae_fakes']['suspicious']} Suspicious, "
           f"{results['with_rules']['uae_fakes']['missed']} missed; legit test flagged {results['with_rules']['legit_test_flagged']:.2%}, "
           f"legit hostnames flagged {results['with_rules']['legit_hostnames_flagged']:.2%}." if results.get("with_rules") else "n/a"),
        "",
    ]
    if results.get("uae_frozen_holdout"):
        f = results["uae_frozen_holdout"]
        lines += [f"**Frozen UAE holdout** (analyst-confirmed, never trained on or used for rules): {f['high risk']} High, "
                  f"{f['suspicious']} Suspicious, {f['no warning signs']} missed of {f['total']} (CI {f['detection_rate_ci']}).", ""]
    lines += ["Sanity examples: " + "; ".join(f"`{d}` {v}" for d, v in results["sanity_examples"].items()), "",
              "## Limits",
              "",
              "- Looks at the domain name only (plus popularity). A fake with an innocent-looking name and no brand can be missed.",
              "- Domain age, certificate issuer, DNS and page content are not used yet: the public training lists don't have them.",
              "- Popularity helps a lot but is partly an artefact of how the legit set was built (top-sites list); see the 'not popular' row.",
              f"- Precision at {LIVE_PREVALENCE:.0%} is an estimate from test recall and false-alarm rate; the real live rate is unknown.",
              "- Labels come from public lists, which contain some errors; synthetic UAE fakes follow known patterns only.",
              "- Not yet evaluated on a live UAE pilot."]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def system_check(log=print):
    """The full app (learned score + labelled UAE-impersonation rules), as the dashboard uses it."""
    sys.path.insert(0, ROOT)
    from backend.app import scoring
    from common import EVAL_SUBDOMAINS
    scoring.reload_model()
    test, uae, _ = load_eval_sets()
    rnd = random.Random(11)
    flagged = ("suspicious", "high risk")
    v = lambda ds: Counter(scoring.score_domain(d)["verdict"] for d in ds)
    leg = test[test.is_phishing == 0].domain.tolist()
    u, l, h = v(uae.domain), v(leg), v(f"{rnd.choice(EVAL_SUBDOMAINS)}.{d}" for d in leg)
    out = {"uae_fakes": {"high risk": u["high risk"], "suspicious": u["suspicious"],
                         "missed": len(uae) - u["high risk"] - u["suspicious"], "total": len(uae)},
           "legit_test_flagged": round(sum(l[k] for k in flagged) / len(leg), 4),
           "legit_hostnames_flagged": round(sum(h[k] for k in flagged) / len(leg), 4)}
    log(f"  with rules (full app): {out}")
    return out


def _save(bundle, results):
    bundle["results"] = results
    tmp = MODEL_PATH + ".tmp"
    joblib.dump(bundle, tmp)
    os.replace(tmp, MODEL_PATH)
    with open(os.path.join(HERE, "model_report.json"), "w", encoding="utf-8") as f:
        json.dump({"weights": weights_table(bundle), "thresholds": bundle["thresholds"],
                   "raw_thresholds": bundle["raw_thresholds"], "calibration": bundle["calib"],
                   "data": bundle["data_summary"], "results": results, "trained_at": bundle["trained_at"]},
                  f, indent=2)


def main(extra=None, log=print, drop_from_base=None):
    """extra: optional DataFrame(domain, is_phishing[, weight, source]) added to the base data.
    drop_from_base: domains whose base label is replaced (analyst labels win)."""
    train = pd.read_csv(os.path.join(DATA, "shield_training_domains.csv"))
    train["source"], train["weight"] = "base", 1.0
    if drop_from_base:
        train = train[~train.domain.isin(drop_from_base)]
    if extra is not None and len(extra):
        # extra rows go first so that, on duplicates, analyst/feed labels win
        train = pd.concat([extra, train], ignore_index=True)
    bundle = build(train, log=log)
    log("Evaluating on held-out data ...")
    results = evaluate(bundle, log=log)
    _save(bundle, results)
    results["with_rules"] = system_check(log)
    _save(bundle, results)
    write_model_card(bundle, results, os.path.join(ROOT, "docs", "model_card.md"))
    log(f"Saved model -> {MODEL_PATH}")
    log("Report -> ml/model_report.json and docs/model_card.md")
    return bundle


if __name__ == "__main__":
    main()
