"""
Train Shield's risk model and write an honest evaluation report.

Run from the repo folder (with .venv active):
    python ml\\train_baseline.py

Creates:
    ml/domain_model.joblib   the model used by the app
    ml/model_report.json     all evaluation numbers
    docs/model_card.md       readable summary (data, method, results, limits)

How the score is calculated: see ml/model.py.
"""

import json
import os
import sys

import joblib
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from model import DATA, MODEL_PATH, ROOT, build, evaluate, weights_table  # noqa: E402

DESCRIPTIONS = {
    "ml_logit": "Text model score (character patterns), per unit of log-odds",
    "brand_typosquat": "Registered name is the brand re-spelled (emirates-post.org)",
    "brand_with_lure": "Brand + lure word on a domain the brand doesn't own (salik-pay)",
    "brand_in_subdomain": "Brand placed in front of an unrelated domain (aramex.valeriair.com)",
    "brand_homoglyph": "Brand written with look-alike characters (sa1ik)",
    "brand_other_mention": "Brand name with other words, no lure (could be a partner/fan site)",
    "fake_country_label": "'.ae' / 'gov' inside a foreign domain",
    "risky_tld": "Ending often abused (.xyz, .top, .live ...)",
    "free_host": "Free hosting / site-builder",
    "many_hyphens": "3+ hyphens",
    "lure_word": "Lure word (login, pay, verify ...)",
    "deep_subdomain": "3+ subdomain levels",
    "digits_in_name": "3+ digits in the name",
}


def write_model_card(bundle, results, path):
    w = weights_table(bundle)
    lines = [
        "# Shield risk model — model card",
        "",
        f"Trained {bundle['trained_at']} on {bundle['train_rows']:,} labelled domains "
        f"({bundle['seconds']} s). Generated automatically by `ml/train_baseline.py`.",
        "",
        "## Data",
        "",
        "- Training: `data/shield_training_domains.csv` (PhiUSIIL 2024, CC BY 4.0; Phishing.Database, MIT; top-10k domains list). 50/50 phishing/legitimate.",
        "- Test: `data/shield_test_domains.csv`, 10,000 domains with no overlap with training; phishing side from a different source.",
        "- UAE check: `data/uae_phishing_domains_real.csv`, 66 real phishing domains imitating UAE brands; never used for training.",
        "",
        "## Method",
        "",
        "1. **Text model** (70% of training data): character 2–5-grams + logistic regression.",
        "2. **Risk combiner** (separate 18%): logistic regression over warning-sign features; **weights are learned, not hand-set**.",
        "3. **Thresholds** (separate 12%): *Suspicious* and *High risk* cut-offs chosen so only 3% / 0.5% of legitimate domains reach them.",
        "",
        "Score = 100 × combiner probability. The probability assumes equal numbers of phishing and legitimate domains; in reality phishing is far rarer, so the **level** is the decision, the number is for ranking.",
        "",
        "## Learned weights",
        "",
        "| Warning sign | Weight (log-odds) | Multiplies phishing odds by |",
        "|---|---|---|",
    ]
    for r in w:
        mult = "per unit" if r["odds_multiplier"] is None else f"{r['odds_multiplier']}×"
        lines.append(f"| {DESCRIPTIONS.get(r['feature'], r['feature'])} | {r['weight']} | {mult} |")
    s, h = results["at_suspicious"], results["at_high"]
    lines += [
        "",
        "## Results (test set never used in training)",
        "",
        f"AUC: **{results['auc']}**",
        "",
        "| Level | Precision | Recall | F1 | False-positive rate |",
        "|---|---|---|---|---|",
        f"| Suspicious or higher | {s['precision']} | {s['recall']} | {s['f1']} | {s['false_positive_rate']:.2%} |",
        f"| High risk | {h['precision']} | {h['recall']} | {h['f1']} | {h['false_positive_rate']:.2%} |",
        "",
        f"Confusion at Suspicious: TP {s['confusion']['tp']}, FP {s['confusion']['fp']}, TN {s['confusion']['tn']}, FN {s['confusion']['fn']}.",
        "",
        f"Legitimate domains written as real hostnames (mail.company.com): "
        f"{results['legit_hostnames_flagged_suspicious_or_higher']:.2%} flagged Suspicious or higher, "
        f"{results['legit_hostnames_flagged_high']:.2%} High risk.",
        "",
        f"66 real UAE fakes, **model alone**: {results['uae_fakes']['high risk']} High risk, {results['uae_fakes']['suspicious']} Suspicious, "
        f"{results['uae_fakes']['no warning signs']} missed ({', '.join(results['uae_missed']) or 'none'}).",
        "",
        "**Full app (model + labelled UAE-impersonation rules)** — what the dashboard shows: "
        + (f"{results['with_rules']['uae_fakes']['high risk']} High risk, {results['with_rules']['uae_fakes']['suspicious']} Suspicious, "
           f"{results['with_rules']['uae_fakes']['missed']} missed; legitimate test domains flagged {results['with_rules']['legit_test_flagged']:.2%}, "
           f"legitimate hostnames flagged {results['with_rules']['legit_hostnames_flagged']:.2%}." if results.get("with_rules") else "n/a"),
        "",
        "The rules never change the score. They send any domain imitating a *registered UAE brand* to analyst review, because "
        "public phishing data has too few such examples to learn their weight (e.g. re-spelled brand names: 1 in 20,000 training domains).",
        "",
        "## Limits",
        "",
        "- Looks at the domain name only. A fake with an innocent-looking name and no brand in it can be missed.",
        "- Brand-pattern weights are learned mostly from global brands (PayPal, Microsoft, DHL...), which dominate public phishing data, and applied to UAE brands.",
        "- Labels come from public lists, which contain some errors.",
        "- Not yet evaluated on a live UAE pilot; real-world precision is unknown until then.",
    ]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def system_check(log=print):
    """The full app (learned score + labelled UAE-impersonation rules), as the dashboard uses it."""
    import random
    from collections import Counter
    sys.path.insert(0, ROOT)
    from backend.app import scoring
    from common import COMMON_SUBDOMAINS
    scoring.reload_model()
    test = pd.read_csv(os.path.join(DATA, "shield_test_domains.csv"))
    uae = pd.read_csv(os.path.join(DATA, "uae_phishing_domains_real.csv"))
    rnd = random.Random(11)
    flagged = ("suspicious", "high risk")
    v = lambda ds: Counter(scoring.score_domain(d)["verdict"] for d in ds)
    leg = test[test.is_phishing == 0].domain.tolist()
    u, l, h = v(uae.domain), v(leg), v(f"{rnd.choice(COMMON_SUBDOMAINS)}.{d}" for d in leg)
    out = {"uae_fakes": {"high risk": u["high risk"], "suspicious": u["suspicious"],
                         "missed": len(uae) - u["high risk"] - u["suspicious"], "total": len(uae)},
           "legit_test_flagged": round(sum(l[k] for k in flagged) / len(leg), 4),
           "legit_hostnames_flagged": round(sum(h[k] for k in flagged) / len(leg), 4)}
    log(f"  with rules (full app): {out}")
    return out


def main(extra=None, log=print, drop_from_base=None):
    train = pd.read_csv(os.path.join(DATA, "shield_training_domains.csv"))
    if drop_from_base:
        train = train[~train.domain.isin(drop_from_base)]       # analyst labels replace old ones
    if extra is not None and len(extra):
        train = pd.concat([train, extra], ignore_index=True)
    bundle = build(train, log=log)
    log("Evaluating on held-out data ...")
    results = evaluate(bundle, log=log)
    bundle["results"] = results
    tmp = MODEL_PATH + ".tmp"
    joblib.dump(bundle, tmp)
    os.replace(tmp, MODEL_PATH)
    with open(os.path.join(HERE, "model_report.json"), "w", encoding="utf-8") as f:
        json.dump({"weights": weights_table(bundle), "thresholds": bundle["thresholds"],
                   "results": results, "trained_at": bundle["trained_at"]}, f, indent=2)
    results["with_rules"] = system_check(log)
    bundle["results"] = results
    joblib.dump(bundle, tmp)
    os.replace(tmp, MODEL_PATH)
    with open(os.path.join(HERE, "model_report.json"), "w", encoding="utf-8") as f:
        json.dump({"weights": weights_table(bundle), "thresholds": bundle["thresholds"],
                   "results": results, "trained_at": bundle["trained_at"]}, f, indent=2)
    write_model_card(bundle, results, os.path.join(ROOT, "docs", "model_card.md"))
    log(f"Saved model -> {MODEL_PATH}")
    log("Report -> ml/model_report.json and docs/model_card.md")
    return bundle


if __name__ == "__main__":
    main()
