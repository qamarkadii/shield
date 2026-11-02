"""
Score the model on data it has NEVER seen (built by ml/collect_uae.py and ml/build_unseen.py).

    python ml\\eval_unseen.py                 report (+ errors of the DEV parts) -> ml/unseen_report.json
    python ml\\eval_unseen.py --errors 40     also print 40 example mistakes of each kind (dev only)

DEV parts: numbers AND the mistakes are shown, so the logic can be fixed.
FROZEN parts: only totals, never the domains. Looking at them would make them a dev set.

"Full app" = what Shield shows: the learned score plus the labelled UAE-impersonation rule.
"""

import json
import os
import sys
from collections import Counter, defaultdict

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.environ.get("SHIELD_CODE_ROOT") or os.path.dirname(HERE)     # lets an old version be scored
DATA = os.path.join(os.path.dirname(HERE), "data")
sys.path.insert(0, ROOT)

import joblib  # noqa: E402

from backend.app import riskmodel  # noqa: E402
from backend.app.registry import UAE_BRANDS  # noqa: E402

IMPERSONATION = ("brand_typosquat", "brand_with_lure", "brand_in_subdomain", "brand_homoglyph")


def load_bundle(path=None):
    return joblib.load(path or os.path.join(ROOT, "ml", "domain_model.joblib"))


def score(bundle, domains, chunk=20_000):
    """Returns DataFrame(domain, p_raw, level_model, rule, level_app, brand)."""
    out = []
    domains = list(domains)
    th = bundle["raw_thresholds"]
    for i in range(0, len(domains), chunk):
        part = domains[i:i + chunk]
        p, _, X, infos = riskmodel.predict(bundle, part)
        for d, pr, info in zip(part, p, infos):
            f, b = info["features"], info["brand"]
            uae = bool(b) and "(global brand)" not in b and not info["official"]
            rule = bool((uae and (any(f[k] for k in IMPERSONATION) or f["fake_country_label"]))
                        or f["fake_country_label"])
            lvl = 2 if pr >= th["high"] else 1 if pr >= th["suspicious"] else 0
            if info["official"] and uae:
                lvl = 0
            app = max(lvl, 1) if rule and not info["official"] else lvl
            out.append((d, float(pr), lvl, rule, app, b or "", bool(info["official"])))
    return pd.DataFrame(out, columns=["domain", "p_raw", "level_model", "rule", "level_app", "brand", "official"])


def rates(df, y):
    """Detection (phishing) or false-alarm (legit) rates at both levels, model alone and full app."""
    n = len(df)
    if n == 0:
        return {"n": 0}
    r = {"n": int(n)}
    for col, name in (("level_model", "model"), ("level_app", "app")):
        r[f"{name}_suspicious_or_higher"] = round(float((df[col] >= 1).mean()), 4)
        r[f"{name}_high"] = round(float((df[col] >= 2).mean()), 4)
    if y == 1:
        r["kind"] = "detection rate (higher is better)"
    else:
        r["kind"] = "false-alarm rate (lower is better)"
    return r


def by_group(df, y, col):
    return {str(k): rates(g, y) for k, g in df.groupby(col)}


def evaluate(bundle, show_errors=0, log=print):
    rep = {}
    for part in ("dev", "frozen"):
        u = pd.read_csv(os.path.join(DATA, f"unseen_{part}.csv"))
        s = score(bundle, u.domain).assign(is_phishing=u.is_phishing.values, source=u.source.values)
        ph, lg = s[s.is_phishing == 1], s[s.is_phishing == 0]
        r = {"phishing": rates(ph, 1), "legit": rates(lg, 0),
             "phishing_by_source": by_group(ph, 1, "source"), "legit_by_source": by_group(lg, 0, "source")}
        try:
            from sklearn.metrics import roc_auc_score
            r["auc"] = round(float(roc_auc_score(s.is_phishing, s.p_raw)), 4)
        except Exception:
            pass
        rep[f"unseen_{part}"] = r
        if part == "dev" and show_errors:
            rnd = np.random.default_rng(0)
            miss = ph[ph.level_app == 0]
            fa = lg[lg.level_app >= 1]
            fa_ae = lg[(lg.level_app >= 1) & (lg.source == "tranco_ae")]
            for title, d in (("MISSED phishing (dev)", miss), ("FALSE ALARMS on legit (dev)", fa),
                             ("FALSE ALARMS on legit .ae sites (dev)", fa_ae)):
                k = min(show_errors, len(d))
                log(f"\n--- {title}: {len(d):,}; {k} examples")
                for _, row in d.iloc[rnd.permutation(len(d))[:k]].iterrows():
                    log(f"   {row.domain:60s} p={row.p_raw:.3f} lvl={row.level_app} rule={int(row.rule)} {row.brand}")
    for part, path in (("dev", "uae_phishing_collected.csv"), ("frozen", "uae_test_frozen.csv")):
        u = pd.read_csv(os.path.join(DATA, path)).fillna("")
        if part == "dev":
            u = u[u.part == "dev"]
        u = u[u.category != "uae_plain"]          # plain business names: see collect_uae.py
        s = score(bundle, u.domain).assign(category=u.category.values)
        r = {"all": rates(s, 1), "by_category": by_group(s, 1, "category")}
        rep[f"uae_{part}"] = r
        if part == "dev" and show_errors:
            miss = s[s.level_app == 0]
            log(f"\n--- MISSED UAE phishing (dev): {len(miss):,} of {len(s):,}")
            for _, row in miss.iterrows():
                log(f"   {row.domain:60s} p={row.p_raw:.3f} {row.category} {row.brand}")
    return rep


def main():
    show = int(sys.argv[sys.argv.index("--errors") + 1]) if "--errors" in sys.argv else 0
    bundle = load_bundle(os.environ.get("SHIELD_BUNDLE"))
    rep = evaluate(bundle, show)
    out = os.environ.get("SHIELD_REPORT_OUT") or os.path.join(HERE, "unseen_report.json")
    with open(out, "w") as f:
        json.dump(rep, f, indent=1)
    def line(name, r):
        return (f"{name:34s} n={r['n']:6,}  model S+/H {r['model_suspicious_or_higher']:.1%} / {r['model_high']:.1%}"
                f"   app S+/H {r['app_suspicious_or_higher']:.1%} / {r['app_high']:.1%}")
    print()
    for part in ("dev", "frozen"):
        r = rep[f"unseen_{part}"]
        print(f"== unseen {part}  AUC {r.get('auc')}")
        print(line("  phishing caught", r["phishing"]))
        print(line("  legit flagged", r["legit"]))
        for k, v in r["phishing_by_source"].items():
            print(line(f"    phishing from {k}", v))
        for k, v in r["legit_by_source"].items():
            print(line(f"    legit from {k}", v))
        u = rep[f"uae_{part}"]
        print(line(f"  UAE phishing caught ({part})", u["all"]))
        for k, v in u["by_category"].items():
            print(line(f"    UAE {k}", v))
    print("\nSaved", out)


if __name__ == "__main__":
    main()
