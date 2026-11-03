"""
Train the DOMAIN FACTS model: how much registration age, certificate, mail setup, etc. add
on top of the name model.

    python ml\\train_facts.py                  (looks up ~1,800 + 1,800 domains: 30-50 minutes, cached)
    python ml\\train_facts.py --n 600          (smaller, faster)
    python ml\\train_facts.py --lookup-only    (only fill the cache; fit later)

Why a separate model: facts can only be looked up for sites that are ONLINE NOW, and most
domains in the big phishing lists are already gone. So phishing and legit samples are both
looked up at the same time, and only names that still resolve are used (otherwise "offline"
would be learned as "phishing").

Data. First try (Nov 2): months-old phishing that is still online is mostly hacked OLD sites,
so age looked useless - not what the live radar sees. Now:
  phishing  FRESH: domains PhishDestroy added in the last 15 days (data/sources/destroy_changes_*.json)
  legit     Tranco sites (70% ranked 250k-1M or .ae, 30% top 250k)
Only sites in the DEV part (collect_uae.part_of) and not in the base files are used: the name model
never trained on any of them, so its score is an honest input. Split by site 70/30 into
facts-train / facts-test.

Model: logistic regression on [name model log-odds, facts] -> combined probability.
Saved to ml/facts_model.joblib; scoring.assess() uses it when facts are looked up.
"""

import glob
import json
import os
import random
import sys
import time
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed

import joblib
import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from backend.app import enrich, riskmodel  # noqa: E402
from backend.app.enrich import FACT_NAMES, fact_vector  # noqa: E402
from backend.app.features import clean, owner  # noqa: E402
from collect_uae import part_of  # noqa: E402

DATA = os.path.join(ROOT, "data")
CACHE = os.path.join(DATA, "facts_cache.jsonl")
OUT = os.path.join(HERE, "facts_model.joblib")
OWNERS = os.path.join(DATA, "facts_owners.txt")
SEED = 3


def _cache():
    c = {}
    if os.path.exists(CACHE):
        with open(CACHE, encoding="utf-8") as f:
            for line in f:
                try:
                    j = json.loads(line)
                    c[j["domain"]] = j
                except Exception:
                    pass
    return c


def lookup(domains, workers=24, log=print):
    cache = _cache()
    todo = [d for d in domains if d not in cache]
    log(f"Facts: {len(domains) - len(todo):,} cached, looking up {len(todo):,} ...")
    t0 = time.time()
    with open(CACHE, "a", encoding="utf-8") as out, ThreadPoolExecutor(workers) as pool:
        futs = {pool.submit(enrich.facts, d, True): d for d in todo}
        for i, fu in enumerate(as_completed(futs), 1):
            d = futs[fu]
            try:
                fx = fu.result()
            except Exception as ex:
                fx = {"domain": d, "error": str(ex)[:100]}
            cache[d] = fx
            out.write(json.dumps(fx, default=str) + "\n")
            out.flush()
            if i % 200 == 0:
                log(f"  {i:,}/{len(todo):,} ({time.time() - t0:.0f} s)")
    return {d: cache[d] for d in domains}


def build_sample(n, seed=SEED):
    """Fresh phishing + legit, dev-part sites only, one name per site, split 70/30 by site."""
    base = set()
    for name in ("shield_training_domains.csv", "shield_test_domains.csv"):
        base |= {owner(clean(d)) for d in pd.read_csv(os.path.join(DATA, name)).domain}
    rnd = random.Random(seed)

    def pick(names, k):
        seen, out = set(), []
        names = list(names)
        rnd.shuffle(names)
        for d in names:
            d = clean(d)
            if not d or "." not in d:
                continue
            o = owner(d)
            if o not in seen and o not in base and part_of(o) == "dev":
                seen.add(o)
                out.append((d, o))
            if len(out) >= k:
                break
        return out

    fresh = []
    for f in sorted(glob.glob(os.path.join(DATA, "sources", "destroy_changes_*.json"))):
        fresh += json.load(open(f, encoding="utf-8")).get("primary_added", [])
    with zipfile.ZipFile(os.path.join(DATA, "lists", "tranco.zip")) as z:
        rows = [l.split(",", 1) for l in z.read(z.namelist()[0]).decode("utf-8", "ignore").splitlines()]
    rows = [(int(r), d) for r, d in (x for x in rows if len(x) == 2) if r.isdigit()]
    small = [d for r, d in rows if r > 250_000 or d.endswith(".ae")]
    big = [d for r, d in rows if r <= 250_000 and not d.endswith(".ae")]
    fresh_set = {clean(d) for d in fresh}
    ph = pick(fresh, n)
    lg = [x for x in pick(small, int(n * 0.7)) + pick(big, n - int(n * 0.7)) if x[0] not in fresh_set]
    df = pd.DataFrame([(d, 1, o) for d, o in ph] + [(d, 0, o) for d, o in lg],
                      columns=["domain", "is_phishing", "owner"])
    df["split"] = ["test" if zlib.crc32(("facts|" + o).encode()) % 10 < 3 else "train" for o in df.owner]
    return df


def matrix(df, facts, bundle):
    """Rows that resolve now: X = [name log-odds, facts...], y."""
    keep = [d for d in df.domain if (facts.get(d) or {}).get("dns", {}).get("resolves")]
    sub = df.set_index("domain").loc[keep].reset_index()
    _, p_bal, _, _ = riskmodel.predict(bundle, sub.domain)
    name_lg = riskmodel.logit(p_bal)
    F = np.array([[fact_vector(facts[d])[k] for k in FACT_NAMES] for d in sub.domain])
    return np.column_stack([name_lg, F]), sub.is_phishing.values, sub


def main():
    n = int(sys.argv[sys.argv.index("--n") + 1]) if "--n" in sys.argv else 1800
    df = build_sample(n)
    with open(OWNERS, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(set(df.owner))))
    print(f"Sample: {int(df.is_phishing.sum()):,} fresh phishing, {int((df.is_phishing == 0).sum()):,} legit")
    facts = lookup(list(df.domain))
    if "--lookup-only" in sys.argv:
        return

    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import roc_auc_score
    from recovery import Run
    run = Run(df, SEED)
    bundle = joblib.load(os.path.join(HERE, "domain_model.joblib"))
    tr, te = df[df.split == "train"].reset_index(drop=True), df[df.split == "test"].reset_index(drop=True)
    Xtr, ytr, _ = matrix(tr, facts, bundle)
    Xte, yte, _ = matrix(te, facts, bundle)
    print(f"Online now: train {len(ytr):,} ({ytr.sum():,} phishing), test {len(yte):,} ({yte.sum():,} phishing)")
    clf = run.stage('facts_classifier', lambda: LogisticRegression(C=1.0, max_iter=2000, class_weight="balanced").fit(Xtr, ytr))
    p_comb = clf.predict_proba(Xte)[:, 1]
    p_name = riskmodel.sigmoid(Xte[:, 0])

    def at_fpr(p, y, fpr):
        th = np.quantile(p[y == 0], 1 - fpr)
        return float((p[y == 1] >= th).mean())
    res = {"test_rows": int(len(yte)), "test_phishing": int(yte.sum()),
           "phishing": "fresh (reported in the last 15 days)",
           "auc_name_only": round(float(roc_auc_score(yte, p_name)), 4),
           "auc_name_plus_facts": round(float(roc_auc_score(yte, p_comb)), 4)}
    for fpr in (0.03, 0.005):
        res[f"recall_at_{fpr:.1%}_false_alarms"] = {"name_only": round(at_fpr(p_name, yte, fpr), 3),
                                                     "name_plus_facts": round(at_fpr(p_comb, yte, fpr), 3)}
    names = ["name_model"] + FACT_NAMES
    res["weights"] = {k: round(float(w), 3) for k, w in zip(names, clf.coef_[0])}
    res["odds_multiplier"] = {k: round(float(np.exp(w)), 2) for k, w in zip(names, clf.coef_[0])}
    # cut-offs on the combined probability: same false-alarm budget as the name model (3% / 0.5%)
    p_tr = clf.predict_proba(Xtr)[:, 1]
    th = {"suspicious": float(np.quantile(p_tr[ytr == 0], 0.97)), "high": float(np.quantile(p_tr[ytr == 0], 0.995))}
    facts_bundle = {"version": 1, "names": names, "clf": clf, "thresholds": th, "results": res,
                    "trained_at": time.strftime("%Y-%m-%d %H:%M"), "train_rows": int(len(ytr))}
    run.stage('facts_bundle', lambda: facts_bundle)
    if not os.path.exists(OUT):
        tmp = OUT + '.tmp'
        joblib.dump(facts_bundle, tmp)
        check = joblib.load(tmp)
        np.testing.assert_allclose(clf.predict_proba(Xte), check['clf'].predict_proba(Xte), rtol=0, atol=0)
        os.replace(tmp, OUT)
    with open(os.path.join(HERE, "facts_report.json"), "w") as f:
        json.dump(res, f, indent=1)
    print(json.dumps(res, indent=1))


if __name__ == "__main__":
    main()
