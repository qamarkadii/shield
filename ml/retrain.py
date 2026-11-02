"""
Retrain the risk model with LIVE data.

Live certificate domains have no labels (nobody has said yet whether they're phishing),
so the model can't learn from them directly. Training on its own guesses would just
repeat its mistakes. Instead Shield learns from live data in three honest ways:

1. Fresh phishing feeds (OpenPhish + Phishing.Database), downloaded at retrain time,
   so the model keeps up with the newest scam patterns.
2. Analyst decisions: every "Confirm" / "Legit" click in the dashboard is a real label.
   If it disagrees with an older label for the same domain, the analyst wins.
   Analyst labels count x25 (ANALYST_WEIGHT): a handful of real decisions would
   otherwise vanish among 276k public rows.
3. Matching NEW legitimate sites (Tranco top sites not yet in the data), as many as the
   fresh phishing domains, so retraining doesn't tilt the model toward "phishing".

Every third analyst-confirmed UAE-brand fake is put in data/uae_holdout_frozen.csv instead
of training: a growing UAE test set nobody tuned rules on.

Training and evaluation are exactly the same as ml/train_baseline.py. The test set, the
66 real UAE fakes and the frozen holdout are never used for training (whole owners are
removed), so the numbers shown after retraining stay honest.

Run by hand:  python ml\\retrain.py      (or the Retrain button on the dashboard)
"""

import os
import random
import sys

import pandas as pd
import requests

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
FEEDS = os.path.join(DATA, "feeds")
FROZEN_UAE = os.path.join(DATA, "uae_holdout_frozen.csv")
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

FEED_URLS = {
    "openphish.txt": "https://openphish.com/feed.txt",
    "phishing_database_active.txt":
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
}


def _norm(d: str) -> str:
    d = d.strip().lower()
    if "://" in d:
        d = d.split("://", 1)[1]
    d = d.split("/")[0].split(":")[0].rstrip(".")
    return d[4:] if d.startswith("www.") else d


def download_feeds() -> dict:
    os.makedirs(FEEDS, exist_ok=True)
    out = {}
    for name, url in FEED_URLS.items():
        try:
            r = requests.get(url, timeout=120, headers={"User-Agent": "Shield-hackathon"})
            r.raise_for_status()
            with open(os.path.join(FEEDS, name), "wb") as f:
                f.write(r.content)
            out[name] = "ok"
        except Exception as ex:
            out[nadef _freeze_uae(lab: pd.DataFrame, log=print) -> pd.DataFrame:
    """Move every third confirmed UAE-brand fake (by a stable hash) to the frozen holdout."""
    import zlib
    from backend.app.scoring import mentions_brand
    pick = lab[(lab.is_phishing == 1) & lab.domain.map(mentions_brand)
               & lab.domain.map(lambda d: zlib.crc32(d.encode()) % 3 == 0)]
    if len(pick):
        old = pd.read_csv(FROZEN_UAE) if os.path.exists(FROZEN_UAE) else pd.DataFrame(columns=["domain"])
        new = pd.concat([old[["domain"]], pick[["domain"]]]).drop_duplicates("domain")
        new.to_csv(FROZEN_UAE, index=False)
        log(f"Frozen UAE holdout: {len(new)} domains ({len(new) - len(old)} new); not used for training")
    return lab[~lab.domain.isin(pick.domain)]


def retrain(labels=None, fetch=True, feed_sample=30000, log=print) -> dict:
    """labels: list of {"domain", "is_phishing"} from the analyst. Returns a metrics summary."""
    from backend.app.features import clean, private_owner
    from backend.app.popularity import load_ranks
    from model import ANALYST_WEIGHT, load_eval_sets
    from train_baseline import main as train_main

    feed_status = download_feeds() if fetch else {}
    log(f"Feeds: {feed_status or 'skipped'}")
    base = pd.read_csv(os.path.join(DATA, "shield_training_domains.csv"))
    base_set = set(base.domain)
    test, uae, frozen = load_eval_sets()
    held = set(test.domain) | set(uae.domain) | set(frozen.domain)
    held_owners = {private_owner(d) for d in held}      # build() also removes whole owners
    rnd = random.Random(7)

    feed = _read_feed_domains()
    fresh = sorted(d for d in feed - base_set if d not in held and private_owner(d) not in held_owners)
    fresh = rnd.sample(fresh, min(feed_sample, len(fresh)))

    # matching NEW legitimate rows (not copies of base rows, which would be dropped as duplicates)
    feed_owners = {private_owner(d) for d in feed}
    pool = sorted(d for d in load_ranks() if d not in base_set and d not in feed_owners and d not in held_owners)
    legit_new = rnd.sample(pool, min(len(fresh), len(pool)))
    legit_w = min(5.0, len(fresh) / len(legit_new)) if legit_new else 1.0
    if len(legit_new) < len(fresh):
        log(f"Only {len(legit_new)} new legitimate sites available; weighting them x{legit_w:.1f} to stay balanced")
    extra = pd.concat([pd.DataFrame({"domain": fresh, "is_phishing": 1, "weight": 1.0, "source": "feed"}),
                       pd.DataFrame({"domain": legit_new, "is_phishing": 0, "weight": legit_w, "source": "feed_legit"})],
                      ignore_index=True)

    lab = pd.DataFrame(columns=["domain", "is_phishing"])
    if labels:
        lab = pd.DataFrame(labels)[["domain", "is_phishing"]]
        lab["domain"] = lab.domain.map(clean)
        lab = lab[~lab.domain.isin(held)].drop_duplicates("domain", keep="last")
        lab = _freeze_uae(lab, log)
        overrides = int(base.domain.isin(lab.domain).sum())
        if overrides:
            log(f"Analyst overrides {overrides} existing labels")
        extra = extra[~extra.domain.isin(lab.domain)]
        extra = pd.concat([lab.assign(weight=ANALYST_WEIGHT, source="analyst"), extra], ignore_index=True)
    n_labels = len(lab)
    log(f"Adding {len(fresh)} fresh feed domains, {len(legit_new)} new legitimate sites and "
        f"{n_labels} analyst labels (x{ANALYST_WEIGHT:.0f}) ...")

    bundle = train_main(extra=extra, log=log, drop_from_base=set(lab.domain) if n_labels else None)
    r = bundle["results"]
    return {"auc": r["auc"], "precision_suspicious": r["at_suspicious"]["precision"],
            "recall_suspicious": r["at_suspicious"]["recall"],
            "fpr_high": r["at_high"]["false_positive_rate"], "uae_fakes": r["uae_fakes"],
            "fresh_feed_domains": len(fresh), "new_legit_sites": len(legit_new), "analyst_labels": n_labels,
            "trained_at": bundle["trained_at"], "seconds": bundle["seconds"]}


_labels else None)
    r = bundle["results"]
    return {"auc": r["auc"], "precision_suspicious": r["at_suspicious"]["precision"],
            "recall_suspicious": r["at_suspicious"]["recall"],
            "fpr_high": r["at_high"]["false_positive_rate"], "uae_fakes": r["uae_fakes"],
            "fresh_feed_domains": len(fresh), "analyst_labels": n_labels,
            "trained_at": bundle["trained_at"], "seconds": bundle["seconds"]}


if __name__ == "__main__":
    labels = []
    try:
        from backend.app import db
        labels = db.all_labels()
    except Exception:
        pass
    retrain(labels=labels)
