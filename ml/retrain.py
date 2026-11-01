"""
Retrain the risk model with LIVE data.

Live certificate domains have no labels (nobody has said yet whether they're phishing),
so the model can't learn from them directly. Training on its own guesses would just
repeat its mistakes. Instead Shield learns from live data in two honest ways:

1. Fresh phishing feeds (OpenPhish + Phishing.Database), downloaded at retrain time,
   so the model keeps up with the newest scam patterns.
2. Analyst decisions: every "Confirm" / "Legit" click in the dashboard is a real label.
   If it disagrees with an older label for the same domain, the analyst wins.

Training and evaluation are exactly the same as ml/train_baseline.py (two-stage model,
learned weights, data-set thresholds). The test set and the 66 real UAE fakes are never
used for training, so the numbers shown after retraining stay honest.

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
            out[name] = f"failed: {ex}"
    return out


def _read_feed_domains() -> set:
    found = set()
    if not os.path.isdir(FEEDS):
        return found
    for name in os.listdir(FEEDS):
        with open(os.path.join(FEEDS, name), encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    found.add(_norm(line))
    found.discard("")
    return found


def retrain(labels=None, fetch=True, feed_sample=30000, log=print) -> dict:
    """labels: list of {"domain", "is_phishing"} from the analyst. Returns a metrics summary."""
    from train_baseline import main as train_main

    feed_status = download_feeds() if fetch else {}
    log(f"Feeds: {feed_status or 'skipped'}")
    base = pd.read_csv(os.path.join(DATA, "shield_training_domains.csv"))
    test = pd.read_csv(os.path.join(DATA, "shield_test_domains.csv"))
    uae = pd.read_csv(os.path.join(DATA, "uae_phishing_domains_real.csv"))
    held_out = set(test.domain) | set(uae.domain)

    fresh = sorted(_read_feed_domains() - held_out - set(base.domain))
    random.seed(7)
    fresh = random.sample(fresh, min(feed_sample, len(fresh)))
    legit_pool = base[base.is_phishing == 0]
    # keep classes balanced: add as many (re-sampled) legitimate rows as fresh phishing rows
    extra_legit = legit_pool.sample(min(len(fresh), len(legit_pool)), random_state=7)
    extra = pd.concat([pd.DataFrame({"domain": fresh, "is_phishing": 1}), extra_legit], ignore_index=True)

    n_labels = 0
    if labels:
        lab = pd.DataFrame(labels)
        lab = lab[~lab.domain.isin(held_out)][["domain", "is_phishing"]]
        n_labels = len(lab)
        extra = extra[~extra.domain.isin(lab.domain)]
        base_ids = base.domain.isin(lab.domain)
        if base_ids.any():
            log(f"Analyst overrides {int(base_ids.sum())} existing labels")
        extra = pd.concat([extra, lab], ignore_index=True)
    log(f"Adding {len(fresh)} fresh feed domains and {n_labels} analyst labels ...")

    # train_main concatenates base + extra and drops duplicate domains, keeping the first;
    # put analyst labels first by removing those domains from the base file's rows.
    bundle = train_main(extra=extra, log=log, drop_from_base=set(lab.domain) if n_labels else None)
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
