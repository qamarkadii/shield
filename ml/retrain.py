"""
Retrain the domain model with LIVE data.

Live certificate domains have no labels (nobody has said yet whether they're phishing),
so the model can't learn from them directly. Training on its own guesses would just
repeat its mistakes. Instead Shield learns from live data in two honest ways:

1. Fresh phishing feeds (OpenPhish + Phishing.Database), downloaded at retrain time,
   so the model keeps up with the newest scam patterns.
2. Analyst decisions: every "Confirm phishing" / "Not phishing" click in the dashboard
   is a real label. These are weighted 20x so the model adapts quickly to UAE cases.

The test set and the 66 real UAE fakes are never used for training, so the accuracy
shown after retraining stays honest.

Run by hand:  python ml\\retrain.py      (or the Retrain button on the dashboard)
"""

import os
import random
import sys
import time

import joblib
import pandas as pd
import requests
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
FEEDS = os.path.join(DATA, "feeds")
MODEL = os.path.join(HERE, "domain_model.joblib")

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
    """labels: list of {"domain", "is_phishing"} from the analyst. Returns metrics."""
    t0 = time.time()
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
    extra_legit = legit_pool.sample(min(len(fresh), len(legit_pool)), random_state=7)

    parts = [base, pd.DataFrame({"domain": fresh, "is_phishing": 1}), extra_legit]
    n_labels = 0
    if labels:
        lab = pd.DataFrame(labels)
        lab = lab[~lab.domain.isin(held_out)]
        n_labels = len(lab)
        if n_labels:
            parts.append(pd.concat([lab[["domain", "is_phishing"]]] * 20))   # analyst labels weigh 20x
    train = pd.concat(parts, ignore_index=True).sample(frac=1, random_state=7)
    log(f"Training on {len(train)} rows ({len(fresh)} fresh feed domains, {n_labels} analyst labels) ...")

    vec = TfidfVectorizer(analyzer="char", ngram_range=(2, 5), min_df=3,
                          max_features=300000, sublinear_tf=True)
    clf = LogisticRegression(max_iter=2000, C=4)
    clf.fit(vec.fit_transform(train.domain), train.is_phishing)

    pred = clf.predict(vec.transform(test.domain))
    uae_pred = clf.predict(vec.transform(uae.domain))
    metrics = {
        "accuracy": round(accuracy_score(test.is_phishing, pred), 3),
        "precision": round(precision_score(test.is_phishing, pred), 3),
        "recall": round(recall_score(test.is_phishing, pred), 3),
        "uae_caught": f"{int(uae_pred.sum())}/{len(uae)}",
        "train_rows": int(len(train)),
        "fresh_feed_domains": len(fresh),
        "analyst_labels": n_labels,
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()) + " UTC",
        "seconds": round(time.time() - t0),
    }
    tmp = MODEL + ".tmp"
    joblib.dump((vec, clf), tmp)
    os.replace(tmp, MODEL)        # swap in the new model in one step
    log(f"Done: {metrics}")
    return metrics


if __name__ == "__main__":
    labels = []
    sys.path.insert(0, ROOT)
    try:
        from backend.app import db
        labels = db.all_labels()
    except Exception:
        pass
    retrain(labels=labels)
