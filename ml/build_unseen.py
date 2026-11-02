"""
Build a data set of domains the model has NEVER seen, to measure it honestly.

Run after ml\\collect_uae.py (which downloads data/sources):   python ml\\build_unseen.py

Phishing: the newer and older Phishing.Database snapshots, Phishing.Database links, and the
          PhishDestroy list (data/sources), different from the base training file.
Legit:    Tranco sites ranked 250,001-1,000,000 (the model's popularity feature only knows the
          top 250k, so these look like ordinary small sites), plus every .ae site in Tranco.
Every site (owner) that appears ANYWHERE in the base training or test file is removed, and
legit names that also appear on a phishing list are dropped.

Owners are split with the same hash as collect_uae.py, so a site is in the same part in both:
  data/unseen_train.csv   may be used to train the next model
  data/unseen_dev.csv     never trained on; errors are inspected to fix the logic
  data/unseen_frozen.csv  never trained on, never inspected (only totals reported)
"""

import csv
import io
import os
import random
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from backend.app.features import clean, owner  # noqa: E402
from collect_uae import SRC, part_of, _rows  # noqa: E402

DATA = os.path.join(ROOT, "data")
PHISH_FILES = {"pdb_domains_2025-11.txt": "domains", "pdb_domains_2026-05.txt": "domains",
               "destroylist.txt": "domains", "pdb_links_active.txt": "links", "pdb_links_inactive.txt": "links"}
MAX_PER_PART = {"train": 60_000, "dev": 10_000, "frozen": 10_000}     # per class
SEED = 11


def _base_owners():
    seen, names = set(), set()
    for name in ("shield_training_domains.csv", "shield_test_domains.csv", "uae_phishing_domains_real.csv"):
        with open(os.path.join(DATA, name), encoding="utf-8") as f:
            for row in csv.DictReader(f):
                d = clean(row["domain"])
                names.add(d)
                seen.add(owner(d))
    return seen, names


def main():
    base_owners, base_names = _base_owners()
    print(f"Base training/test owners excluded: {len(base_owners):,}")

    phish = {}
    for name, kind in PHISH_FILES.items():
        p = os.path.join(SRC, name)
        if not os.path.exists(p):
            print("missing", p, "- run python ml\\collect_uae.py first")
            continue
        for _, d in _rows(p, kind):
            if d and "." in d and len(d) <= 253 and d not in phish:
                phish[d] = name
    phish_owners = {owner(d) for d in phish}
    print(f"Phishing names in new sources: {len(phish):,}")

    legit = {}
    with zipfile.ZipFile(os.path.join(DATA, "lists", "tranco.zip")) as z:
        text = z.read(z.namelist()[0]).decode("utf-8", "ignore")
    for line in text.splitlines():
        r, _, d = line.partition(",")
        d = clean(d)
        if not d or not r.isdigit():
            continue
        r = int(r)
        if r > 250_000 or d.endswith(".ae"):
            legit[d] = "tranco_ae" if d.endswith(".ae") else "tranco_250k_1m"

    rows = {"train": [], "dev": [], "frozen": []}
    dropped = {"phish_in_base": 0, "legit_in_base": 0, "legit_on_phish_list": 0}
    for d, src in phish.items():
        o = owner(d)
        if o in base_owners or d in base_names:
            dropped["phish_in_base"] += 1
            continue
        rows[part_of(o)].append((d, 1, src, o))
    for d, src in legit.items():
        o = owner(d)
        if o in base_owners or d in base_names:
            dropped["legit_in_base"] += 1
            continue
        if o in phish_owners or d in phish:
            dropped["legit_on_phish_list"] += 1
            continue
        rows[part_of(o)].append((d, 0, src, o))
    print("Dropped:", dropped)

    rnd = random.Random(SEED)
    for part, rs in rows.items():
        out = []
        for y in (1, 0):
            cls = [r for r in rs if r[1] == y]
            if y == 0:      # always keep every .ae legit site (rare and important), sample the rest
                ae = [r for r in cls if r[2] == "tranco_ae"]
                rest = [r for r in cls if r[2] != "tranco_ae"]
                cls = ae + rnd.sample(rest, min(len(rest), MAX_PER_PART[part] - len(ae)))
            else:
                cls = rnd.sample(cls, min(len(cls), MAX_PER_PART[part]))
            out += cls
        rnd.shuffle(out)
        with open(os.path.join(DATA, f"unseen_{part}.csv"), "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["domain", "is_phishing", "source", "owner"])
            w.writerows(out)
        n1 = sum(r[1] for r in out)
        print(f"unseen_{part}.csv: {len(out):,} rows ({n1:,} phishing, {len(out) - n1:,} legit, "
              f"{sum(r[2] == 'tranco_ae' for r in out):,} legit .ae)")


if __name__ == "__main__":
    main()
