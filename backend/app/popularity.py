r"""
Website popularity from the Tranco top-sites list (https://tranco-list.eu, research list
combining several rankings). Used as the `popularity` feature: names under a popular,
long-established site are rarely phishing - unless they are tenants of a hosting
platform, which never inherit the platform's rank (see features.popularity_value).

File: data/lists/tranco.zip (download with: python backend\scripts\download_data.py).
Only the top TOP_N are kept in memory (~30 MB).
"""

import csv
import io
import os
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TRANCO_PATH = os.path.join(ROOT, "data", "lists", "tranco.zip")
TOP_N = 250_000
_ranks = None


def load_ranks(top_n=TOP_N, path=TRANCO_PATH) -> dict:
    """{registered domain: rank}. Empty dict if the list isn't downloaded."""
    global _ranks
    if _ranks is not None and top_n == TOP_N and path == TRANCO_PATH:
        return _ranks
    ranks = {}
    if os.path.exists(path):
        with zipfile.ZipFile(path) as z:
            with z.open(z.namelist()[0]) as f:
                for row in csv.reader(io.TextIOWrapper(f, encoding="utf-8", errors="ignore")):
                    if len(row) < 2:
                        continue
                    r = int(row[0])
                    if r > top_n:
                        break
                    ranks.setdefault(row[1].strip().lower(), r)
    if top_n == TOP_N and path == TRANCO_PATH:
        _ranks = ranks
    return ranks
