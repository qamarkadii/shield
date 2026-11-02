"""
Shield - download tonight's training data into the repo's data folder

Run from the repo folder:   python backend\\scripts\\download_data.py
Uses only Python's built-in libraries (nothing to install).
"""

import csv
import io
import os
import urllib.request
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA = os.path.join(ROOT, "data")  # repo-level data folder
os.makedirs(DATA, exist_ok=True)

HEADERS = {"User-Agent": "Mozilla/5.0 (Shield hackathon project)"}


def fetch(url):
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def save(name, content):
    path = os.path.join(DATA, name)
    with open(path, "wb") as f:
        f.write(content)
    return path


# 1. OpenPhish free feed: currently active phishing URLs (scam examples)
try:
    raw = fetch("https://openphish.com/feed.txt")
    path = save("openphish_phishing.txt", raw)
    count = len([l for l in raw.decode("utf-8", "ignore").splitlines() if l.strip()])
    print(f"OK  OpenPhish: {count} phishing URLs -> {path}")
except Exception as e:
    print("FAILED  OpenPhish:", e)

# 2. Tranco top sites: legitimate domains (safe examples) - keep the top 10,000
try:
    raw = fetch("https://tranco-list.eu/top-1m.csv.zip")
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        text = z.read(z.namelist()[0]).decode("utf-8", "ignore")
    rows = list(csv.reader(io.StringIO(text)))[:10000]
    out = "\n".join(r[1] for r in rows if len(r) > 1)
    path = save("tranco_top10k_legit.txt", out.encode("utf-8"))
    print(f"OK  Tranco: {len(rows)} legitimate domains -> {path}")
except Exception as e:
    print("FAILED  Tranco:", e)

# 3. URLhaus recent: mostly malware-distribution URLs (extra bad examples)
try:
    raw = fetch("https://urlhaus.abuse.ch/downloads/csv_recent/")
    path = save("urlhaus_recent.csv", raw)
    print(f"OK  URLhaus: saved -> {path}")
except Exception as e:
    print("FAILED  URLhaus:", e)

print("\nDone. If anything FAILED, send me the message and I'll give you another route.")

# 4. Top-sites lists for the risk model (kept as .zip in data/lists):
#    Tranco full top-1M  -> `popularity` feature (backend/app/popularity.py)
#    Cisco Umbrella top-1M (DNS traffic, full hostnames) -> real legitimate hostnames for training
LISTS = os.path.join(DATA, "lists")
os.makedirs(LISTS, exist_ok=True)
for name, url in (("tranco.zip", "https://tranco-list.eu/top-1m.csv.zip"),
                  ("umbrella.zip", "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip")):
    try:
        raw = fetch(url)
        zipfile.ZipFile(io.BytesIO(raw)).namelist()      # check it's a valid zip
        with open(os.path.join(LISTS, name), "wb") as f:
            f.write(raw)
        print(f"OK  {name}: {len(raw) // 1024:,} KB -> {LISTS}")
    except Exception as e:
        print(f"FAILED  {name}:", e)
print("\nDone. If anything FAILED, send me the message and I'll give you another route.")
