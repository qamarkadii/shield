"""
Shield - backup Radar using crt.sh (public search over Certificate Transparency logs)

Run from the repo folder:   python backend\\scripts\\crtsh_search.py
Uses only Python's built-in libraries (nothing to install).

For each UAE brand keyword it asks crt.sh for every certificate whose domain
contains that keyword, removes the real official domains, and saves the rest
(newest first) to data\\crtsh_lookalikes.csv. Run it again later to get new ones.
crt.sh can be slow: each keyword may take up to a minute.
"""

import csv
import json
import os
import time
import urllib.parse
import urllib.request

# Longer, distinctive keywords only (short ones like "rta" match "portal")
KEYWORDS = ["salik", "uaepass", "dubaipolice", "emiratespost", "adpolice"]

# Real official domains to ignore (verify and extend this list)
OFFICIAL = ["salik.ae", "uaepass.ae", "dubaipolice.gov.ae", "emiratespost.ae",
            "adpolice.gov.ae", "u.ae"]

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA = os.path.join(ROOT, "data")  # repo-level data folder
os.makedirs(DATA, exist_ok=True)
OUT = os.path.join(DATA, "crtsh_lookalikes.csv")


def is_official(domain):
    return any(domain == d or domain.endswith("." + d) for d in OFFICIAL)


def search(keyword, tries=6):
    q = urllib.parse.quote(f"%{keyword}%")
    url = f"https://crt.sh/?q={q}&output=json&exclude=expired"
    req = urllib.request.Request(url, headers={"User-Agent": "Shield hackathon project"})
    for attempt in range(1, tries + 1):
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                return json.loads(r.read().decode("utf-8", "ignore") or "[]")
        except Exception as e:
            print(f"   try {attempt} failed ({e}); retrying..." if attempt < tries
                  else f"   gave up on '{keyword}': {e}")
            time.sleep(15 * attempt)  # wait longer each time crt.sh is overloaded
    return []


found = {}
for kw in KEYWORDS:
    print(f"Searching crt.sh for '{kw}' ...")
    for cert in search(kw):
        for name in cert.get("name_value", "").split("\n"):
            d = name.strip().lower().lstrip("*.")
            if not d or kw not in d or is_official(d):
                continue
            seen_at = cert.get("not_before", "")
            # keep the newest certificate per domain
            if d not in found or seen_at > found[d]["issued"]:
                found[d] = {"domain": d, "keyword": kw, "issued": seen_at,
                            "issuer": cert.get("issuer_name", "")}
    print(f"   {len([v for v in found.values() if v['keyword'] == kw])} lookalike domains so far")
    time.sleep(3)  # be polite to crt.sh

rows = sorted(found.values(), key=lambda r: r["issued"], reverse=True)
with open(OUT, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["domain", "keyword", "issued", "issuer"])
    w.writeheader()
    w.writerows(rows)

print(f"\nSaved {len(rows)} lookalike domains -> {OUT}")
print("Newest 15:")
for r in rows[:15]:
    print(f"  {r['issued'][:10]}  {r['domain']}")
