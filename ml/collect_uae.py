"""
Collect REAL UAE-targeted phishing from public phishing lists (not synthetic).

Run:  python ml\\collect_uae.py            (downloads the sources into data/sources first)
      python ml\\collect_uae.py --offline  (use what is already in data/sources)

Every domain here was reported as phishing by a public source. We keep the ones that
target the UAE, in four groups:
  brand     imitates a registered UAE brand (backend/app/registry.py): re-spelled, with a lure
            word, in front of an unrelated domain, look-alike letters, or just using the name
  fake_ae   puts 'ae' inside a foreign domain to look official (my-pay.ae.add-on.shop)
  uae_lure  a UAE place or 'uae' plus a lure word / global brand (dubai-chamber-payments.com)
  uae_plain a UAE place in an ordinary business name (carbatterydubai.com); most likely a hacked
            site: kept for reference, never used for training
  path      the NAME looks innocent but the reported LINK's path names a UAE brand
            (x.com/salik/pay): the domain model can't see these, the link check can

Then every owner (registered site or hosting tenant) is put in ONE of three parts by a hash
of its name, so the same site is never in two parts:
  train   50%  may be used for training
  dev     20%  never trained on; errors here are inspected to fix the logic
  frozen  30%  never trained on and never inspected: only totals are ever reported
Outputs: data/uae_phishing_collected.csv (train + dev, with the part column) and
data/uae_test_frozen.csv (frozen part).
"""

import csv
import io
import os
import re
import sys
import urllib.request
import zlib
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from backend.app.features import (HOMOGLYPHS, UAE_TERMS, _has_lure, _match, _tokens, clean,  # noqa: E402
                                  extract, owner, split_domain, uae_term_in)
from backend.app.registry import UAE_BRANDS  # noqa: E402

DATA = os.path.join(ROOT, "data")
SRC = os.path.join(DATA, "sources")
PDB = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database"

# name -> (url, kind). Snapshots of Phishing.Database from earlier dates hold phishing that
# has since gone offline (pinned commits, so the files never change).
SOURCES = {
    "pdb_links_active.txt": (f"{PDB}/master/phishing-links-ACTIVE.txt", "links"),
    "pdb_links_inactive.txt": (f"{PDB}/master/phishing-links-INACTIVE.txt", "links"),
    "pdb_domains_2025-11.txt": (f"{PDB}/bc99e004fa707376227cec713e74dec2871ceeaf/phishing-domains-ACTIVE.txt", "domains"),
    "pdb_domains_2026-05.txt": (f"{PDB}/822ed0a105f409109a063b83a4d5f2bfc35c7c07/phishing-domains-ACTIVE.txt", "domains"),
    "destroylist.txt": ("https://raw.githubusercontent.com/phishdestroy/destroylist/main/list.txt", "domains"),
    "openphish_now.txt": ("https://openphish.com/feed.txt", "links"),
}
LOCAL = {
    "shield_training_domains.csv": "csv",          # phishing rows only
    "shield_test_domains.csv": "csv",
    "phiusiil_urls_labeled.csv": "csv",
    "uae_phishing_domains_real.csv": "csv",
    "feeds/phishing_database_active.txt": "domains",
    "feeds/openphish.txt": "links",
}

PART_SPLIT = (("train", 5), ("dev", 2), ("frozen", 3))      # out of 10


def part_of(o: str) -> str:
    b = zlib.crc32(("uae-split|" + o).encode()) % 10
    for name, n in PART_SPLIT:
        if b < n:
            return name
        b -= n
    return "frozen"


def download(offline=False):
    os.makedirs(SRC, exist_ok=True)
    for name, (url, _) in SOURCES.items():
        path = os.path.join(SRC, name)
        if offline or (os.path.exists(path) and os.path.getsize(path) > 1000 and "now" not in name):
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Shield research)"})
            with urllib.request.urlopen(req, timeout=300) as r, open(path, "wb") as f:
                f.write(r.read())
            print(f"OK  {name}")
        except Exception as ex:
            print(f"FAILED  {name}: {ex}")


def _edits(key: str):
    """All strings one Damerau edit away from key (for a fast typo pre-filter)."""
    abc = "abcdefghijklmnopqrstuvwxyz0123456789"
    out = set()
    for i in range(len(key) + 1):
        for c in abc:
            out.add(key[:i] + c + key[i:])
    for i in range(len(key)):
        out.add(key[:i] + key[i + 1:])
        for c in abc:
            out.add(key[:i] + c + key[i + 1:])
        if i < len(key) - 1:
            out.add(key[:i] + key[i + 1] + key[i] + key[i + 2:])
    return out


KEYS = sorted(UAE_BRANDS, key=len, reverse=True)
_ANY = re.compile("|".join(map(re.escape, [k for k in KEYS] + list(UAE_TERMS) + ["uae", "alain", "ae"])))
TYPOS = set().union(*(_edits(k) for k in KEYS if len(k) >= 6))


def maybe_uae(host: str) -> bool:
    if "xn--" in host:
        return True
    flat = host.translate(HOMOGLYPHS)
    if _ANY.search(flat):
        return True
    return any(l.replace("-", "") in TYPOS for l in host.split("."))


def fake_ae(host: str) -> bool:
    """'ae' used inside a foreign name: an 'ae' label in the middle (etisalat.ae.comseal.xyz),
    a label ending '-ae' (dhlxpress-ae.com). 'gov' alone is not UAE (irs.gov.x.com)."""
    labels = host.split(".")
    return "ae" in labels[:-1] or any(l.endswith("-ae") or (l.startswith("ae-") and _has_lure(_tokens(l)))
                                      for l in labels[:-1])


def classify(host: str):
    """(category, brand) or None.
    uae_lure  = UAE place + a lure word / a global brand / many hyphens (dubai-chamber-payments.com)
    uae_plain = UAE place in an ordinary business name (carbatterydubai.com): most likely a hacked
                small-business site. NOT used for training (it would teach 'dubai = phishing')."""
    ext, reg = split_domain(host)
    info = extract(host, UAE_BRANDS)
    b, f = info["brand"], info["features"]
    if info["official"]:
        return None
    if b and "(global brand)" not in b:
        return "brand", b                 # also on another .ae site (eim.ae.iwc.x.ae)
    if ext.suffix == "ae" or ext.suffix.endswith(".ae"):
        return None                       # otherwise a (hacked) .ae site, not an impersonation
    if fake_ae(host):
        return "fake_ae", (b or "").replace(" (global brand)", "")
    if uae_term_in(host):
        deceptive = f["lure_word"] or (b and "(global brand)" in b) or f["many_hyphens"]
        return ("uae_lure" if deceptive else "uae_plain"), (b or "").replace(" (global brand)", "")
    return None


def path_brand(url: str):
    """A UAE brand named in the PATH of a link (x.com/salik/pay), whole word, 5+ letters."""
    m = re.match(r"^[a-z][a-z0-9+.-]*://[^/]+(/.*)?$", url.strip().lower())
    path = (m.group(1) or "") if m else ""
    for t in _tokens(path):
        for k in KEYS:
            if len(k) >= 5 and _match(t, k) in ("exact", "prefix"):
                return UAE_BRANDS[k][0]
    return None


def _rows(path, kind):
    """Yields (url_or_None, host) of PHISHING entries in one file."""
    with open(path, encoding="utf-8", errors="ignore") as f:
        if kind == "csv":
            r = csv.DictReader(f)
            col = "domain" if "domain" in r.fieldnames else ("url" if "url" in r.fieldnames else r.fieldnames[0])
            lab = next((c for c in ("is_phishing", "label") if c in r.fieldnames), None)
            for row in r:
                if lab is None or str(row[lab]).strip() in ("1", "1.0", "phishing"):
                    v = row[col]
                    yield (v if "://" in v else None), clean(v)
        else:
            for line in f:
                line = line.strip()
                if line and not line.startswith(("#", "!")):
                    yield (line if kind == "links" else None), clean(line)


def collect():
    found = {}          # host -> dict
    files = [(os.path.join(SRC, n), k) for n, (_, k) in SOURCES.items()] + \
            [(os.path.join(DATA, n), k) for n, k in LOCAL.items()]
    for path, kind in files:
        if not os.path.exists(path):
            print("missing:", path)
            continue
        src = os.path.relpath(path, DATA).replace("\\", "/")
        n = hits = 0
        for url, host in _rows(path, kind):
            n += 1
            if not host or "." not in host or len(host) > 253:
                continue
            c = classify(host) if maybe_uae(host) else None
            pb = None
            if c is None and url:
                pb = path_brand(url)
                if pb:
                    c = ("path", pb)
            if c is None:
                continue
            hits += 1
            e = found.setdefault(host, {"domain": host, "url": url or "", "category": c[0], "brand": c[1] or "",
                                        "sources": set()})
            e["sources"].add(src)
            if url and not e["url"]:
                e["url"] = url
        print(f"{src}: {n:,} phishing entries, {hits:,} UAE-targeted")
    return found


def main():
    download("--offline" in sys.argv)
    found = collect()
    base = set()
    with open(os.path.join(DATA, "shield_training_domains.csv"), encoding="utf-8") as f:
        for row in csv.DictReader(f):
            base.add(clean(row["domain"]))
    # The 66 cases of data/uae_phishing_domains_real.csv were looked at while the rules were
    # written: their owners may never be in the frozen part.
    with open(os.path.join(DATA, "uae_phishing_domains_real.csv"), encoding="utf-8") as f:
        seen_owners = {owner(clean(r["domain"])) for r in csv.DictReader(f)}
    rows = []
    for e in found.values():
        o = owner(e["domain"])
        part = part_of(o)
        if part == "frozen" and o in seen_owners:
            part = "dev"
        rows.append({**e, "sources": ";".join(sorted(e["sources"])), "owner": o, "part": part,
                     "in_base_training": int(e["domain"] in base)})
    cols = ["domain", "url", "category", "brand", "owner", "part", "in_base_training", "sources"]
    keep = [r for r in rows if r["part"] != "frozen"]
    frozen = [r for r in rows if r["part"] == "frozen"]
    for name, rs in (("uae_phishing_collected.csv", keep), ("uae_test_frozen.csv", frozen)):
        with open(os.path.join(DATA, name), "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            w.writerows(sorted(rs, key=lambda r: (r["category"], r["brand"], r["domain"])))
    by = defaultdict(lambda: defaultdict(int))
    for r in rows:
        by[r["category"]][r["part"]] += 1
    print("\nUAE-targeted phishing (unique names):", len(rows), "| owners:", len({r['owner'] for r in rows}))
    for c, parts in sorted(by.items()):
        print(f"  {c:9s} " + "  ".join(f"{p}={parts[p]}" for p, _ in PART_SPLIT))
    brands = defaultdict(int)
    for r in rows:
        if r["brand"]:
            brands[r["brand"]] += 1
    print("  by brand:", ", ".join(f"{b} {n}" for b, n in sorted(brands.items(), key=lambda x: -x[1])))


if __name__ == "__main__":
    main()
