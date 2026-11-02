"""
Shared training helpers.

Why augment_legit exists: our legitimate examples are mostly bare names
(company.com) while many phishing examples have subdomains (login.x.xyz).
A model trained on that learns a shortcut: "has a subdomain = phishing".
Adding common subdomains to legitimate examples removes the shortcut. Since
v2 we also add REAL legitimate hostnames (real_legit_hostnames), and we
evaluate hostnames with a DIFFERENT subdomain list (EVAL_SUBDOMAINS) plus real
hostnames of owners never used in training, so the check is not circular.
"""

import io
import math
import os
import random
import zipfile
import zlib
from collections import defaultdict

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LISTS = os.path.join(ROOT, "data", "lists")

# Used to AUGMENT training data
COMMON_SUBDOMAINS = [
    "www", "mail", "webmail", "smtp", "imap", "autodiscover", "api", "app", "portal",
    "shop", "m", "cdn", "static", "vpn", "remote", "dev", "staging", "test", "blog",
    "support", "help", "docs", "admin", "cpanel", "ftp", "ns1", "mx", "secure", "login",
    "account", "my", "online", "pay", "store", "auth", "sso", "id", "en", "ar",
]
# Used only to EVALUATE (no overlap with the list above)
EVAL_SUBDOMAINS = [
    "careers", "jobs", "news", "media", "status", "cloud", "console", "investors", "events",
    "community", "forum", "learn", "academy", "partners", "developer", "careers-eu", "go",
    "files", "assets", "img", "images", "video", "live", "beta", "uat", "sandbox", "cms",
    "crm", "hr", "intranet", "owa", "exchange", "lyncdiscover", "sip", "meet", "calendar",
    "fr", "de", "uk", "ae-en", "kb", "wiki", "search", "maps", "analytics", "track1",
]
assert not set(COMMON_SUBDOMAINS) & set(EVAL_SUBDOMAINS)


def augment_legit(df: pd.DataFrame, share=0.5, seed=42) -> pd.DataFrame:
    """Keep every example and ADD a copy of `share` of the legitimate BARE domains with a
    realistic subdomain (mail.company.com). Copies keep the original's owner/weight."""
    rnd = random.Random(seed)
    legit = df[(df.is_phishing == 0) & (df.domain.str.count(r"\.") <= 2)]
    if "source" in legit:
        legit = legit[legit.source == "base"]
    idx = rnd.sample(list(legit.index), int(len(legit) * share))
    extra = df.loc[idx].copy()
    extra["domain"] = [f"{rnd.choice(COMMON_SUBDOMAINS)}.{d}" for d in extra.domain]
    if "source" in extra:
        extra["source"] = "augmented"
    return pd.concat([df, extra], ignore_index=True)


def legit_hostname_fpr(predict_level, domains, seed=7, subdomains=EVAL_SUBDOMAINS):
    """Share of legitimate domains flagged when written as hostnames with subdomains the
    model never saw in augmentation. predict_level(list) -> array of 0/1 flags."""
    rnd = random.Random(seed)
    hosts = [f"{rnd.choice(subdomains)}.{d}" for d in domains]
    return float(predict_level(hosts).mean())


def detect_platforms(domains, min_tenants=25):
    """Registered domains with many different first-level names under them
    (weeblysite.com, 000webhostapp.com): multi-tenant platforms. Unsupervised - no labels."""
    from backend.app.features import private_owner
    tenants = defaultdict(set)
    for d in domains:
        o = private_owner(d)
        if d != o and d.endswith("." + o):
            tenants[o].add(d[: -len(o) - 1].split(".")[-1])
    return frozenset(o for o, t in tenants.items() if len(t) >= min_tenants)


def _hash_bucket(s: str, n=5) -> int:
    return zlib.crc32(s.encode("utf-8")) % n


def is_eval_owner(o: str) -> bool:
    """Owners in bucket 0 are reserved for evaluating real hostnames; never trained on."""
    return _hash_bucket(o) == 0


def real_legit_hostnames(ranks: dict, platforms, exclude_owners=frozenset(), top_registered=100_000,
                         per_owner=20, seed=5):
    """Real hostnames from the Cisco Umbrella top-1M (data/lists/umbrella.zip, DNS-traffic
    ranking, so it contains full hostnames such as console.aws.amazon.com), kept only when
    the registered domain is a Tranco top-100k site (well-established), or the host is a
    tenant of a hosting platform that is popular enough to be in Umbrella.
    Returns DataFrame(domain, owner, eval) - eval=True rows are for evaluation only."""
    from backend.app.features import FREE_HOSTS, clean, owner, private_owner, split_domain
    path = os.path.join(LISTS, "umbrella.zip")
    if not os.path.exists(path) or not ranks:
        return pd.DataFrame(columns=["domain", "owner", "eval"])
    with zipfile.ZipFile(path) as z:
        text = z.read(z.namelist()[0]).decode("utf-8", "ignore")
    rnd = random.Random(seed)
    per = defaultdict(list)
    for line in text.splitlines():
        parts = line.split(",", 1)
        if len(parts) < 2:
            continue
        h = clean(parts[1])
        if not h or "." not in h or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in h):
            continue
        _, reg = split_domain(h)
        if not reg or h == reg:
            continue
        o = owner(h, platforms)
        tenant = o != reg or private_owner(h) != reg or reg in FREE_HOSTS
        r = ranks.get(reg)
        if (tenant and o.count(".") >= 2) or (not tenant and r is not None and r <= top_registered):
            if o not in exclude_owners:
                per[o].append(h)
    rows = []
    for o, hs in per.items():
        for h in (rnd.sample(hs, per_owner) if len(hs) > per_owner else hs):
            rows.append((h, o, is_eval_owner(o)))
    return pd.DataFrame(rows, columns=["domain", "owner", "eval"])


def wilson(k: int, n: int, z=1.96):
    """95% confidence interval for a proportion k/n."""
    if n == 0:
        return [0.0, 0.0]
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return [round(float(max(0.0, c - h)), 3), round(float(min(1.0, c + h)), 3)]


def precision_at(prevalence, recall, fpr):
    """Precision if `prevalence` of all domains seen were phishing."""
    tp, fp = recall * prevalence, fpr * (1 - prevalence)
    return round(float(tp / (tp + fp)), 3) if tp + fp else 0.0
