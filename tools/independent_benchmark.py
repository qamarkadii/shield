"""Reserve fresh owner-disjoint data before fitting; evaluate without feed lookup shortcuts."""
import argparse
import hashlib
import json
from pathlib import Path
import random
import sys
from urllib.parse import urlparse
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'ml'))

import pandas as pd
from backend.app.features import clean, private_owner, FREE_HOSTS

DEST = ROOT / 'data/independent_reserved.csv'


def prepare():
    if DEST.exists():
        print('Reservation already exists; preserving', DEST)
        return
    snapshots = sorted((ROOT / 'data/external_audit').glob('*/manifest.json'))
    folder = snapshots[-1].parent
    seen = set()
    for p in (ROOT / 'data').glob('*.csv'):
        df = pd.read_csv(p)
        if 'domain' in df:
            seen.update(private_owner(clean(str(d))) for d in df.domain)
        elif 'url' in df:
            seen.update(private_owner(clean(urlparse(str(d)).hostname or '')) for d in df.url)
    phishing = {}
    for url in (folder / 'openphish.txt').read_text().splitlines():
        host = clean(urlparse(url).hostname or '')
        if host and private_owner(host) not in seen:
            phishing.setdefault(private_owner(host), (host, url))
    rows = [(host, url, 1, 'openphish_current', own) for own, (host, url) in phishing.items()]
    rnd = random.Random(20261103)
    with zipfile.ZipFile(folder / 'tranco.zip') as z:
        ranked = [line.split(',', 1) for line in z.read(z.namelist()[0]).decode().splitlines()]
    candidates = [(clean(d), int(rank)) for rank, d in ranked if int(rank) >= 250000]
    rnd.shuffle(candidates)
    used = set(phishing)
    for host, rank in candidates:
        own = private_owner(host)
        if own in seen or own in used:
            continue
        used.add(own)
        rows.append((host, 'https://' + host, 0, 'tranco_current_proxy_legit', own))
        if sum(r[3] == 'tranco_current_proxy_legit' for r in rows) >= 2000:
            break
    with zipfile.ZipFile(folder / 'umbrella.zip') as z:
        hosts = [line.split(',', 1)[1] for line in z.read(z.namelist()[0]).decode().splitlines() if ',' in line]
    rnd.shuffle(hosts)
    count = 0
    for host in hosts:
        host = clean(host)
        if not any(host.endswith('.' + platform) for platform in FREE_HOSTS):
            continue
        own = private_owner(host)
        if own in used or own in seen:
            continue
        used.add(own)
        rows.append((host, 'https://' + host, 0, 'umbrella_hosting_proxy_legit', own))
        count += 1
        if count >= 400:
            break
    df = pd.DataFrame(rows, columns=['domain', 'url', 'is_phishing', 'source', 'owner'])
    df['part'] = ['frozen' if int(hashlib.sha256(('fresh-v1|' + o).encode()).hexdigest(), 16) % 10 < 3 else 'dev' for o in df.owner]
    df.to_csv(DEST, index=False)
    summary = dict(snapshot=str(folder), seed=20261103, rows=len(df),
                   counts=df.groupby(['part', 'source']).size().to_dict(),
                   caveat='Rankings are proxy legitimate labels, not verified safety. One snapshot and small positive sample limit generalization.')
    summary['counts'] = {str(k): int(v) for k, v in summary['counts'].items()}
    (ROOT / 'audit/independent_reservation.json').write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


def evaluate(path, output=None):
    import joblib
    import numpy as np
    from backend.app import riskmodel
    from common import wilson
    bundle = joblib.load(path)
    df = pd.read_csv(DEST)
    p, _, _, _ = riskmodel.predict(bundle, df.domain)
    df['p'] = p
    results = {'model_path': str(path), 'selection': 'No thresholds selected on this benchmark', 'groups': {}}
    results['model_sha256'] = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    if bundle.get('error_training'):
        results['candidate_training'] = bundle['error_training']
        results['independent_parts'] = ['frozen']
    for (part, source), group in df.groupby(['part', 'source']):
        r = dict(n=len(group), is_phishing=int(group.is_phishing.iloc[0]))
        for level, threshold in bundle['raw_thresholds'].items():
            k = int((group.p >= threshold).sum())
            r[level] = dict(flagged=k, rate=k/len(group), ci95=wilson(k, len(group)))
        results['groups'][part + '/' + source] = r
    # Names of frozen rows deliberately omitted, dev error examples only.
    dev = df[df.part == 'dev']
    errors = dev[((dev.is_phishing == 0) & (dev.p >= bundle['raw_thresholds']['suspicious'])) |
                 ((dev.is_phishing == 1) & (dev.p < bundle['raw_thresholds']['suspicious']))]
    results['dev_errors'] = errors.head(50).to_dict('records')
    out = Path(output) if output else ROOT / 'audit/independent_evaluation.json'
    out.write_text(json.dumps(results, indent=2))
    print(json.dumps({k:v for k,v in results.items() if k != 'dev_errors'}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--model')
    parser.add_argument('--out')
    args = parser.parse_args()
    evaluate(args.model, args.out) if args.model else prepare()
