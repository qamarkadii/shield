"""Audit supplied reports and exact domain overlap without claiming a fresh model run."""
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    sets = {}
    for p in (ROOT / 'data').glob('*.csv'):
        with p.open(encoding='utf-8-sig', newline='') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        domains = {r.get('domain', '').strip().lower() for r in rows} - {''}
        labels = {}
        for r in rows:
            labels.setdefault(r.get('is_phishing', 'unlabelled'), 0)
            labels[r.get('is_phishing', 'unlabelled')] += 1
        sets[p.name] = dict(rows=len(rows), unique_domains=len(domains), labels=labels, domains=domains)
    overlap = []
    names = list(sets)
    for i, name in enumerate(names):
        for other in names[i + 1:]:
            count = len(sets[name]['domains'] & sets[other]['domains'])
            if count:
                overlap.append(dict(a=name, b=other, exact_overlap=count))
    for v in sets.values():
        del v['domains']
    report = json.loads((ROOT / 'ml/unseen_report.json').read_text())
    projected = {}
    for part in ('dev', 'frozen'):
        r = report['unseen_' + part]
        projected[part] = {}
        for level in ('suspicious_or_higher', 'high'):
            tpr = r['phishing']['app_' + level]
            fpr = r['legit']['app_' + level]
            projected[part][level] = {'recall': tpr, 'fpr': fpr,
                'precision_at_1pct': .01*tpr / (.01*tpr + .99*fpr),
                'source': 'historical bundled report; not reproduced'}
    out = dict(datasets=sets, exact_overlap=overlap, historical_projections=projected,
               warning='Exact overlap is diagnostic. Owner-level training purges must also be verified.')
    (ROOT / 'audit').mkdir(exist_ok=True)
    (ROOT / 'audit/data_audit.json').write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == '__main__':
    main()
