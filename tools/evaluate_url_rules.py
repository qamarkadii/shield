"""Measure URL rules separately from ML and known-feed membership.

Only aggregate frozen counts are emitted. Curated benign examples are regression
cases, not a representative estimate of real-world false-positive rate.
"""
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import pandas as pd
from backend.app import linkcheck


def blank(host):
    return dict(domain=host, registered_domain=host, score=None, verdict='unknown',
                brand=None, reasons=[], signals=[], rule=None)


def main():
    results = dict(protocol='URL rules only: domain ML and known feeds disabled', parts={})
    for part, filename in [('dev', 'uae_phishing_collected.csv'), ('frozen', 'uae_test_frozen.csv')]:
        df = pd.read_csv(ROOT / 'data' / filename).fillna('')
        if part == 'dev':
            df = df[df.part == 'dev']
        df = df[(df.category == 'path') & df.url.str.len().gt(0)]
        caught = 0
        with patch.object(linkcheck, 'score_domain', side_effect=blank), patch.object(linkcheck, '_known', set()):
            for url in df.url:
                r = linkcheck.check_link(url)
                caught += r.get('verdict') in ('suspicious', 'high risk')
        results['parts'][part] = dict(n=len(df), caught=caught, recall=caught/len(df) if len(df) else None)
    benign = [
        'https://example.org/articles/rta/transport-history',
        'https://example.org/news/adcb/annual-results',
        'https://example.org/research/salik/traffic',
        'https://example.org/partners/aramex/shipping',
        'https://example.org/myrtaexample/payment',
        'https://example.org/rtanews/login',
    ]
    with patch.object(linkcheck, 'score_domain', side_effect=blank), patch.object(linkcheck, '_known', set()):
        cases = [dict(url=u, verdict=linkcheck.check_link(u)['verdict']) for u in benign]
    results['curated_benign_regressions'] = cases
    results['curated_benign_flagged'] = sum(c['verdict'] in ('suspicious', 'high risk') for c in cases)
    results['limitation'] = 'A domain-only model cannot see URL paths. These rates do not measure ML and must not be presented as deployment accuracy.'
    (ROOT / 'audit/url_rules_evaluation.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
