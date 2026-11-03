"""Check fast evaluation agrees with actual serving decisions on regression cases."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'ml'))
import joblib
import model
import eval_unseen
from backend.app import scoring

if __name__ == '__main__':
    bundle = joblib.load(ROOT / 'ml/domain_model.joblib')
    domains = model.SANITY + ['salik.ae', 'www.adcb.com', 'example.com']
    batch = eval_unseen.score(bundle, domains)
    mapping = {'official': 0, 'no warning signs': 0, 'suspicious': 1, 'high risk': 2}
    actual = [mapping[scoring.score_domain(d)['verdict']] for d in domains]
    assert actual == batch.level_app.tolist()
    result = dict(cases=len(domains), all_serving_risk_levels_match=True,
                  includes_official_domains=True)
    (ROOT / 'audit/batch_serving_parity.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
