"""Finish corrected evaluation from saved weights, without invoking training."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'ml'))

import joblib
import eval_unseen
import train_baseline
from recovery import digest, event, atomic_json


def main():
    path = ROOT / 'ml/domain_model.joblib'
    identity = dict(model_sha256=digest(path), evaluator_sha256=digest(ROOT / 'ml/eval_unseen.py'),
                    system_check_sha256=digest(ROOT / 'ml/train_baseline.py'))
    completed = ROOT / 'audit/baseline_evaluation_complete.json'
    if completed.exists() and json.loads(completed.read_text()).get('identity') == identity:
        print('Corrected evaluation already completed for these weights and code; reusing report')
        return
    bundle = joblib.load(path)
    report = json.loads((ROOT / 'ml/model_report.json').read_text())
    assert report['trained_at'] == bundle['trained_at'], 'Model/report lineage mismatch'
    assert report['raw_thresholds'] == bundle['raw_thresholds']
    results = report['results']
    results['never_seen'] = eval_unseen.evaluate(bundle)
    results['with_rules'] = train_baseline.system_check()
    train_baseline._save(bundle, results)
    train_baseline.write_model_card(bundle, results, ROOT / 'docs/model_card.md')
    atomic_json(completed, dict(identity=identity, completed=True, trained_again=False,
                                with_rules=results['with_rules']))
    event('baseline_evaluation_complete', trained_again=False, **identity)
    print('Evaluation completed from existing model; no fitting repeated')


if __name__ == '__main__':
    main()
