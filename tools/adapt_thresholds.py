"""Train a separate operating-point candidate on fresh DEV proxy legitimate data.

This changes thresholds, not classifier weights. Reduced false alarms can cost
recall: both must be reported. Frozen data never selects thresholds.
"""
import copy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'ml'))

import joblib
import numpy as np
import pandas as pd
from backend.app import riskmodel
from recovery import publish, digest


def main():
    source = ROOT / 'ml/domain_model.joblib'
    bundle = joblib.load(source)
    data = pd.read_csv(ROOT / 'data/independent_reserved.csv')
    dev = data[(data.part == 'dev') & (data.is_phishing == 0)]
    if len(dev) < 500:
        raise RuntimeError('Insufficient fresh development proxy negatives')
    p, _, _, _ = riskmodel.predict(bundle, dev.domain)
    candidate = copy.deepcopy(bundle)
    candidate['recovery_run'] += '-fresh-dev-thresholds-v1'
    old = dict(bundle['raw_thresholds'])
    # Conservative adaptation: never lower an existing threshold. This is a
    # declared operational budget, not a claim of statistically proven FPR.
    targets = {'suspicious': .005, 'high': .001}
    candidate['raw_thresholds'] = {
        level: max(old[level], float(np.quantile(p, 1-budget, method='higher')))
        for level, budget in targets.items()}
    candidate['thresholds'] = {level: float(riskmodel.calibrated(candidate, np.array([value]))[0])
                               for level, value in candidate['raw_thresholds'].items()}
    candidate['threshold_adaptation'] = dict(source_sha256=digest(source),
        dataset_sha256=digest(ROOT / 'data/independent_reserved.csv'),
        fit_part='dev proxy negatives only', rows=len(dev), targets=targets,
        old=old, new=candidate['raw_thresholds'],
        caveat='Threshold calibration only. Proxy labels may be wrong; FPR is not guaranteed. Evaluate independent recall and abstentions.')
    # Old results no longer describe this operating point.
    candidate.pop('results', None)
    receipt = publish(candidate, source)  # preserves existing production artifact
    out = dict(receipt=receipt, adaptation=candidate['threshold_adaptation'])
    (ROOT / 'audit/threshold_candidate.json').write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == '__main__':
    main()
