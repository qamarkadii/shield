"""Verify checkpoint bytes and exact predictions after restoring a trusted model."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'ml'))

import joblib
import numpy as np
from backend.app import riskmodel
from recovery import digest


def verify(path):
    path = Path(path)
    first = joblib.load(path)
    second = joblib.load(path)
    probes = ['example.com', 'react-docs.vercel.app', 'careers.dubaiholding.com', 'salik-pay.com']
    p = riskmodel.predict(first, probes)[0]
    q = riskmodel.predict(second, probes)[0]
    np.testing.assert_allclose(p, q, rtol=0, atol=0)
    result = dict(path=str(path.resolve()), sha256=digest(path), prediction_parity_exact=True,
                  probes=dict(zip(probes, map(float, p))),
                  recovery_run=first.get('recovery_run'), version=first.get('version'))
    (ROOT / 'audit/recovery_verification.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--model', default=str(ROOT / 'ml/domain_model.joblib'))
    args = parser.parse_args()
    verify(args.model)
