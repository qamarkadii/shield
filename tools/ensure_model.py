"""Restore a valid local model before considering training; never delete checkpoints."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'ml'))
import joblib
from recovery import digest
from backend.app import riskmodel


def ensure(train_if_missing=False):
    destination = ROOT / 'ml/domain_model.joblib'
    if not destination.exists():
        candidates = []
        pointer = ROOT / 'checkpoints/serving.json'
        if pointer.exists():
            item = json.loads(pointer.read_text())
            candidate = ROOT / item['archive_relative_path']
            if candidate.exists() and digest(candidate) == item['sha256']:
                candidates = [candidate]
        if not candidates:
            for p in (ROOT / 'checkpoints/runs').glob('*/fitted_bundle.joblib'):
                sidecar = p.with_suffix('.json')
                if sidecar.exists() and digest(p) == json.loads(sidecar.read_text())['sha256']:
                    candidates.append(p)
        if len(candidates) == 1:
            restored = joblib.load(candidates[0])
            assert restored['version'] == riskmodel.BUNDLE_VERSION
            tmp = destination.with_suffix('.tmp')
            shutil.copy2(candidates[0], tmp)
            os.replace(tmp, destination)
            print('Restored existing model; no training:', candidates[0])
        elif len(candidates) > 1:
            raise RuntimeError('Multiple recoverable models exist; select one explicitly instead of retraining')
        elif train_if_missing:
            partial = list((ROOT / 'checkpoints/runs').glob('*/*.joblib'))
            if partial:
                if not (ROOT / 'audit/split_compatibility.json').exists():
                    raise RuntimeError('Partial checkpoints exist; inspect run metadata and resume compatible training')
                command = [sys.executable, 'tools/resume_optimized.py']
            else:
                if not (ROOT / 'data/lists/tranco.zip').exists():
                    subprocess.run([sys.executable, 'backend/scripts/download_data.py'], cwd=ROOT, check=True)
                command = [sys.executable, 'ml/train_baseline.py']
            subprocess.run(command, cwd=ROOT, check=True)
        else:
            raise RuntimeError('No complete model. Resume compatible stages or explicitly use --train-if-missing')
    model = joblib.load(destination)
    if model.get('uses_popularity') and not (ROOT / 'data/lists/tranco.zip').exists() and 'ranks' not in model:
        raise RuntimeError('Restore the matching Tranco list; a fresh list would change this model\'s predictions')
    riskmodel.predict(model, ['example.com'])
    print('Model reload and inference verified:', destination)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--train-if-missing', action='store_true')
    args = parser.parse_args()
    ensure(args.train_if_missing)
