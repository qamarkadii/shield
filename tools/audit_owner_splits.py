"""Reconstruct preparation only, verify actual owner exclusions; never refit a model."""
import hashlib
import inspect
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'ml'))
import joblib
import pandas as pd
import model
from backend.app.features import owner


class Prepared(Exception):
    pass


if __name__ == '__main__':
    captured = {}
    class Capture:
        def __init__(self, frame, seed):
            pass
        def stage(self, name, compute):
            assert name == 'static_fit'
            frame = inspect.currentframe().f_back.f_locals
            captured.update({k: frame[k] for k in ('fit', 'hold', 'held', 'real', 'platforms')})
            raise Prepared()
    train = pd.read_csv(ROOT / 'data/shield_training_domains.csv')
    train['source'], train['weight'] = 'base', 1.
    try:
        with patch('recovery.Run', Capture):
            model.build(train)
    except Prepared:
        pass
    fit, hold, held = set(captured['fit'].owner), set(captured['hold'].owner), set(captured['held'])
    fresh = pd.read_csv(ROOT / 'data/independent_reserved.csv')
    fresh_owners = {owner(d, captured['platforms']) for d in fresh.domain}
    real_eval = set(captured['real'].loc[captured['real']['eval'], 'owner'])
    saved_model = joblib.load(ROOT / 'ml/domain_model.joblib')
    out = dict(protocol='Current-source preparation only; no training performed',
        matches_saved_baseline_row_count=len(captured['fit']) == saved_model['train_rows'],
        fit_rows=len(captured['fit']), hold_rows=len(captured['hold']),
        fit_hold_owner_overlap=len(fit & hold), fit_reserved_evaluation_owner_overlap=len(fit & held),
        fit_fresh_benchmark_owner_overlap=len(fit & fresh_owners),
        hold_fresh_benchmark_owner_overlap=len(hold & fresh_owners),
        fit_real_hostname_evaluation_owner_overlap=len(fit & real_eval),
        fit_owner_sha256=hashlib.sha256('\n'.join(sorted(fit)).encode()).hexdigest(),
        hold_owner_sha256=hashlib.sha256('\n'.join(sorted(hold)).encode()).hexdigest())
    # Keep the actual pre-fix baseline audit immutable when future code changes.
    (ROOT / 'audit/owner_split_audit_current.json').write_text(json.dumps(out, indent=2), encoding='utf-8')
    print(json.dumps(out, indent=2))
    assert not (fit & hold or fit & held or fit & fresh_owners or hold & fresh_owners), 'Primary owner exclusion failed'
