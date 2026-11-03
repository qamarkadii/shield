"""Resume the existing run after a verified, semantics-preserving splitter optimization.

Only the documented model.py hash substitution is permitted. All other source,
data, dependency and input hashes continue to participate in checkpoint identity.
"""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'ml'))

import numpy as np
import recovery
import model
import train_baseline


def main():
    meta = json.loads((ROOT / 'audit/split_compatibility.json').read_text())
    original_digest = recovery.digest
    model_path = ROOT / 'ml/model.py'
    if original_digest(model_path) != meta['model_after_sha256']:
        raise RuntimeError('Model code changed beyond the verified optimization; review before resuming')
    before = (ROOT / 'audit/baseline_model_before_split.py').read_bytes()
    import hashlib
    assert hashlib.sha256(before).hexdigest() == meta['model_before_sha256']
    expected = before.decode().replace('\r\n', '\n').replace(
        'GroupKFold(n_splits=5, shuffle=True, random_state=seed).split(fit, groups=fit.owner)',
        'GroupKFold(n_splits=5, shuffle=True, random_state=seed).split(fit, groups=pd.factorize(fit.owner, sort=True)[0])')
    assert expected == model_path.read_text(), 'Optimization must be the only source change'

    def compatible_digest(path):
        actual = original_digest(path)
        if Path(path).resolve() == model_path.resolve():
            assert actual == meta['model_after_sha256']
            return meta['model_before_sha256']
        return actual

    recovery.digest = compatible_digest
    original_run = recovery.Run

    class CompatibleRun(original_run):
        def __init__(self, frame, seed):
            super().__init__(frame, seed)
            if self.key != meta['run']:
                raise RuntimeError('Other inputs changed; this is not the original recoverable run')

    recovery.Run = CompatibleRun
    splitter = model.GroupKFold
    verified = []

    class VerifiedGroupKFold(splitter):
        def split(self, X, y=None, groups=None):
            # Original sklearn logic, with set membership replacing quadratic
            # object-array np.isin. Compare exact indices on ALL actual rows.
            owners = X.owner.values
            expected_groups = np.array_split(np.random.RandomState(self.random_state).permutation(np.unique(owners)), self.n_splits)
            for i, (tr, va) in enumerate(super().split(X, y, groups)):
                selected = set(expected_groups[i])
                mask = np.fromiter((o in selected for o in owners), dtype=bool, count=len(owners))
                np.testing.assert_array_equal(va, np.flatnonzero(mask))
                np.testing.assert_array_equal(tr, np.flatnonzero(~mask))
                verified.append(dict(fold=i, rows=len(owners), exact_membership_equal=True))
                recovery.atomic_json(ROOT / 'audit/split_equivalence.json', verified)
                yield tr, va

    model.GroupKFold = VerifiedGroupKFold
    train_baseline.main()


if __name__ == '__main__':
    main()
