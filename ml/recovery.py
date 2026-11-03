"""Persistent, immutable stage checkpoints for sklearn's non-incremental fits.

Resume at completed stages; an interrupted individual fit must repeat. Joblib is
pickle: only restore checkpoints produced by this trusted local project.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import time
import uuid

import joblib
from filelock import FileLock

ROOT = Path(__file__).resolve().parents[1]
STORE = Path(os.environ.get('SHIELD_CHECKPOINT_DIR', ROOT / 'checkpoints')).resolve()


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    tmp.write_text(json.dumps(value, indent=2, default=str), encoding='utf-8')
    os.replace(tmp, path)


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def event(kind, **details):
    STORE.mkdir(parents=True, exist_ok=True)
    with FileLock(str(STORE / '.metadata.lock'), timeout=30):
        _event(kind, **details)


def _event(kind, **details):
    with (STORE / 'history.jsonl').open('a', encoding='utf-8') as f:
        f.write(json.dumps(dict(time=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                                event=kind, **details), default=str) + '\n')
    # Keep human handoff documents current even when a chat ends mid-training.
    status = dict(last_event=kind, **details)
    atomic_json(STORE / 'status.json', status)
    marker = '\n<!-- AUTO_CHECKPOINT_STATUS -->\n'
    for name in ('PROJECT_HANDOFF.md', 'TRAINING_STATE.md', 'CONTINUE_HERE.md'):
        doc = ROOT / name
        if doc.exists():
            body = doc.read_text(encoding='utf-8').split(marker)[0]
            summary = marker + '\nLatest automatic recovery event:\n```json\n' + json.dumps(status, indent=2, default=str) + '\n```\n'
            tmp = doc.with_name(doc.name + '.' + uuid.uuid4().hex + '.tmp')
            tmp.write_text(body + summary, encoding='utf-8')
            os.replace(tmp, doc)


class Run:
    def __init__(self, frame, seed):
        import sklearn
        h = hashlib.sha256(frame.to_csv(index=False).encode())
        h.update(f'{seed}|{sklearn.__version__}|{platform.python_version()}'.encode())
        # All model code and local datasets affect cache identity, including lists.
        for folder in ('ml', 'backend/app', 'data'):
            for p in sorted((ROOT / folder).rglob('*')):
                if p.is_file() and p.suffix in ('.py', '.csv', '.zip', '.txt', '.jsonl'):
                    h.update(str(p.relative_to(ROOT)).encode())
                    h.update(digest(p).encode())
        self.key = h.hexdigest()
        self.path = STORE / 'runs' / self.key
        self.path.mkdir(parents=True, exist_ok=True)
        atomic_json(self.path / 'run.json', dict(fingerprint=self.key, seed=seed,
                    sklearn=sklearn.__version__, python=platform.python_version(),
                    rows=len(frame), optimizer_state='not exposed by sklearn batch fit'))
        event('run_open', fingerprint=self.key)

    def stage(self, name, compute):
        # Fail fast rather than fit the same run twice in competing processes.
        with FileLock(str(self.path / '.training.lock'), timeout=0):
            return self._stage(name, compute)

    def _stage(self, name, compute):
        target = self.path / (name + '.joblib')
        manifest = target.with_suffix('.json')
        if target.exists() and manifest.exists():
            expected = json.loads(manifest.read_text())['sha256']
            if digest(target) != expected:
                raise RuntimeError(f'Checkpoint corrupted: {target}; restore a backup')
            result = joblib.load(target)
            event('stage_resumed', run=self.key, stage=name)
            return result
        result = compute()
        tmp = target.with_name(target.name + '.' + uuid.uuid4().hex + '.tmp')
        joblib.dump(result, tmp, compress=3)
        joblib.load(tmp)  # verify actual deserialization before publishing
        os.replace(tmp, target)
        atomic_json(manifest, dict(sha256=digest(target), stage=name))
        atomic_json(STORE / 'latest.json', dict(run=self.key, stage=name, path=str(target)))
        event('stage_saved_reload_verified', run=self.key, stage=name)
        return result


def publish(bundle, path):
    """Archive every candidate; best selected by internal validation, never frozen test."""
    STORE.mkdir(parents=True, exist_ok=True)
    with FileLock(str(STORE / '.publish.lock'), timeout=30):
        return _publish(bundle, path)


def _publish(bundle, path):
    run = bundle.get('recovery_run', 'legacy')
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:8]
    archive = STORE / 'models' / (stamp + '.joblib')
    archive.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, archive, compress=3)
    restored = joblib.load(archive)
    from backend.app import riskmodel
    import numpy as np
    probe = ['example.com', 'salik-pay.com', 'react-docs.vercel.app']
    np.testing.assert_allclose(riskmodel.predict(bundle, probe)[0],
                               riskmodel.predict(restored, probe)[0], rtol=0, atol=0)
    score = bundle['combiner_scores'][bundle['combiner_kind']]['holdout_log_loss']
    best_path = STORE / 'best.json'
    previous = json.loads(best_path.read_text()) if best_path.exists() else None
    # Different datasets are incomparable. Keep a per-run best and preserve global incumbent.
    pointer = dict(path=str(archive), sha256=digest(archive), run=run,
                   selection_metric='internal_holdout_log_loss', value=score,
                   prediction_reload_verified=True)
    atomic_json(STORE / 'latest_model.json', pointer)
    if previous is None or (previous['run'] == run and score <= previous['value']):
        atomic_json(best_path, pointer)
    else:
        per_run = STORE / ('best-' + run + '.json')
        incumbent = json.loads(per_run.read_text()) if per_run.exists() else None
        if incumbent is None or score <= incumbent['value']:
            atomic_json(per_run, pointer)
    destination = Path(path)
    if destination.exists():
        import shutil
        shutil.copy2(destination, STORE / 'models' / (stamp + '-previous-production.joblib'))
    # First recovered baseline is deployable; subsequent experiments require explicit promotion.
    if not destination.exists():
        import shutil
        tmp = destination.with_suffix('.tmp')
        shutil.copy2(archive, tmp)
        os.replace(tmp, destination)
    event('model_saved_reload_verified', **pointer)
    return pointer
