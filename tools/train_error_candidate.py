"""Fit an error-focused combiner while reusing completed text-model fits.

Fresh ranking negatives are explicitly PROXY labels, never analyst labels.
Only a development subset is added to training. Frozen rows remain untouched.
"""
import copy
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
from unittest.mock import patch
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'ml'))

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import log_loss, roc_auc_score
from sklearn.model_selection import GroupKFold
from backend.app import riskmodel
import model
from recovery import Run, digest, publish


class Captured(Exception):
    pass


def main(source_arg=None):
    started = time.time()
    source = Path(source_arg) if source_arg else ROOT / 'ml/domain_model.joblib'
    baseline = joblib.load(source)
    old_run = ROOT / 'checkpoints/runs' / baseline['recovery_run']

    def saved(name):
        p = old_run / (name + '.joblib')
        meta = json.loads(p.with_suffix('.json').read_text())
        if digest(p) != meta['sha256']:
            raise RuntimeError('Corrupt baseline stage: ' + name)
        return joblib.load(p)

    # Recover the exact original preparation, not a new text-model fit. The old
    # trainer did not persist row order, so capture it and verify static columns.
    captured = {}

    class CaptureRun:
        def __init__(self, frame, seed):
            self.key = baseline['recovery_run']

        def stage(self, name, compute):
            closure = dict(zip(compute.__code__.co_freevars,
                               [cell.cell_contents for cell in compute.__closure__ or []]))
            captured.update(closure)
            if name == 'static_hold':
                raise Captured()
            if name != 'static_fit':
                raise RuntimeError('Unexpected preparation stage: ' + name)
            return saved(name)

    train = pd.read_csv(ROOT / 'data/shield_training_domains.csv')
    train['source'], train['weight'] = 'base', 1.
    try:
        with patch('recovery.Run', CaptureRun):
            model.build(train)
    except Captured:
        pass
    fit, hold = captured['fit'], captured['hold']
    if len(fit) != baseline['train_rows']:
        raise RuntimeError('Baseline preparation changed; cannot reuse OOF stages')
    static, suffixes = saved('static_fit')
    static_hold, hold_suffixes = saved('static_hold')
    # Verify ordering against deterministic row-level features before reuse.
    idx = np.linspace(0, len(fit)-1, 100, dtype=int)
    sample, sample_suffixes = model._static(fit.domain.iloc[idx], captured['ranks'], captured['platforms'])
    np.testing.assert_array_equal(static[idx], sample)
    assert [suffixes[i] for i in idx] == sample_suffixes
    y, w = fit.is_phishing.values, fit.weight.values
    X = static.copy()
    il, it = model.FEATURE_NAMES.index('ml_logit'), model.FEATURE_NAMES.index('tld_risk')
    _, T = saved('vectorizer')
    for k, (tr, va) in enumerate(GroupKFold(n_splits=5, shuffle=True, random_state=model.SEED).split(fit, groups=pd.factorize(fit.owner, sort=True)[0])):
        clf = saved(f'text_fold_{k}')
        X[va, il] = riskmodel.logit(clf.predict_proba(T[va])[:, 1])
        X[va, it] = model._tld_column([suffixes[i] for i in va],
            model.tld_table([suffixes[i] for i in tr], y[tr], w[tr]))
    del T
    _, _, Xhold, _ = riskmodel.predict(baseline, hold.domain)
    fresh = pd.read_csv(ROOT / 'data/independent_reserved.csv')
    dev = fresh[fresh.part == 'dev'].copy()
    dev['inner'] = ['validation' if zlib.crc32(('error-v1|' + o).encode()) % 10 < 3 else 'train' for o in dev.owner]
    extra = dev[dev.inner == 'train']
    validation = dev[dev.inner == 'validation']
    _, _, Xe, _ = riskmodel.predict(baseline, extra.domain)
    _, _, Xv, _ = riskmodel.predict(baseline, validation.domain)
    config = dict(source_sha256=digest(source), protocol='fresh-dev-owner-split-error-v1',
                  proxy_negative_weight=20., phishing_feed_weight=5., free_host_monotonic_constraint=0)
    run = Run(extra.assign(config=json.dumps(config, sort_keys=True)), 42)
    candidate = copy.deepcopy(baseline)
    candidate.pop('results', None)
    candidate['recovery_run'] = run.key
    constraints = [model.MONOTONIC.get(k, 0) if k != 'free_host' else 0 for k in model.FEATURE_NAMES]
    combiner = model._combiners(42)['gradient_boosting'].set_params(monotonic_cst=constraints)
    combined_y = np.r_[y, extra.is_phishing.values]
    combined_w = np.r_[w, np.where(extra.is_phishing.values == 0, 20., 5.)]
    candidate['combiner'] = run.stage('error_combiner', lambda: model._fit(
        combiner, np.vstack([X, Xe]), combined_y, combined_w))
    candidate['combiner_kind'] = 'gradient_boosting'
    ph = candidate['combiner'].predict_proba(Xhold)[:, 1]
    yh = hold.is_phishing.values
    platt = LogisticRegression(C=1e6, max_iter=1000).fit(riskmodel.logit(ph).reshape(-1, 1), yh)
    candidate['calib'] = dict(a=float(platt.coef_[0][0]), b=float(platt.intercept_[0]), prevalence=float(yh.mean()))
    candidate['raw_thresholds'] = dict(suspicious=float(np.quantile(ph[yh == 0], .97)),
                                       high=float(np.quantile(ph[yh == 0], .995)))
    candidate['thresholds'] = {k: float(riskmodel.calibrated(candidate, np.array([v]))[0])
                               for k,v in candidate['raw_thresholds'].items()}
    candidate['combiner_scores'] = {'gradient_boosting': dict(
        holdout_log_loss=float(log_loss(yh, ph)), holdout_auc=float(roc_auc_score(yh, ph)))}
    candidate['weights'] = model.effects_table(candidate, Xhold, yh)
    candidate['error_training'] = dict(config, rows=len(extra),
        proxy_negative_rows=int((extra.is_phishing == 0).sum()), feed_positive_rows=int(extra.is_phishing.sum()),
        analyst_labels=0, validation_rows=len(validation), text_model='frozen baseline; OOF fits reused')
    candidate['trained_at'] = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
    candidate['seconds'] = round(time.time() - started)
    candidate['text_train_rows'] = baseline['train_rows']
    candidate['train_rows'] = len(fit) + len(extra)
    candidate['data_summary']['proxy_hard_negatives'] = int((extra.is_phishing == 0).sum())
    candidate['data_summary']['fresh_feed_augmented'] = int(extra.is_phishing.sum())
    comparison = {}
    for name, b in [('baseline', baseline), ('candidate', candidate)]:
        pv = b['combiner'].predict_proba(Xv)[:, 1]
        slices = {}
        for label, mask in [('phishing', validation.is_phishing.values == 1),
                            ('proxy_legitimate', validation.is_phishing.values == 0),
                            ('hosting_proxy_legitimate', validation.source.values == 'umbrella_hosting_proxy_legit')]:
            slices[label] = {'n': int(mask.sum()), **{level: float((pv[mask] >= th).mean()) if mask.any() else None
                                                      for level, th in b['raw_thresholds'].items()}}
        comparison[name] = slices
    # Predeclared development gate; frozen never selects candidate configuration.
    a, b = comparison['baseline'], comparison['candidate']
    passes = all(b['proxy_legitimate'][level] < a['proxy_legitimate'][level] and
                 b['phishing'][level] >= a['phishing'][level] - .05 for level in ('suspicious', 'high'))
    receipt = publish(candidate, source)  # archive only; preserve production
    output = dict(receipt=receipt, training=candidate['error_training'], inner_validation=comparison,
                  development_gate_passed=passes, promoted=False,
                  caveat='Ranking-based negatives are proxies. This experiment is not analyst-supervised or a live UAE pilot.')
    (ROOT / 'audit/error_candidate.json').write_text(json.dumps(output, indent=2))
    print(json.dumps(output, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--model')
    args = parser.parse_args()
    main(args.model)
