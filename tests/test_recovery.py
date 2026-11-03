import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'ml'))

import numpy as np
import pandas as pd
import recovery
from backend.app import linkcheck


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        # Test checkpoints must never update the real project's handoff files.
        self.events = patch.object(recovery, 'event')
        self.events.start()
        self.addCleanup(self.events.stop)

    def test_completed_stage_is_reloaded_and_corruption_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'audit') as folder:
            with patch.object(recovery, 'STORE', Path(folder)):
                run = recovery.Run(pd.DataFrame({'domain': ['example.com'], 'is_phishing': [0]}), 42)
                first = run.stage('unit', lambda: np.array([1., 2.]))
                with patch.object(recovery.joblib, 'load', wraps=recovery.joblib.load) as loader:
                    second = run.stage('unit', lambda: self.fail('completed stage recomputed'))
                    self.assertEqual(loader.call_count, 1)
                np.testing.assert_array_equal(first, second)
                (run.path / 'unit.joblib').write_bytes(b'corrupted')
                with self.assertRaisesRegex(RuntimeError, 'corrupted'):
                    run.stage('unit', lambda: None)

    def test_input_changes_create_different_runs(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'audit') as folder:
            with patch.object(recovery, 'STORE', Path(folder)):
                a = recovery.Run(pd.DataFrame({'domain': ['example.com']}), 42)
                b = recovery.Run(pd.DataFrame({'domain': ['other.example']}), 42)
                self.assertNotEqual(a.key, b.key)

    def test_competing_fit_is_refused_instead_of_recomputed(self):
        from filelock import FileLock, Timeout
        with tempfile.TemporaryDirectory(dir=ROOT / 'audit') as folder:
            with patch.object(recovery, 'STORE', Path(folder)):
                run = recovery.Run(pd.DataFrame({'domain': ['example.com']}), 42)
                with FileLock(str(run.path / '.training.lock')):
                    with self.assertRaises(Timeout):
                        run.stage('must_not_fit', lambda: self.fail('competing fit ran'))

    def test_fitted_estimator_prediction_survives_resume(self):
        from sklearn.linear_model import LogisticRegression
        X = np.array([[0., 0.], [1., 0.], [0., 1.], [1., 1.]])
        y = np.array([0, 0, 1, 1])
        with tempfile.TemporaryDirectory(dir=ROOT / 'audit') as folder:
            with patch.object(recovery, 'STORE', Path(folder)):
                run = recovery.Run(pd.DataFrame({'domain': ['example.com']}), 42)
                fitted = run.stage('classifier', lambda: LogisticRegression(random_state=42).fit(X, y))
                resumed = run.stage('classifier', lambda: self.fail('classifier refitted'))
                np.testing.assert_allclose(fitted.predict_proba(X), resumed.predict_proba(X), rtol=0, atol=0)

    def test_feed_parser(self):
        import retrain
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / 'openphish.txt').write_text('# comment\nhttps://www.example.com/pay\n\n')
            with patch.object(retrain, 'FEEDS', folder):
                self.assertEqual(retrain._read_feed_domains(), {'example.com'})

    def test_encoded_and_short_brand_paths(self):
        self.assertIsNotNone(linkcheck.path_brand('/%73%61%6c%69%6b/pay'))
        self.assertIsNotNone(linkcheck.path_brand('/adcb/verify'))
        self.assertIsNotNone(linkcheck.path_brand('/rta/pay'))
        self.assertIsNone(linkcheck.path_brand('/articles/rta/transport-history'))
        self.assertIsNone(linkcheck.path_brand('/myrtaexample/payment'))

    def test_unsupported_scheme_rejected(self):
        self.assertIn('error', linkcheck.check_link('file://example.com/path'))

    def test_failed_or_empty_page_capture_never_returns_clean_verdict(self):
        from backend.app import pagecheck
        for capture in ({'error': 'timeout'}, {}, {'error': ''}):
            result = pagecheck.analyse(capture, 'example.com')
            self.assertEqual(result['verdict'], 'not checked')
            self.assertFalse(result['opened'])

    def test_model_identity_describes_loaded_bytes_until_reload(self):
        import hashlib
        import joblib
        from backend.app import scoring, riskmodel
        with tempfile.TemporaryDirectory(dir=ROOT / 'audit') as folder:
            path = Path(folder) / 'model.joblib'
            bundle = dict(version=riskmodel.BUNDLE_VERSION, trained_at='first', thresholds={}, weights={})
            joblib.dump(bundle, path)
            first_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            with patch.object(scoring, '_MODEL_PATH', str(path)), patch.object(scoring, '_model', None), patch.object(scoring, '_model_sha256', None):
                self.assertEqual(scoring.model_info()['model_sha256'], first_hash)
                joblib.dump(dict(bundle, trained_at='second'), path)
                self.assertEqual(scoring.model_info()['model_sha256'], first_hash)
                scoring.reload_model()
                self.assertNotEqual(scoring.model_info()['model_sha256'], first_hash)
                self.assertEqual(scoring.model_info()['trained_at'], 'second')

    def test_default_chat_never_calls_external_provider(self):
        from backend.app import chat
        with patch.dict('os.environ', {'SHIELD_EXTERNAL_CHAT_ENABLED': '0'}), patch.object(chat.requests, 'post') as post:
            events = [json.loads(line) for line in chat.run(
                [{'role': 'user', 'content': 'How can I check a message?'}], lambda r: r)]
        post.assert_not_called()
        self.assertEqual(events[-1]['type'], 'done')
        self.assertIn('External chat is disabled', events[0]['text'])

    def test_known_feed_not_required_for_url_review(self):
        blank = {'domain': 'innocent.example', 'registered_domain': 'innocent.example',
                 'score': 1, 'verdict': 'no warning signs', 'brand': None,
                 'reasons': [], 'signals': [], 'rule': None}
        with patch.object(linkcheck, 'score_domain', return_value=blank.copy()), patch.object(linkcheck, '_known', set()):
            result = linkcheck.check_link('https://innocent.example/adcb/verify')
        self.assertEqual(result['verdict'], 'suspicious')
        self.assertFalse(result['known_phishing'])


if __name__ == '__main__':
    unittest.main()
