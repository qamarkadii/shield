from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'ml'))
import model


class TrainingExclusionTests(unittest.TestCase):
    def test_supplemental_rows_cannot_reintroduce_real_evaluation_owner(self):
        forbidden = 'evaltenant.netlify.app'
        real = pd.DataFrame([(forbidden, forbidden, True)], columns=['domain', 'owner', 'eval'])
        columns = ['domain', 'is_phishing', 'weight', 'source', 'owner']
        late = pd.DataFrame([(forbidden, 1, 1., 'unseen_train', forbidden)], columns=columns)
        empty = pd.DataFrame(columns=columns)
        synthetic = pd.DataFrame(columns=['domain', 'is_phishing', 'source'])
        train = pd.DataFrame({'domain': [f'benign{i}.com' for i in range(20)] + [f'bad{i}.com' for i in range(20)],
                              'is_phishing': [0]*20 + [1]*20})
        captured = {}
        class Done(Exception):
            pass
        class Capture:
            def __init__(self, frame, seed):
                pass
            def stage(self, name, compute):
                import inspect
                local = inspect.currentframe().f_back.f_locals
                captured.update({k: local[k] for k in ('fit', 'hold')})
                raise Done()
        with patch('recovery.Run', Capture), patch.object(model, 'load_ranks', return_value={}), \
             patch.object(model, 'load_eval_sets', return_value=(train.iloc[:1], train.iloc[:0], train.iloc[:0])), \
             patch.object(model, 'detect_platforms', return_value={'netlify.app'}), \
             patch.object(model, 'held_out_owners', return_value={'reserved.com'}), \
             patch.object(model, 'real_legit_hostnames', return_value=real), \
             patch.object(model, 'real_uae_train', return_value=empty), \
             patch.object(model, 'unseen_train', return_value=late), \
             patch.object(model.synth_uae, 'generate', return_value=synthetic):
            with self.assertRaises(Done):
                model.build(train, log=lambda _: None)
        self.assertNotIn(forbidden, set(captured['fit'].owner) | set(captured['hold'].owner))


if __name__ == '__main__':
    unittest.main()
