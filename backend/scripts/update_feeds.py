"""
Download the newest public phishing feeds into data/feeds/
(OpenPhish + Phishing.Database). Used by the link check ("already listed as
phishing") and by retraining.

Run from the repo folder:   python backend\\scripts\\update_feeds.py
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from ml.retrain import download_feeds  # noqa: E402

for name, status in download_feeds().items():
    print(f"{name}: {status}")
