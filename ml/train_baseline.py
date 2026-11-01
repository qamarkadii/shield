"""
Shield - baseline domain classifier (starting point for the ML person)

Setup:  pip install pandas scikit-learn
Run:    python ml\\train_baseline.py   (from the repo folder)

Trains on shield_training_domains.csv, tests on shield_test_domains.csv
(a different source, so the score is honest), then checks the 66 real
UAE-targeted fakes. Takes about 1-3 minutes.
"""

import os
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score
import joblib

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
MODEL = os.path.join(HERE, "domain_model.joblib")

train = pd.read_csv(os.path.join(DATA, "shield_training_domains.csv"))
test = pd.read_csv(os.path.join(DATA, "shield_test_domains.csv"))
uae = pd.read_csv(os.path.join(DATA, "uae_phishing_domains_real.csv"))

# Character n-grams: learns patterns like "-login", "secure-", "0" for "o"
vec = TfidfVectorizer(analyzer="char", ngram_range=(2, 5), min_df=3,
                      max_features=300000, sublinear_tf=True)
model = LogisticRegression(max_iter=2000, C=4)

print("Training on", len(train), "domains ...")
model.fit(vec.fit_transform(train.domain), train.is_phishing)

pred = model.predict(vec.transform(test.domain))
print(f"Test set ({len(test)} unseen domains, different source):")
print(f"  accuracy  {accuracy_score(test.is_phishing, pred):.3f}")
print(f"  precision {precision_score(test.is_phishing, pred):.3f}  (of flagged, how many were really phishing)")
print(f"  recall    {recall_score(test.is_phishing, pred):.3f}  (of real phishing, how many were caught)")

u_pred = model.predict(vec.transform(uae.domain))
print(f"\nReal UAE-targeted fakes caught: {u_pred.sum()}/{len(uae)}")
missed = uae[u_pred == 0]
if len(missed):
    print("Missed (these need the lookalike rules / visual check):")
    print(missed.to_string(index=False))

joblib.dump((vec, model), MODEL)
print("\nSaved model ->", MODEL)
