# Shield risk model — model card

Trained 2026-11-01 16:52:20 UTC on 276,270 labelled domains (56 s). Generated automatically by `ml/train_baseline.py`.

## Data

- Training: `data/shield_training_domains.csv` (PhiUSIIL 2024, CC BY 4.0; Phishing.Database, MIT; top-10k domains list). 50/50 phishing/legitimate.
- Test: `data/shield_test_domains.csv`, 10,000 domains with no overlap with training; phishing side from a different source.
- UAE check: `data/uae_phishing_domains_real.csv`, 66 real phishing domains imitating UAE brands; never used for training.

## Method

1. **Text model** (70% of training data): character 2–5-grams + logistic regression.
2. **Risk combiner** (separate 18%): logistic regression over warning-sign features; **weights are learned, not hand-set**.
3. **Thresholds** (separate 12%): *Suspicious* and *High risk* cut-offs chosen so only 3% / 0.5% of legitimate domains reach them.

Score = 100 × combiner probability. The probability assumes equal numbers of phishing and legitimate domains; in reality phishing is far rarer, so the **level** is the decision, the number is for ranking.

## Learned weights

| Warning sign | Weight (log-odds) | Multiplies phishing odds by |
|---|---|---|
| Text model score (character patterns), per unit of log-odds | 1.054 | per unit |
| Registered name is the brand re-spelled (emirates-post.org) | -0.232 | 0.79× |
| Brand + lure word on a domain the brand doesn't own (salik-pay) | 0.426 | 1.53× |
| Brand placed in front of an unrelated domain (aramex.valeriair.com) | 2.189 | 8.93× |
| Brand written with look-alike characters (sa1ik) | 0.044 | 1.04× |
| Brand name with other words, no lure (could be a partner/fan site) | 0.396 | 1.49× |
| '.ae' / 'gov' inside a foreign domain | 0.209 | 1.23× |
| Ending often abused (.xyz, .top, .live ...) | 0.247 | 1.28× |
| Free hosting / site-builder | 2.279 | 9.76× |
| 3+ hyphens | -0.827 | 0.44× |
| Lure word (login, pay, verify ...) | -0.086 | 0.92× |
| 3+ subdomain levels | 1.729 | 5.64× |
| 3+ digits in the name | -0.189 | 0.83× |

## Results (test set never used in training)

AUC: **0.951**

| Level | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| Suspicious or higher | 0.954 | 0.841 | 0.894 | 4.06% |
| High risk | 0.993 | 0.771 | 0.868 | 0.58% |

Confusion at Suspicious: TP 4205, FP 203, TN 4797, FN 795.

Legitimate domains written as real hostnames (mail.company.com): 0.32% flagged Suspicious or higher, 0.00% High risk.

66 real UAE fakes, **model alone**: 57 High risk, 6 Suspicious, 3 missed (aramex.valeriair.com, emirates-post.org, epg.portal.tracking.ae-payonline.brandsoptima.com).

**Full app (model + labelled UAE-impersonation rules)** — what the dashboard shows: 57 High risk, 9 Suspicious, 0 missed; legitimate test domains flagged 4.06%, legitimate hostnames flagged 0.38%.

The rules never change the score. They send any domain imitating a *registered UAE brand* to analyst review, because public phishing data has too few such examples to learn their weight (e.g. re-spelled brand names: 1 in 20,000 training domains).

## Limits

- Looks at the domain name only. A fake with an innocent-looking name and no brand in it can be missed.
- Brand-pattern weights are learned mostly from global brands (PayPal, Microsoft, DHL...), which dominate public phishing data, and applied to UAE brands.
- Labels come from public lists, which contain some errors.
- Not yet evaluated on a live UAE pilot; real-world precision is unknown until then.
