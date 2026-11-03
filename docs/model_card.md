# Shield risk model — model card

Trained 2026-11-03 07:21:34 UTC on 425,414 rows (194 s). Generated automatically by `ml/train_baseline.py`.

## Data

- Base: `data/shield_training_domains.csv` (PhiUSIIL 2024, CC BY 4.0; Phishing.Database, MIT; top-10k list): 269,799 rows used.
- **Real legitimate hostnames** (Cisco Umbrella top-1M under Tranco top-100k sites, plus popular hosting tenants): 39,877.
- **Synthetic UAE impersonations** (`ml/synth_uae.py`, training only, never evaluated on): 3,000.
- **Real UAE-targeted phishing** (`ml/collect_uae.py`, from ~2.5M public phishing records; train part only, weight ×5): 289.
- **Never-in-base data** (`ml/build_unseen.py`: newer/older phishing lists, Tranco sites ranked 250k–1M and .ae sites; train part only): 119,965.
- Analyst labels (weight ×25): 0. Fresh feed domains: 0.
- **Leakage removed:** 6,466 training rows whose *owner* (registered domain, or tenant on one of 131 detected hosting platforms) appears in an evaluation set. All splits keep each owner on one side.
- Test: `data/shield_test_domains.csv` (10,000, 50/50). UAE: `data/uae_phishing_domains_real.csv` (66 real fakes).

## Method

1. **Text model**: character 2–5-grams + logistic regression, C=4.0 (tuned on a grouped split). 5-fold out-of-fold scores (folds by owner) feed the combiner; the final text model uses all rows.
2. **Ending risk**: learned, smoothed phishing log-odds per ending (out-of-fold too).
3. **Combiner**: `gradient_boosting` (kept for lower held-out log-loss; scores: gradient_boosting {'holdout_log_loss': 0.324, 'holdout_auc': 0.925}; logistic_regression {'holdout_log_loss': 0.3308, 'holdout_auc': 0.9225}). Gradient boosting uses monotonic constraints: brand/hosting signs can only raise risk, popularity only lower it.
4. **Held-out slice** (64,559 real rows, separate owners): *Suspicious* / *High risk* cut-offs at 3% / 0.5% false alarms on its legitimate domains, and Platt calibration of the score.

**Score** = 100 × calibrated probability if half of all domains were phishing (for ranking). **live_probability** = the same at the expected live rate (1%). The **level** is the decision.

## Learned effects

Average effect on the log-odds on held-out rows where the sign is present (model with vs. without it).

| Warning sign | Present in | Avg effect (log-odds) | Odds × |
|---|---|---|---|
| Text model score (character patterns), log-odds | 100.0% | 0.709 | 2.03× |
| Registered name is the brand re-spelled (emirates-post.org) | 0.1% | 1.642 | 5.17× |
| Brand + lure word on a domain the brand doesn't own (salik-pay) | 0.1% | 0.638 | 1.89× |
| Brand placed in front of an unrelated domain (aramex.valeriair.com) | 1.4% | 1.545 | 4.69× |
| Brand written with look-alike characters (sa1ik, Cyrillic letters) | 0.0% | 2.718 | 15.15× |
| Brand name with other words, no lure (could be a partner/fan site) | 0.8% | 0.408 | 1.5× |
| '.ae' / 'gov' inside a foreign domain | 0.0% | 1.779 | 5.92× |
| Learned risk of the ending (.xyz, .top ...) | 99.5% | -0.201 | 0.82× |
| Free hosting / site-builder | 15.8% | 0.068 | 1.07× |
| 3+ hyphens | 3.8% | -0.174 | 0.84× |
| Lure word (login, pay, verify ...) | 3.5% | 0.131 | 1.14× |
| 3+ subdomain levels | 2.2% | 0.361 | 1.43× |
| 3+ digits in the name | 4.2% | -0.085 | 0.92× |
| Non-Latin letters (xn--) | 0.1% | 0.0 | 1.0× |
| Random-looking letters (entropy) | 97.6% | 0.069 | 1.07× |
| Name length | 94.1% | 0.185 | 1.2× |
| Long consonant run | 56.1% | 0.013 | 1.01× |
| Owner is a popular site (Tranco rank) | 14.1% | -2.291 | 0.1× |

## Results (never used in training, thresholds or calibration)

AUC: **0.946** · Brier score (calibration): 0.0843

| Level | Precision (50/50 test) | **Precision at 1% phishing** | Recall [95% CI] | F1 | False-positive rate [95% CI] |
|---|---|---|---|---|---|
| Suspicious or higher | 0.981 | **0.345** | 0.784 [0.772, 0.795] | 0.871 | 1.50% [0.012, 0.019] |
| High risk | 0.999 | **0.874** | 0.684 [0.671, 0.697] | 0.812 | 0.10% [0.0, 0.002] |

Confusion at Suspicious: TP 3919, FP 75, TN 4925, FN 1081.

False alarms on legitimate names (Suspicious or higher / High risk):

- Legit test domains that are **not** popular sites (4,019): 1.84% / 0.12%
- Legit test domains written as hostnames with **unseen** subdomains (careers., console. ...): 3.62% / 0.38%
- **Real** legitimate hostnames of owners never trained on (45,575): 1.87% / 0.91%; of which on hosting platforms (477): 40.46%

66 real UAE fakes, **model alone**: 65 High risk, 1 Suspicious, 0 missed (detection 95% CI [0.945, 1.0]; missed: none). *Development set: these were looked at while designing the rules, so this is optimistic.*

**Full app (model + labelled UAE-impersonation rules)**: 65 High risk, 1 Suspicious, 0 missed; legit test flagged 1.50%, legit hostnames flagged 3.70%.

## Never-seen data (sites never used for training, thresholds or calibration)

*Dev* parts: numbers and mistakes are inspected to fix the logic. *Frozen* parts: only these totals are ever looked at.
Columns: Suspicious-or-higher / High risk, for the model alone and for the full app (model + labelled UAE rules).

| Set | n | Model alone | Full app | |
|---|---|---|---|---|
| Phishing, new lists (dev); AUC 0.9004 | 10,000 | 72.96% / 60.26% | 72.97% / 60.26% | caught |
| Legit small sites + .ae (dev) | 10,000 | 6.14% / 1.23% | 6.17% / 1.23% | false alarms |
|   of which legit .ae sites (dev) | 128 | 0.78% / 0.00% | 2.34% / 0.00% | false alarms |
| **Real UAE-targeted phishing (dev)** | 152 | 92.11% / 88.16% | 92.76% / 88.16% | caught |
|   UAE: brand (dev) | 55 | 100.00% / 96.36% | 100.00% / 96.36% | caught |
|   UAE: fake_ae (dev) | 21 | 95.24% / 95.24% | 100.00% / 95.24% | caught |
|   UAE: path (dev) | 17 | 35.29% / 17.65% | 35.29% / 17.65% | caught |
|   UAE: uae_lure (dev) | 59 | 100.00% / 98.31% | 100.00% / 98.31% | caught |
| Phishing, new lists (frozen); AUC 0.9038 | 10,000 | 73.65% / 60.62% | 73.65% / 60.62% | caught |
| Legit small sites + .ae (frozen) | 10,000 | 6.86% / 1.05% | 6.88% / 1.05% | false alarms |
|   of which legit .ae sites (frozen) | 192 | 2.08% / 0.00% | 3.12% / 0.00% | false alarms |
| **Real UAE-targeted phishing (frozen)** | 157 | 88.54% / 80.89% | 88.54% / 80.89% | caught |
|   UAE: brand (frozen) | 38 | 100.00% / 76.32% | 100.00% / 76.32% | caught |
|   UAE: fake_ae (frozen) | 29 | 100.00% / 96.55% | 100.00% / 96.55% | caught |
|   UAE: path (frozen) | 28 | 39.29% / 35.71% | 39.29% / 35.71% | caught |
|   UAE: uae_lure (frozen) | 62 | 98.39% / 96.77% | 98.39% / 96.77% | caught |

UAE categories: *brand* imitates a registered UAE brand; *fake_ae* puts 'ae' inside a foreign name; *uae_lure* a UAE place + lure word; *path* an innocent name whose link path names a UAE brand (only the link check can see that, so the model alone misses these by design).

Sanity examples: `react-docs.vercel.app` high risk (99); `my-portfolio.netlify.app` high risk (99); `team-blog.github.io` high risk (98); `eu-west-1.console.aws.amazon.com` no warning signs (0); `a1b2c3.cloudfront.net` no warning signs (0); `careers.dubaiholding.com` high risk (91); `login.microsoftonline.com` no warning signs (21); `shop.alfuttaim.ae` no warning signs (18); `bestpizza-dubai.com` no warning signs (55); `emirates-post.org` high risk (98); `aramex.valeriair.com` high risk (99); `salik-pay.com` high risk (97); `xn--slik-53d.com` high risk (99)

## Limits

- Looks at the domain name only (plus popularity). A fake with an innocent-looking name and no brand can be missed.
- The NAME model doesn't see domain age, certificate, DNS or page content. Those are added live by the facts model (`ml/train_facts.py`, see `ml/facts_report.json`) and the isolated page check, which can't be trained from the old lists.
- Popularity helps a lot but is partly an artefact of how the legit set was built (top-sites list); see the 'not popular' row.
- Precision at 1% is an estimate from test recall and false-alarm rate; the real live rate is unknown.
- Labels come from public lists, which contain some errors; synthetic UAE fakes follow known patterns only.
- Not yet evaluated on a live UAE pilot.

## Owner-audit correction

The older real-hostname diagnostic is not fully independent: reconstructed fitting data shares 18 owners with that diagnostic. Supplemental rows reintroduced them after the base purge. Primary test/fresh benchmark and fit/calibration have zero owner overlap. The future training pipeline now purges after all sources merge and asserts exclusion; existing weights were not retrained for this secondary diagnostic fix. See `audit/owner_split_audit.json`. Do not use the older real-hostname slice as an independent accuracy claim.
