# Shield risk model — model card

Trained 2026-11-01 19:55:38 UTC on 323,235 rows (772 s). Generated automatically by `ml/train_baseline.py`.

## Data

- Base: `data/shield_training_domains.csv` (PhiUSIIL 2024, CC BY 4.0; Phishing.Database, MIT; top-10k list): 269,935 rows used.
- **Real legitimate hostnames** (Cisco Umbrella top-1M under Tranco top-100k sites, plus popular hosting tenants): 39,834.
- **Synthetic UAE impersonations** (`ml/synth_uae.py`, training only, never evaluated on): 3,000.
- Analyst labels (weight ×25): 0. Fresh feed domains: 0.
- **Leakage removed:** 6,330 training rows whose *owner* (registered domain, or tenant on one of 131 detected hosting platforms) appears in an evaluation set. All splits keep each owner on one side.
- Test: `data/shield_test_domains.csv` (10,000, 50/50). UAE: `data/uae_phishing_domains_real.csv` (66 real fakes).

## Method

1. **Text model**: character 2–5-grams + logistic regression, C=4.0 (tuned on a grouped split). 5-fold out-of-fold scores (folds by owner) feed the combiner; the final text model uses all rows.
2. **Ending risk**: learned, smoothed phishing log-odds per ending (out-of-fold too).
3. **Combiner**: `gradient_boosting` (kept for lower held-out log-loss; scores: gradient_boosting {'holdout_log_loss': 0.2985, 'holdout_auc': 0.9354}; logistic_regression {'holdout_log_loss': 0.3058, 'holdout_auc': 0.9317}). Gradient boosting uses monotonic constraints: brand/hosting signs can only raise risk, popularity only lower it.
4. **Held-out slice** (46,469 real rows, separate owners): *Suspicious* / *High risk* cut-offs at 3% / 0.5% false alarms on its legitimate domains, and Platt calibration of the score.

**Score** = 100 × calibrated probability if half of all domains were phishing (for ranking). **live_probability** = the same at the expected live rate (1%). The **level** is the decision.

## Learned effects

Average effect on the log-odds on held-out rows where the sign is present (model with vs. without it).

| Warning sign | Present in | Avg effect (log-odds) | Odds × |
|---|---|---|---|
| Text model score (character patterns), log-odds | 100.0% | 0.416 | 1.52× |
| Registered name is the brand re-spelled (emirates-post.org) | 0.1% | 1.528 | 4.61× |
| Brand + lure word on a domain the brand doesn't own (salik-pay) | 0.1% | 1.049 | 2.85× |
| Brand placed in front of an unrelated domain (aramex.valeriair.com) | 1.2% | 1.617 | 5.04× |
| Brand written with look-alike characters (sa1ik, Cyrillic letters) | 0.0% | 4.068 | 58.44× |
| Brand name with other words, no lure (could be a partner/fan site) | 0.9% | 0.266 | 1.3× |
| '.ae' / 'gov' inside a foreign domain | 0.0% | 1.749 | 5.75× |
| Learned risk of the ending (.xyz, .top ...) | 99.8% | -0.249 | 0.78× |
| Free hosting / site-builder | 14.5% | 0.008 | 1.01× |
| 3+ hyphens | 3.9% | -0.232 | 0.79× |
| Lure word (login, pay, verify ...) | 3.2% | 0.326 | 1.39× |
| 3+ subdomain levels | 3.4% | 0.229 | 1.26× |
| 3+ digits in the name | 3.1% | 0.177 | 1.19× |
| Non-Latin letters (xn--) | 0.1% | 0.186 | 1.2× |
| Random-looking letters (entropy) | 99.8% | 0.241 | 1.27× |
| Name length | 94.2% | 0.092 | 1.1× |
| Long consonant run | 57.0% | 0.108 | 1.11× |
| Owner is a popular site (Tranco rank) | 20.4% | -2.268 | 0.1× |

## Results (never used in training, thresholds or calibration)

AUC: **0.943** · Brier score (calibration): 0.0883

| Level | Precision (50/50 test) | **Precision at 1% phishing** | Recall [95% CI] | F1 | False-positive rate [95% CI] |
|---|---|---|---|---|---|
| Suspicious or higher | 0.967 | **0.226** | 0.804 [0.793, 0.815] | 0.878 | 2.78% [0.024, 0.033] |
| High risk | 0.996 | **0.704** | 0.708 [0.695, 0.72] | 0.827 | 0.30% [0.002, 0.005] |

Confusion at Suspicious: TP 4020, FP 139, TN 4861, FN 980.

False alarms on legitimate names (Suspicious or higher / High risk):

- Legit test domains that are **not** popular sites (4,029): 3.43% / 0.37%
- Legit test domains written as hostnames with **unseen** subdomains (careers., console. ...): 3.34% / 0.36%
- **Real** legitimate hostnames of owners never trained on (42,284): 2.01% / 0.87%; of which on hosting platforms (565): 46.02%

66 real UAE fakes, **model alone**: 57 High risk, 6 Suspicious, 3 missed (detection 95% CI [0.875, 0.984]; missed: acm1.eim.ae.iwc.static.c11n.all.sirija.indramayukab.go.id, acm2.eim.ae.iwc.static.normoeagles.com.au, aramexaeo3.temp.swtest.ru). *Development set: these were looked at while designing the rules, so this is optimistic.*

**Full app (model + labelled UAE-impersonation rules)**: 57 High risk, 9 Suspicious, 0 missed; legit test flagged 2.78%, legit hostnames flagged 3.04%.

Sanity examples: `react-docs.vercel.app` high risk (95); `my-portfolio.netlify.app` high risk (99); `team-blog.github.io` high risk (98); `eu-west-1.console.aws.amazon.com` no warning signs (0); `a1b2c3.cloudfront.net` no warning signs (0); `careers.dubaiholding.com` high risk (91); `login.microsoftonline.com` no warning signs (35); `shop.alfuttaim.ae` no warning signs (29); `bestpizza-dubai.com` no warning signs (66); `emirates-post.org` high risk (96); `aramex.valeriair.com` high risk (99); `salik-pay.com` high risk (98); `xn--slik-53d.com` high risk (99)

## Limits

- Looks at the domain name only (plus popularity). A fake with an innocent-looking name and no brand can be missed.
- Domain age, certificate issuer, DNS and page content are not used yet: the public training lists don't have them.
- Popularity helps a lot but is partly an artefact of how the legit set was built (top-sites list); see the 'not popular' row.
- Precision at 1% is an estimate from test recall and false-alarm rate; the real live rate is unknown.
- Labels come from public lists, which contain some errors; synthetic UAE fakes follow known patterns only.
- Not yet evaluated on a live UAE pilot.
