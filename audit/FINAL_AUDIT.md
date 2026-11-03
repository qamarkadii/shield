# Shield audit and experiment outcome

3 November 2026. **The detector still has a material false-alarm problem. The error-focused model was trained and tested, but was not promoted.** The recovery/checkpoint system is implemented separately from that accuracy conclusion.

## Actual experiment

The uploaded ZIP omitted all trained weights and the original review DB. A baseline was therefore recovered by training the existing architecture, preserving its source/data and adding checkpoints. It used 425,414 fitting rows, 64,559 internal holdout rows, text C=4, five owner-grouped OOF fits, a final text fit, and a 400-iteration histogram gradient boosting combiner. All five optimized owner splits matched the original membership on every fitting row. No neural optimizer/epochs exist in this sklearn batch architecture.

The error-focused candidate reused the completed text fits and their valid OOF predictions. It added 1,257 development rows: 1,167 ranking-based proxy negatives (weight 20) and 90 fresh phishing-feed positives (weight 5). It removed the constraint that free hosting can only raise risk. Another 579 development rows were reserved for inner validation. **Zero analyst labels** were invented or used. Candidate configuration was fixed before frozen evaluation.

## Fresh frozen test — measured, not inferred from the old report

One timestamped OpenPhish/Tranco/Umbrella snapshot, whole owners excluded from baseline fitting/calibration, deterministic dev/frozen assignment. Frozen: **55 phishing examples, 574 ranked-site proxy negatives, 123 hosting proxy negatives**. Rankings/traffic are not analyst-verified legitimacy; these results diagnose source shift and do not establish deployment accuracy. Confidence intervals are recorded in the JSON reports; the phishing sample is small.

| Metric | Recovered baseline | Error-focused candidate |
|---|---:|---:|
| Phishing recall, Suspicious+ | 45/55 = 81.8% | 45/55 = 81.8% |
| Phishing recall, High risk | 42/55 = 76.4% | 39/55 = 70.9% |
| Ranked-site proxy false alarms, Suspicious+ | 33/574 = 5.75% | 35/574 = 6.10% |
| Ranked-site proxy false alarms, High risk | 7/574 = 1.22% | 8/574 = 1.39% |
| Hosting proxy false alarms, Suspicious+ | 113/123 = 91.9% | 70/123 = 56.9% |
| Hosting proxy false alarms, High risk | 102/123 = 82.9% | 29/123 = 23.6% |

The candidate reduced hosting alarms substantially in this sample, but missed three additional high-risk phishing cases and worsened ranked-site false alarms slightly. Its original internal holdout log-loss also worsened (.33048 versus .324). It is retained as an experiment, not a replacement for the baseline. This frozen result is now historical; do not tune further on it and keep calling it unseen.

The user's examples remain a failure: baseline `react-docs.vercel.app` = High risk/99 and `careers.dubaiholding.com` = High risk/91. Candidate = Suspicious/91 and High risk/93 respectively. **These were not fixed by changing the scores or adding handpicked allowlist entries.** See `error_examples_comparison.json`.

## Additional owner-audit finding

The older real-hostname diagnostic is not fully independent: reconstructed fitting data shares 18 owners with that diagnostic. Supplemental rows reintroduced them after the base purge. Primary test/fresh benchmark and fit/calibration have zero owner overlap. The future training pipeline now purges after all sources merge and asserts exclusion; existing weights were not retrained for this secondary diagnostic fix. The current fitted-model audit is `owner_split_audit.json`; future current-source preparation checks write a separate file. A regression test verifies that supplemental rows cannot reintroduce evaluated owners.

## Errors actually repaired

- Invalid `ml/retrain.py` syntax, missing feed parser and duplicated broken tail.
- Missing persistent model/stage checkpointing, versioned candidates, latest/best tracking, exact prediction reload checks and portable backups.
- Quadratic owner-string comparisons in shuffled GroupKFold. Numeric codes preserve exact folds; the saved first fit was reused rather than repeated.
- Slow full-app evaluation computed 18 feature explanations per domain. Batch evaluation was checked against actual serving decisions; no training was repeated during finalization.
- Unreachable official-domain exemption in the domain evaluator.
- Full-URL checks missed encoded paths and short brands. Added decoded paths and exact short-brand action-context matches; unsupported URL schemes are rejected.
- Failed/empty page capture returned **“nothing found”**. It now returns **“not checked.”** Regression tests cover timeout, empty output and empty error text.
- Website performance was hardcoded to an old model. It now obtains metrics and the loaded model's SHA-256 from `/api/model-status`, distinguishes balanced tests from fresh-source results, shows confidence intervals/proxy-label limits, and displays an unavailable state instead of stale numbers. Feature count corrected to 18.
- Docker no longer unconditionally discards packaged weights and retrains. `tools/ensure_model.py` restores existing weights/checkpoints first. Docker image build itself was not run.

## URL/page evidence limits

The old report's “full app” path category evaluated domains, not complete URLs. A separate **rule-only** test, with ML and known-feed membership disabled, flagged 17/17 development and 28/28 frozen source path URLs. It also flagged 2/6 deliberately benign reference/partner cases. Those small/regression samples are not a deployment false-positive estimate. A brand mention alone remains weak evidence.

A benign `example.com` page-check smoke test was refused by the environment's DNS/public-address guard. Actual page rendering was therefore **not** verified here. The guard was not weakened. Screenshot similarity is not a validated visual phishing model, and a subprocess is not a production VM sandbox.

## Impact and creativity judgment

**4/10 as a hackathon solution; 2/10 for demonstrated prevention impact; 3/10 for originality.** The project implements meaningful triage components, but has not demonstrated an authorized takedown/blocking channel, reviewed alert yield, lead time before independent feeds, prevented loss, or a UAE pilot. A globe, chatbot and domain checker do not establish a distinctive product advantage. The main page still leads with team branding and simulated signals.

The strongest next direction is one narrow, measurable operation: give a consenting UAE bank/brand a reviewed campaign evidence bundle, record its action and resolution time, and prospectively measure feed lead time and missed cases. Shared IP/registrar/brand alone must not be treated as proof of a campaign. Even beating a feed does not prove a scam message had not been sent.

Detailed design critique: `PRODUCT_REVIEW.md`. Review/learning protocol: `../docs/REVIEW_PROTOCOL.md`. Neither document is a claim that these operational integrations already exist.

## Reproducible evidence

`independent_baseline.json`, `independent_candidate.json`, `error_candidate.json`, `error_examples_comparison.json`, `url_rules_evaluation.json`, `recovery_verification.json`, `batch_serving_parity.json`, `baseline_evaluation_complete.json`, `regression-tests.txt`, `frontend-build.log`, `split_equivalence.json`, source download manifests, and `checkpoints/history.jsonl`.

The local services remain prototypes with radar off. No real alert, takedown request, citizen label or cloud upload was fabricated.
