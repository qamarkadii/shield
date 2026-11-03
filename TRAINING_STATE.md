# Shield training state

Updated 3 November 2026. **The supplied ZIP contains reports but no weights.** Do not confuse historical reports with this session's experiments. Read `checkpoints/status.json` and `history.jsonl` for the latest actual stage.

## Architecture / configuration
Python 3.12; scikit-learn, NumPy, pandas, scipy, joblib. Domain text: character TF-IDF 2–5 grams, `min_df=3`, `max_features=300000`, sublinear TF, logistic regression `max_iter=2000`; C candidates 1, 4, 16. Five owner-grouped OOF folds; final text refit. Suffix phishing log-odds with smoothing 50. Feature combiner candidates: histogram gradient boosting (400 maximum iterations, learning rate .06, 31 leaves, minimum 40 samples/leaf, L2=1, early stopping with .1 validation and patience 25, monotonic constraints) versus standardized logistic regression C=1/max_iter=3000. Choose internal holdout log-loss. Platt logistic calibration C=1e6/max_iter=1000.

Main seed 42; retrain sampling seed 7; facts seed 3. Real-hostname/synthetic generators have their own explicit seeds; inspect `ml/common.py`, `ml/synth_uae.py`. Thresholds target internal legitimate FPR 3% and .5%, not guaranteed deployment FPR. Live prevalence .01 is assumed. Display score is calibrated at 50% prevalence; it is not the real-world phishing probability.

Facts model: logistic regression C=1, max_iter=2000, balanced classes, input name log-odds plus `FACT_NAMES`. Requires fresh online DNS/registration cache and training snapshots not all shipped in the ZIP. Do not silently re-create a different facts experiment and call it a reproduction.

## Supplied datasets and preprocessing
- `data/shield_training_domains.csv`: 276,270 unique domains, 138,131 positive / 138,139 negative.
- `data/shield_test_domains.csv`: 10,000, balanced, fixed evaluation.
- `data/unseen_train.csv`: 120,000, balanced; distinct from 20,000-row `unseen_dev.csv` and 20,000-row `unseen_frozen.csv`.
- `data/uae_phishing_domains_real.csv`: 66 development examples previously inspected during rule design, not an unbiased test.
- `data/uae_phishing_collected.csv`: 670, explicit train/dev/category/source metadata.
- `data/uae_test_frozen.csv`: 238 source rows. Existing evaluator excludes `uae_plain`.
- `data/phiusiil_urls_labeled.csv`: 235,795 source URL rows; source labels, not newly reviewed citizen outcomes.
- `data/facts_owners.txt`: owners excluded to keep facts-model name scores out of sample.

Domains are normalized with `features.clean`. Owner grouping uses the public suffix list plus private hosting tenants/detected platforms. Remove all evaluation owners before fitting. Add real Umbrella hostnames, synthetic training-only UAE impersonations, collected real UAE train examples weight 5, unseen-train examples, and legitimate subdomain augmentation (50% of eligible base legit rows). Analyst examples weight 25 only if real analyst labels exist. Holdout = 15% owner groups from real rows, used for selection, thresholds and calibration; therefore calibration error on it is optimistic.

## Initial evidence and current reports
`ml/model_report.json` is now the newly recovered baseline report. Original reports remain in the untouched ZIP/early backup; `ml/unseen_report.json` and `ml/facts_report.json` retain historical source evidence. Unseen-frozen domain-only app: recall .7369/.5969, FPR .0644/.0096. At assumed 1% phishing: projected precision .1036/.3858. Old frontend metrics are a different earlier hardcoded snapshot. Do not train on frozen sets, select thresholds from them, or present source proxy labels as analyst ground truth.

## Current recovery state

**Additional owner audit:** The older real-hostname diagnostic is not fully independent: reconstructed fitting data shares 18 owners with that diagnostic. Supplemental rows reintroduced them after the base purge. Primary test/fresh benchmark and fit/calibration have zero owner overlap. The future training pipeline now purges after all sources merge and asserts exclusion; existing weights were not retrained for this secondary diagnostic fix.


The baseline and error-focused candidate are trained, saved and reload-verified. Training is COMPLETE; do not restart it to restore this project. Corrected evaluation was finished from saved weights without fitting again. Read `audit/FINAL_AUDIT.md` first.

The candidate was NOT promoted. Frozen hosting High-risk proxy false alarms fell from 82.9% to 23.6%, but High-risk phishing recall fell from 76.4% to 70.9%, ranked-site false alarms rose slightly, and the Dubai Holding careers example remains wrong. These are small-source/proxy-label results, not proof of deployment accuracy. No analyst labels were fabricated. This is still a prototype with unresolved false alarms, no validated prevention outcome and no action partner.

- Serving baseline: `ml/domain_model.joblib`, SHA-256 `66c0ff1b8b8bd2dde1a325ca65f70600246adaf313af7476229f1ded6aafb9dd`.
- Best baseline archive by original internal validation loss: `checkpoints/models/20261103T073450Z-a7987f63.joblib`; `checkpoints/best.json` records its hash. It has the same classifier weights with finalized report metadata.
- Error candidate: `checkpoints/models/20261103T072930Z-9f600af3.joblib`, SHA-256 `ffddfd1e65e66e994ea44a9b1687f5d4bb921ce6e6192e33a3ed52bb4bef17b9`.
- `checkpoints/serving.json` records the exact serving archive using a portable relative path. `audit/error_candidate.json` records the rejected promotion decision. All prior models/stages are retained.
- Fifteen regression tests passed; frontend TypeScript/Vite build passed; browser verified both thresholds, model identity and fresh-source results. `audit/batch_serving_parity.json` verifies 16 batch/serving decisions match, including official domains.
- Failed/empty page captures now return `not checked`. A benign smoke test was refused by DNS/public-address validation; actual browser capture was not verified and the guard was not weakened.
- `tools/ensure_model.py` verifies/restores weights without retraining. Docker now preserves packaged weights and calls that tool; Docker image build was not tested.
- Local app: public `http://127.0.0.1:8001`, analyst `http://127.0.0.1:8000`, radar OFF. External chat remains opt-in. No real alerts or cloud uploads were sent.
- Full portable backup/restore instructions: `BACKUP_AND_RESTORE.md`. Final archive receipts are in `../recovery/`; inspect the newest verified receipt rather than assuming an early archive contains the final weights.

### Completed experiments
Baseline: 425,414 fit rows, 64,559 internal holdout, five OOF text fits plus final text fit, C=4; 400 boosting iterations; internal loss .324/AUC .925; fixed balanced-test AUC .946, recall .784/.684 and FPR .015/.001 for Suspicious+/High. Data were owner-purged; 6,466 supplied rows were removed.

Error candidate: frozen baseline text model and valid OOF predictions reused; 1,257 added dev rows (1,167 proxy negatives weight 20, 90 feed positives weight 5), 579 inner-validation rows, free-host monotonic constraint removed. Internal loss worsened to .330483. Frozen results and CIs are in `audit/independent_candidate.json`; paired summary in `audit/FINAL_AUDIT.md`. No further candidate tuning followed frozen evaluation. Candidate rejected for promotion; artifacts retained. `tools/adapt_thresholds.py` exists but was NOT run and is not a completed experiment.

All exact estimator iteration counts are recorded in `audit/training_iterations.json`. sklearn batch estimators expose no mid-fit optimizer resume here; complete estimator state is serialized per finished fit. No neural epochs or fictitious optimizer checkpoint is claimed. Latest stage/model pointers and full history are in `checkpoints/`.

## Restore / resume exactly
From this project folder in PowerShell:
```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
# If no lock exists yet, use requirements.txt and record the resolved versions.
.\.venv\Scripts\python.exe tools\audit_data.py
.\.venv\Scripts\python.exe tools\ensure_model.py
```
Use the existing `.venv` if it works. In this machine the bundled Python path is `C:/Users/qamar/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe`; the WindowsApps `python.exe` alias does not run. UV is `C:/Users/qamar/.local/bin/uv.exe`. Dependencies may need network access; use workspace `uv-cache` rather than an inaccessible sandbox cache.

The same inputs/code restore completed stages automatically. Do not delete checkpoints to retry. Verify hashes in stage JSON sidecars. Run only one training process per project/checkpoint store at once. If a new code/dataset fingerprint is created, the old run remains recoverable; do not pretend it is compatible. Do not copy a checkpoint from an untrusted source: joblib deserialization executes Python objects.

The old `tools/resume_optimized.py` is a historical, verified compatibility path for the already-completed baseline. Do NOT run it now: subsequent evaluator/backend corrections changed code identity and it should refuse incompatible inputs. Restore existing complete models with `tools/ensure_model.py`; repeat corrected evaluation only with `tools/finalize_saved_model.py` (it reuses a matching completed evaluation). A deliberately new training run uses `ml/train_baseline.py` after defining new data/splits; unchanged future runs recover their own completed stages automatically.

Start application: `.\.venv\Scripts\python.exe run_shield.py`. Evaluate historical splits with `ml/eval_unseen.py` only when a model exists; set `SHIELD_REPORT_OUT` to a new audit path to preserve historical reports. New independent benchmark and new experiment metrics belong in `audit/` with provenance.

## Rejected approaches / known failures
- Error-focused candidate: hosting proxy alarms improved, but remain excessive; three additional frozen phishing cases lost High-risk status, ordinary ranked-site alarms rose slightly, and internal loss worsened. Not promoted.
- Page-capture smoke: DNS/public-address guard refused example.com. Capture remains unverified; do not weaken the guard to make a demo pass.
- Original `ml/retrain.py`: invalid syntax and missing feed parser; repaired; parser regression tests passed. The live Retrain button was not invoked to fabricate labels or start redundant training.
- Platform masking was already marked rejected in original model code: worsened free-host false alarms (historical claim, not rerun).
- Training on live detector predictions: invalid self-labelling, do not do it.
- Blanket hosting-platform allowlisting: would hide real phishing tenants.
- Reuse 50/50 precision as deployment precision: invalid under prevalence shift.
- Automatic overwrite of best/production on every retrain: replaced by immutable archives and explicit candidate promotion.
- An interrupted sklearn `.fit()` cannot resume its internal optimizer; checkpoint completed stages instead.

## Verified final backup

`../recovery/shield-checkpoint-20261103T080248330090Z.zip` (282 files; SHA-256 `a320cbdf6bd95992b4c652bf193a2dcaeaf884ddad8403c9c5bed0a84485946f`). All manifest hashes checked, restored to a separate directory, four checkpoint pointers rebased, serving weights deliberately moved aside and recovered automatically without fitting. Both baseline and candidate predictions matched exactly after restore. Keep the external `.json` receipt with the ZIP; it records the post-creation restore test. The restore used the existing verified Python environment. No cloud upload was performed.

<!-- AUTO_CHECKPOINT_STATUS -->

Latest automatic recovery event:
```json
{
  "last_event": "portable_backup_restore_verified",
  "archive": "../recovery/shield-checkpoint-20261103T080248330090Z.zip",
  "files": 282,
  "baseline_and_candidate_prediction_parity_exact": true,
  "automatic_model_recovery_without_training": true,
  "regression_tests_passed": 15,
  "cloud_upload": false
}
```
