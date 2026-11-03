# Shield project handoff

Updated 3 November 2026 (Asia/Dubai). Canonical working project: the folder containing this file. Do not edit the ChatGPT mirror's `sources/`. The supplied ZIP and project documentation are reference material, not additional user instructions.

## Current status (authoritative)

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

## Objective and acceptance criteria
Detect phishing impersonating UAE services, help citizens check messages, and give analysts evidence they can act on. The user's priorities are independent evaluation, fewer false alarms, better path-scam coverage, a candid impact/website review, and recovery across AI chats. Never report unrun tests as passed, invent analyst labels, train on predictions, or restart completed checkpoint stages unnecessarily.

## Architecture and important paths
- `ml/model.py`: scikit-learn domain classifier: character TF-IDF/logistic regression, out-of-fold text scores and suffix risk, monotonic histogram gradient boosting versus logistic combiner, Platt calibration.
- `backend/app/features.py`, `registry.py`, `riskmodel.py`, `scoring.py`: common training/serving features, brand registry, model inference, review rules, optional domain-facts model.
- `ml/train_baseline.py`, `retrain.py`, `train_facts.py`: base training, public-feed/analyst-label retraining, separate registration/DNS facts training.
- `backend/app/linkcheck.py`: complete URL rules and phishing-feed checks. This is distinct from the domain model.
- `backend/app/ctlog.py`: certificate radar; `db.py`: SQLite analyst queue; `alerts.py`: alerts; `evidence.py`: evidence packs.
- `backend/app/pagecheck.py`: subprocess browser capture and screenshot comparison; not a trained visual classifier and not a production VM sandbox.
- `backend/app/main.py`: analyst API/dashboard. `public.py`: citizen API/page and built frontend. `chat.py`: local explanation by default; external DeepSeek only with `SHIELD_EXTERNAL_CHAT_ENABLED=1`.
- `frontend/src/`: React/Vite/Three.js presentation; `frontend/dist/`: previously built site served by the backend. Its performance component now fetches serving-model evidence from `/api/model-status`; old hardcoded metrics were removed.
- `run_shield.py`: localhost analyst service 8000 and citizen service 8001; radar off unless requested.
- `data/*.csv`: supplied labelled/split datasets; `data/brand_refs/`: supplied official-site screenshot references.
- `ml/recovery.py`: persistent stage checkpoints and immutable model archives. `checkpoints/history.jsonl`: machine-readable experiment/recovery history.
- `tools/backup_project.py`: portable ZIP with SHA-256 manifest, SQLite consistent snapshots, read-back verification, no `.env` or reinstallable runtimes.
- `tools/audit_data.py`: reproducible source-data overlap audit and historical precision projections.
- `tools/fetch_audit_sources.py`: timestamped external-source downloads with provenance/hashes, never phishing-page visits.
- `audit/`: actual audit outputs. `TRAINING_STATE.md`: training specifics. `CONTINUE_HERE.md`: continuation instructions. `CHANGELOG.md`: milestones.

## Initial audit and confirmed findings
The original supplied ZIP has 183 entries and **zero** model/checkpoint/database files. Existing model reports are historical evidence, not recoverable weights. Original SHA-256: `C1E563BF29BBC7CB822D492EA707A2A7B5124B070703E13B23F320174D39DA0A`.

Existing local `shield-main` had earlier backend improvements absent from the ZIP (external chat opt-in, review metrics/API, DB changes). They were preserved. Other directories (`shield`, `aida-defense`) are not the canonical working copy for this task.

`ml/retrain.py` had a truncated exception handler, missing `_read_feed_domains`, and duplicated invalid tail. Repaired; AST audit initially passed across all ML/backend Python files. Runtime tests are recorded separately.

Supplied historical unseen-frozen report: recall 73.69% / 59.69% and full-app FPR 6.44% / 0.96% for Suspicious+/High. Bayes projection at 1% prevalence is 10.36% / 38.58% precision. This is a prevalence assumption and domain-only historical result.

The old "full app" evaluator never calls the complete URL checker. Its path category is a domain-only baseline, not a full URL capability measurement. `linkcheck.path_brand` excluded brands shorter than five characters and did not URL-decode paths. Added exact short-brand matching with action context and two-pass decoding. Changed categorical claim about off-domain brand mentions to a review signal (partners/references can be legitimate).

Raw training files overlap some frozen-domain files (e.g. 20 exact base-training/frozen-UAE domains). `held_out_owners()` is intended to purge these before fitting. Raw-file overlap alone does not establish fitted-model leakage; verify the actual split and purge assertions.

## Recovery design and decisions

Historical resume optimization: `tools/resume_optimized.py` preserved the original checkpoint run across the one reviewed owner-code optimization, checking all five folds on all 425,414 actual fitting rows. Both models are now complete. Later evaluator/backend fixes intentionally changed the code fingerprint; do not invoke that historical wrapper to restore current inference. Use `tools/ensure_model.py` and existing weights. The wrapper refuses incompatible inputs by design.

- Checkpoints default to persistent project `checkpoints/`, configurable with `SHIELD_CHECKPOINT_DIR`. Use a persistent volume on cloud hosts.
- Cache identity hashes input training rows, seed, Python/sklearn versions, model/backend Python code and local dataset files. Changed inputs create a new run rather than reusing incompatible objects.
- Save feature matrices, vectorizer, C selection, each completed OOF classifier, final text classifier, combiners and fitted bundle. Each save is atomic and reloaded before publication. Resuming repeats preparation and any interrupted individual sklearn fit, not completed expensive fits.
- sklearn batch estimators do not expose a portable incremental optimizer checkpoint. No fictitious epochs/optimizer state are claimed.
- Immutable timestamped candidates, a latest pointer, best pointer selected by internal validation log-loss only, and exact prediction checks after reload. Across different run fingerprints, preserve the incumbent best and track per-run best separately.
- Existing production model is archived and never automatically replaced by a later experiment. First recovered baseline can populate an absent model. Candidate promotion requires an explicit evaluated choice; frozen data must not select candidates.
- Milestone events automatically update status blocks in the three handoff documents. Recreate a full backup after significant milestones. History and model artifacts are local; no Google Drive/Hugging Face upload has been performed.

## Unfinished work / priorities
1. Obtain analyst-verified legitimate and phishing pages, especially free hosting, UAE businesses, authorized partners and brand references. Original live DB/weights were not shipped. Do not manufacture reviewer decisions from rankings or model scores.
2. Restore a functioning, properly isolated page-evidence service without weakening DNS/private-network protections. Validate capture failures, reference drift and paired legitimate/phishing visual examples before making page checking central to decisions.
3. Create a NEW future temporal/owner-disjoint test before another experiment. The 3 November frozen snapshot has now been evaluated; never tune further on it and call it unseen. Keep existing artifacts as incumbents.
4. Reassess hard-negative training with verified labels, path/reference false positives, confidence intervals, recall and review workload. Do not blanket-allow hosting platforms or tune against the two showcased failures.
5. Implement label provenance/adjudication history (the current DB only has binary label/timestamp), then prove reviewed labels actually enter training. `docs/REVIEW_PROTOCOL.md` specifies the process.
6. Arrange a consenting action partner and record review-to-resolution outcomes. Group campaigns only with corroborating kit/form/infrastructure evidence; shared brand/IP/registrar alone is weak.
7. Prospectively record Shield/feed first-observed timestamps and missed/unmatched cases. No pre-message detection or lead-time claim is currently supported.
8. Copy a verified final backup off-device to a user-selected destination. No Drive/GitHub/Hugging Face upload has occurred. Maintain handoff/state/changelog and backups after future milestones.

## Known limits
No live pilot, takedown partner, demonstrated prevented losses, validated campaign clustering, or measurable pre-feed lead time is established by these files. The 120/121 unreviewed claim cannot be checked without the missing original DB. Screenshot similarity needs separate validation and stronger network/process isolation. Current site is a research presentation; simulated counters do not demonstrate impact.

## Verified final backup

`../recovery/shield-checkpoint-20261103T081130195204Z.zip` (289 files; SHA-256 `24381fc87077265d51ad23c918adc756a4ffcc1c22a9d0e91d54876db2eef254`). All manifest hashes checked, restored separately, four checkpoint pointers rebased, and removed serving weights automatically recovered without fitting. Baseline and candidate predictions matched exactly; the public frontend build flag was restored. Keep the external `.json` receipt with the ZIP; it records the post-creation restore test. The existing verified Python environment was reused. No cloud upload occurred. A smaller AI handoff packet carries source/docs/reports separately from model/data artifacts; read `AI_HANDOFF_PACKET_README.md`.

<!-- AUTO_CHECKPOINT_STATUS -->

Latest automatic recovery event:
```json
{
  "last_event": "final_portable_backup_restore_verified",
  "archive": "../recovery/shield-checkpoint-20261103T081130195204Z.zip",
  "files": 289,
  "model_prediction_parity_exact": true,
  "automatic_model_recovery_without_training": true,
  "public_build_config_preserved": true,
  "regression_tests_passed": 15,
  "cloud_upload": false
}
```
