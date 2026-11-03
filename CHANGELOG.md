# Experiment and recovery changelog

## 2026-11-03 — audit and recovery implementation
- Preserved untouched uploaded ZIP under `../recovery/`, SHA-256 recorded in handoff.
- Audited archive: 183 entries, zero model weights or databases. Preserved existing local backend privacy/review improvements.
- Repaired truncated `ml/retrain.py`, restored missing feed parser, removed invalid duplicated tail. All backend/ML Python parsed after repair (see `audit/syntax_audit.json`).
- Added persistent fingerprinted sklearn stage checkpoints, atomic writes, reload verification, immutable candidates, latest/best pointers, production preservation and automatic handoff status updates.
- Added portable backup tool with consistent SQLite snapshot and per-file ZIP read-back verification.
- Added data/source audit and timestamped fresh-source download tools. Historical unseen precision estimates recalculated; they are not new trained-model results.
- Fixed complete-URL scheme validation, encoded-path matching, short-brand action-context matching, and overconfident off-domain brand wording.
- Prepared cross-AI handoff and training-state documents. Runtime environment, training and final backup verification still in progress; consult subsequent entries and checkpoint history.

## 2026-11-03 — verified environment, independent reservation and first checkpoints
- Installed dependencies into the persistent project `.venv`; pinned resolved versions in `requirements-lock.txt`, recorded key versions in `audit/environment.json`. Initial sandbox DNS/cache failures were resolved with authorized dependency downloads and a workspace UV cache.
- Downloaded OpenPhish, Tranco and Umbrella snapshots with UTC timestamps/hashes under `data/external_audit/20261103T064127Z/`.
- Reserved 2,588 fresh rows, zero exact overlaps with other supplied CSV domain sets: 188 phishing-source rows, 2,000 Tranco proxy-negative rows, 400 Umbrella hosting proxy-negative rows. Deterministic owner-based dev/frozen split; all reserved owners are excluded from baseline fitting/calibration.
- Eight regression tests passed (`audit/regression-tests.txt`), including real sklearn estimator serialization/prediction parity, corruption rejection and no external chat request by default.
- Browser-tested landing page, performance panel, analyst dashboard and bilingual citizen checker. Reserved ADCB path test was raised for review. Saved `audit/citizen-check.jpg`. No alerts, analyst labels or radar activity were fabricated.
- URL-rule-only evaluation: 17/17 dev and 28/28 frozen source path URLs flagged; 2/6 deliberately benign reference/partner regression examples also flagged. Small source samples and curated regressions are not deployment metrics. The prior domain-only path figures were not full-URL checker measurements.
- Verified portable backup `../recovery/shield-checkpoint-20261103T064916654266Z.zip`: 186 files, SHA-256 `2fbdd1405f4a890abbd71b60f75c6eaa98b297dc50d5e2795361cbcbc92a637d`. Later milestones require a newer backup.
- Baseline recovery run `c8c7e9c87180f68e41981b7ec7cd9bf970b3842d3de6a8bd3319826986ec5adc`: 425,414 fit rows, 64,559 internal holdout rows; static matrices, vectorizer and C selection saved and reloaded. Chosen text C=4; internal tuning log-loss .3511 versus .3725 (C=1) and .3667 (C=16). OOF fits in progress; no final model success claimed here.
- Expanded recovery tests to 11 passing cases, including consistent SQLite WAL snapshots, secret exclusion, restore-pointer rebasing, refusal to overwrite work and archive traversal rejection.
- Diagnosed long OOF delays in installed sklearn source: shuffled GroupKFold applies `np.isin` to owner strings, creating expensive object comparisons. Preserved completed fold 0 (96 optimizer iterations) and stopped only the identified training process. Replaced owner representation with sorted factorized integers; `tools/resume_optimized.py` verifies the exact source delta and every actual fold's membership, preserving and reusing the original checkpoint run. Original logs/source are retained under `audit/`.

## 2026-11-03 — completed experiments and final verification
- Baseline trained and checkpointed: all five OOF fits and final text fit, C=4; gradient boosting 400 iterations, original internal loss .324. Exact split membership verified across all 425,414 fitting rows. Existing completed fits were reused.
- Trained a separate error-focused combiner using 1,257 fresh development rows and frozen baseline text fits; 358 boosting iterations; internal loss .330483. Zero analyst labels used.
- Locked candidate before frozen testing. Hosting proxy High-risk false alarms fell from 102/123 to 29/123; phishing High-risk recall fell from 42/55 to 39/55; ranked-site false alarms rose from 7/574 to 8/574. Candidate NOT promoted. Full counts/CIs and unchanged failure examples are saved in audit JSON and FINAL_AUDIT.md.
- Finished corrected evaluation from saved weights instead of repeating training. Replaced slow per-domain explanation loops with batching, checked 16 actual serving decisions including official domains, and corrected the evaluator's official-domain exemption.
- Fixed failed/empty browser captures being labelled nothing found; now not checked. A benign page smoke test was refused by DNS/public-address validation; rendering remains unverified, protections unchanged.
- Rebuilt site evidence panel to use exact loaded-model identity and metrics, source-shift failures/CIs, proxy-label limits and unavailable states. Corrected feature count, unmeasured stage percentages and chat capability copy. Browser verified both threshold settings. TypeScript/Vite build passed.
- Model identity is now bound to the bytes actually loaded, including when the file later changes; reload changes identity. Fourteen regression tests passed, including checkpoint reuse/corruption, concurrent-fit refusal, privacy default, URL rules, failed-page verdict, SQLite WAL snapshots, secret exclusion, safe restore and pointer rebasing.
- Added training/publication/metadata locks and unique temporary handoff writes; per-run best pointers no longer move to a worse result. Added ensure_model.py to restore weights before training and preserved packaged weights in Docker. Docker build was not executed.
- Local services run on 8000/8001 with radar off. Original source ZIP, prior checkpoints and candidates retained. No alerts, real analyst labels, cloud upload or live impact claims fabricated.

- Final owner reconstruction verified zero fit/calibration overlap with the fresh benchmark and primary reserved evaluation owners, but found 18 overlapping owners in the older real-hostname diagnostic. Marked that diagnostic non-independent in the report/model card; fixed/tested the future all-source purge after merging supplements. Existing artifacts retained without pretending this source-only correction retrained them. Fifteen regression tests now pass.

- Final full backup `shield-checkpoint-20261103T080248330090Z.zip` verified (282 files, SHA-256 a320cbdf6bd95992b4c652bf193a2dcaeaf884ddad8403c9c5bed0a84485946f), restored separately with four pointer paths rebased; automatic recovery restored removed serving weights without fitting. Baseline and candidate predictions matched exactly after restore. External receipt/LATEST_BACKUP.json include the restore proof.

- Backup review caught the non-secret frontend/.env.shield build flag being excluded with secret environment files. Added a precise allowlist and regression coverage while preserving exclusion of private environment files. Creating a superseding complete archive with this config and restore evidence; the earlier archive already passed model recovery tests.
