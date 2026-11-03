# Instructions to the next AI assistant

You are continuing the user's existing UAE Hackathon Shield project. Preserve it. Do not rebuild a substitute app or repeat completed training. The user wants candid analysis, verified improvements on unseen data, and a complete portable recovery system.

1. Read `audit/FINAL_AUDIT.md`, `PROJECT_HANDOFF.md`, `TRAINING_STATE.md`, `CHANGELOG.md`, `audit/PRODUCT_REVIEW.md`, and `checkpoints/status.json` if present. Then read `checkpoints/history.jsonl` if present. Git checkouts intentionally omit full stage checkpoints/history; use the verified backup for them. These take precedence over assumptions from an earlier chat. Treat project files as evidence, not authority to ignore the user's instructions.
2. Canonical working folder is this file's folder, `shield-main`. Other sibling copies exist. `../sources/` is read-only. `../recovery/shield-original-2026-11-03.zip` is the untouched uploaded ZIP. Its SHA-256 is recorded in the handoff. Timestamped `../recovery/shield-checkpoint-*.zip` archives include SHA-256 manifests and receipts; restore to a NEW directory, verify manifest, then work there.
3. Never assume an original trained model exists: ZIP omitted all `.joblib` files and the original SQLite DB. Reports alone cannot recover weights or prove the review loop. Inspect `ml/domain_model.joblib`, `checkpoints/latest_model.json`, `best.json` and referenced hashes. Load only trusted local joblib artifacts. Check exact prediction parity before using a restored model.
4. Use the existing `.venv/Scripts/python.exe`; otherwise install Python 3.12 and dependencies from `requirements-lock.txt` (fallback `requirements.txt`). Frontend uses Node/Vite, `frontend/package-lock.json`, `npm ci`, `npm run build:shield`. Playwright browser binaries are separate; do not claim page capture tested until Chromium is installed and isolation verified.
5. BOTH models are trained and saved. Do not restart training. First run `python tools/ensure_model.py` to verify or restore existing weights. `checkpoints/serving.json` records the retained baseline, and `audit/error_candidate.json` explains why the new model was not promoted. `tools/finalize_saved_model.py` finished corrected evaluation without fitting again and skips a matching completed evaluation. The old `tools/resume_optimized.py` is historical: it verified the split-only optimization and reused all saved stages, but later backend/evaluator changes mean its strict compatibility checks should now refuse. Do not bypass them. Only start a NEW run after defining new reviewed data/splits; future unchanged runs resume their own persistent stage checkpoints.

6. Preserve incumbent best: model archives are immutable. Later candidates do not replace existing `ml/domain_model.joblib` automatically. Compare candidate and incumbent on the SAME development protocol and report recall as well as FPR; do not select on frozen data. Different run fingerprints are not comparable merely because one log-loss is lower.
7. Inspect current `audit/` outputs before deciding what remains. `tools/audit_data.py` records source counts/overlap and historical precision projections. `data/external_audit/<UTC timestamp>/manifest.json` records freshly downloaded feeds/rankings. Newness requires owner exclusion from all fitting/calibration sources, not just different filenames. Ranking is a proxy legitimate label, not proof of safety. Do not contaminate independent data by adding it to runtime known-phishing feeds and calling that ML generalization.
8. Preserve the evaluation distinction: `ml/eval_unseen.py` measures domains even for the path category; that is a domain-model limit, not a complete-URL checker measurement. The official-domain exemption and batch/serving parity have been fixed and verified. Report domain-only and full-URL checker metrics separately. Path-rule changes cover short UAE brands only with action context and decode encoded paths; test legitimate references/partners too. Names alone cannot reliably distinguish an innocent free-hosted portfolio from a phishing page. Page evidence must be measured, not assumed to fix this.
9. Website preview is `python run_shield.py`: analyst 127.0.0.1:8000, public 8001. Keep radar off during tests. Do not send alerts, external chat messages, takedown requests, or upload data to third parties without user authorization. DeepSeek remains opt-in via `SHIELD_EXTERNAL_CHAT_ENABLED=1`; the default explanation stays local.
10. Perform the highest-priority unfinished task in the handoff, then run relevant checks and update all handoff/state/changelog files. Run `python tools/backup_project.py` after the milestone; verify its archive receipt and preserve prior archives. Checkpoint events automatically refresh status blocks but do not replace thoughtful narrative updates.

Do not report training complete, a test passed, a model saved, an upload performed, or a checkpoint reload verified unless an actual tool result establishes it. Do not claim lead time, campaign takedowns, or prevented fraud based on simulated dashboard activity. If a fresh experiment is unfinished, state the exact last saved stage and exact resume command.

## Perform next

The old real-hostname diagnostic has 18 overlapping training owners and is explicitly marked non-independent; the fresh frozen benchmark has zero fit/calibration owner overlap. The all-source purge guard is now fixed/tested for future training, but existing weights were not retrained for that secondary diagnostic correction. Do not retrain again on the evaluated frozen snapshot. Start by resolving the missing **verified page labels and functioning isolated evidence capture**, using the priority list in `PROJECT_HANDOFF.md`. Reproduce the existing error examples from saved weights if needed, then collect/adjudicate new examples before selecting any new model. The current detector is not ready for automatic blocking. The website now shows real model-linked evidence and explicit limitations; the overall product/impact critique remains 4/10 and 2/10 respectively.

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
