# Moving this project to another AI

Start with `CONTINUE_HERE.md`, then `audit/FINAL_AUDIT.md` and `TRAINING_STATE.md`. The models have already been trained; a new chat must not repeat training because it cannot see the weights yet.

The small **AI handoff packet** contains source, configuration, reports and instructions. It deliberately excludes large datasets, model weights, checkpoint matrices, screenshots and the compiled website. It is suitable for sharing project context with another AI, but is not the complete recoverable project.

The **complete backup** is the large `shield-checkpoint-*.zip` plus its external `.json` receipt, identified by `../recovery/LATEST_BACKUP.json`. It includes both trained models, all recoverable stage checkpoints, source/data/assets and dependency specifications. Copy the ZIP and receipt together to a private Drive/artifact folder or restore them in the next AI's accessible workspace. Nothing has been uploaded automatically.

A web chat cannot read a `C:/...` path on this computer merely because the path appears in Markdown. Supply the packet/files or an accessible user-authorized storage location. If artifacts are missing from the new AI's environment, request them; do not train replacement models and call that recovery.

For inference, the main small artifacts are `ml/domain_model.joblib` (about 6 MB), the matching `data/lists/tranco.zip` (about 10 MB), source and dependency lock files. The full checkpoint matrices are mainly for training recovery. Preserve `data/brand_refs/` for the optional page checker, which remains unvalidated in this audit. Prefer the full backup when practical.

Restore with `tools/restore_backup.py` into an empty directory, install dependencies, and run `tools/ensure_model.py`. It reuses saved weights. The existing baseline remains the serving prototype; the error-focused candidate is preserved but was not promoted. Do not tune on the already-evaluated frozen snapshot.
