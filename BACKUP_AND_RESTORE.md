# Backup and restore

`tools/backup_project.py` creates versioned ZIPs beside the project in `../recovery/`. Every ZIP includes source, dependency specifications/lock file, supplied data/assets, documentation and all project-local checkpoints. It excludes `.env` secrets, `.venv`, `node_modules`, caches, general runtime logs and Git internals. Audit/training logs under `audit/` are retained as debugging history. SQLite is snapshotted with its backup API, including committed WAL data; raw WAL/SHM files are excluded. Never place unprotected credentials in a backup or public repository.

Each archive has an external `.json` receipt with its SHA-256 and file count, and an internal `BACKUP_MANIFEST.json` mapping every included file to its SHA-256. Creation reopens the ZIP, checks ZIP integrity and verifies every included file's bytes. Original uploads and older archives are retained.

```powershell
# In shield-main, after a significant development/training milestone:
.\.venv\Scripts\python.exe tools\backup_project.py

# Restore to an EMPTY directory; never restore over existing work:
.\.venv\Scripts\python.exe tools\restore_backup.py ..\recovery\shield-checkpoint-TIMESTAMP.zip ..\recovery\restored-project
```

Restore verifies all manifest hashes before writing. It records `RESTORE_RECEIPT.json` and rebases checkpoint pointer paths for the new location. Reinstall the environment from `requirements-lock.txt`, then read `CONTINUE_HERE.md`. Existing models/stages are reused; training is not required merely to restore inference. Joblib must only be loaded from trusted local artifacts, not arbitrary downloads.

## Portable layout

```text
shield-main/
  CONTINUE_HERE.md, PROJECT_HANDOFF.md, TRAINING_STATE.md, CHANGELOG.md
  requirements.txt, requirements-lock.txt, Dockerfile, .env.example
  backend/       API, citizen/analyst pages, evidence and scoring
  frontend/      React source, package-lock.json, built dist/
  ml/            model/training code and deployed domain_model.joblib
  data/          CSVs, brand refs, downloaded source snapshots and lists
  checkpoints/   fingerprinted runs, latest/best pointers, immutable models, history
  audit/         measured results, environment details and review
  tools/         backup, restore, data and model-audit utilities
  tests/         focused recovery/privacy/URL regressions
  docs/, deploy/ reference/deployment instructions
recovery/
  shield-original-2026-11-03.zip
  shield-checkpoint-<UTC timestamp>.zip
  shield-checkpoint-<UTC timestamp>.json
```

For GitHub, commit source/config/docs and small reproducible audit outputs. The existing `.gitignore` excludes model weights and downloaded lists; **Git alone is not the model backup**. Large checkpoints require Git LFS, a release/artifact store, or a private Drive folder. Checkpoint vectorizer matrices can exceed GitHub's regular per-file limit. Keep the verified ZIP and receipt together when copying to Google Drive. No cloud upload or sync has been configured in this session.

## Downloads and secrets restored separately

- Python 3.12 and packages pinned in `requirements-lock.txt`; Node plus `npm ci` in `frontend/` when rebuilding the website.
- Playwright Chromium browser binaries are not included. `python -m playwright install chromium` downloads them; page execution/isolation requires its own validation.
- Full current Tranco/Umbrella/OpenPhish snapshots downloaded in this audit are included in the ZIP. Historical large phishing-source snapshots used by `collect_uae.py` and the original facts lookup cache were not shipped and cannot be reconstructed exactly from the reports.
- `.env` and API/SMTP/Hugging Face credentials must be configured separately. External chat remains opt-in. The default application can run without those integrations.
- If `SHIELD_CHECKPOINT_DIR` points OUTSIDE this project, separately back up that persistent volume; the project ZIP includes the default project-local `checkpoints/` only.

Local backups protect against accidental changes and chat limits. They do not protect against losing the whole computer. Copy a verified archive to a user-selected off-device destination when ready.

The public non-secret rontend/.env.shield build flag is retained; private .env and .env.production remain excluded. A small AI handoff packet can carry source/reports separately from large artifacts; see AI_HANDOFF_PACKET_README.md.
