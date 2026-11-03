# Prepared GitHub update

Repository: https://github.com/qamarkadii/shield

The Git-ready checkout is `C:/Users/qamar/Desktop/shield-updated`. It preserves the repository's existing history. The changes are prepared locally; the user performs the push.

This checkout includes the serving baseline at `ml/domain_model.joblib` and its matching `data/lists/tranco.zip`. Their exact bytes are preserved so deployment can load the evaluated model without training again. Docker installs the pinned dependency lock file. The error-focused candidate remains unpromoted.

Virtual environments (including `.venv312`), node_modules, runtime databases, private `.env` files, raw audit downloads and full stage checkpoints are excluded. The public `frontend/.env.shield` flag is retained. Complete stage/candidate recovery remains in the verified full backup described in `BACKUP_AND_RESTORE.md`; a Git checkout alone is not that full backup.

After the local commit has been prepared, run in PowerShell:

```powershell
cd C:\Users\qamar\Desktop\shield-updated
git push origin main
```

GitHub may ask you to sign in. No force push is required. Do not push an older extracted copy from another folder.
