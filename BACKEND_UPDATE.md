# Backend update for the uploaded Shield project

The `frontend/` tree is copied unchanged from `shield-main.zip`. The API and model work is under `backend/`, `ml/`, and `docs/`.

## Changes

- External chat is disabled unless `SHIELD_EXTERNAL_CHAT_ENABLED=1` is set in `.env`. When enabled, messages and pasted links go to the configured DeepSeek endpoint. Inform users before enabling it.
- `GET /review/queue` and `GET /review/brand-activity?hours=24` are on the analyst service (`app.aidashield.tech`, protected by Cloudflare Access). Brand activity is only a lead for investigation; shared brand and timing do not prove common control.
- `/stats` includes reviewed and pending counts. No analyst labels or takedowns are claimed unless recorded.
- The uploaded training code already draws only from `unseen_train.csv`; `unseen_dev.csv`, `unseen_frozen.csv`, and UAE holdouts stay excluded from training. Recheck owner-level overlap before release.

## Deployment

Back up the running `data/shield.db`, `.env`, and any model files first. Extract this ZIP to a new folder, copy the backed-up runtime files into it, then restart Shield using the repository's deployment instructions. The laptop must stay on for its Cloudflare Tunnel route. The built `frontend/dist` is included unchanged.

Only copy a newly trained `ml/domain_model.joblib` after the held-out evaluation succeeds. Never claim a measured time-to-detection lead without first-seen timestamps from both Shield and the external feed. The repository does not provide those paired timestamps.

The isolated `POST /pagecheck` already exists on the protected analyst service. It requires a separate browser process; do not move page visits into the public API or citizen browser.
