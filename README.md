# Shield (درع)

AI early-warning system that helps UAE government entities find websites and domains
impersonating official services, group them into campaigns, and produce takedown-ready
evidence. UAE Hackathon 2026 (TDRA) — Pioneers Track, team AIDA.

## What the demo does

| Feature | How it works |
|---|---|
| **Live radar** | Reads new HTTPS certificates directly from public Certificate Transparency logs (Google's official log list), flags any domain imitating a watched UAE brand, scores it and adds it to the feed. |
| **Is this link official?** | A citizen pastes a suspicious link. Shield never opens it; it checks the domain (lookalike rules + ML), red flags in the link (IP address, `@` trick, shorteners, punycode letters, payment paths) and known phishing lists. The report joins the feed. |
| **Analyst review** | Every detection can be marked *Confirm* (phishing) or *Legit*. These decisions become training labels. |
| **Alert emails** | *Alert* sends an evidence email (with a JSON evidence file and SHA-256 hash) after the analyst approves. **Demo: always to your team inbox (`ALERT_TO`), never to a real government address.** |
| **Retraining** | Downloads the newest phishing feeds, adds analyst labels (weighted 20×), retrains and swaps in the new model without restarting. Test set and the 66 UAE cases are never used for training, so scores stay honest. |
| **Replay** | Loads 66 real phishing domains that impersonated UAE brands, for a reliable demo. |

## Setup (Windows, Command Prompt)

```
cd C:\shield
python -m pip install -r requirements.txt
python ml\train_baseline.py
python backend\scripts\update_feeds.py
python -m uvicorn backend.app.main:app --reload
```

Open **http://127.0.0.1:8000** for the dashboard (API docs at `/docs`).

### Alert emails (optional)

Copy `.env.example` to `.env` and fill it in (Gmail needs an *App password*).
Without `.env`, alerts are saved as `.eml` files in `data/outbox/`, so the demo still works.

## Folder structure

| Folder | What's in it | Owner |
|---|---|---|
| `backend/app/` | `main.py` API, `scoring.py` rules + ML, `ctlog.py` live radar, `linkcheck.py`, `alerts.py`, `db.py`, `static/index.html` dashboard | B: Backend |
| `backend/scripts/` | `update_feeds.py`, `certstream_test.py`, `crtsh_search.py`, `download_data.py` | B: Backend |
| `ml/` | `train_baseline.py`, `retrain.py` | A: Data and ML |
| `data/` | Training, test and real UAE phishing datasets (see `data/README.md`) | A: Data and ML |
| `frontend/` | Space for a React dashboard if the team builds one | C: Frontend |
| `docs/` | Build guide link | D: Pitch and product |

## Results (Nov 1)

- Baseline model: 90.6% accuracy on 10,000 unseen domains; 63/66 real UAE fakes.
- After retraining with 30,000 fresh feed domains: 90.8% accuracy; 64/66.
- Model + lookalike rules: all 66 UAE fakes flagged.

## Honest limits (say these if judges ask)

- On a laptop the radar reads the newest window of a few logs: a live **sample** of the
  stream, not every certificate. A production deployment would read all logs continuously.
- Live certificate domains have no labels, so the model learns from fresh phishing feeds
  and analyst decisions, never from its own guesses (that would repeat its mistakes).
- Fakes of UAE brands are rare at any given minute; use the replay for the scoring demo.

## Safety rules

- Never open domains from `data/` or the feed in a browser — they are real phishing sites.
- Alerts go only to `ALERT_TO`. `ENTITY_CONTACTS` in `alerts.py` stays empty unless an
  entity agrees to receive them.
- Verify every official domain in `backend/app/scoring.py` (`BRANDS`) before the demo.
- Never commit `.env`.
