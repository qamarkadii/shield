# Shield (درع)

AI early-warning system that helps UAE government entities find websites and domains
impersonating official services, group them into campaigns, and produce takedown-ready
evidence. UAE Hackathon 2026 (TDRA) — Pioneers Track, team AIDA.

## What the demo does

| Feature | How it works |
|---|---|
| **Live radar** | Reads new HTTPS certificates directly from public Certificate Transparency logs (Google's official log list), one parallel reader per log (6 logs), each certificate counted once. Every UAE-related domain (.ae, UAE place names, watched brands) goes to the **UAE watch** tab with its score; only real warning signs are flagged. |
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

## Results (Nov 1, measured)

| Measure | Before hostname fix | Now |
|---|---|---|
| Test accuracy (10,000 unseen domains) | 90.6% | 89.7% |
| Precision / recall | 93.0% / 87.9% | 92.6% / 86.3% |
| False alarms on legitimate hostnames (mail.company.com style) | **66.0%** | **0.5%** |
| Real UAE fakes caught by the model alone | 63/66 | 61/66 |
| Real UAE fakes flagged by model + lookalike rules | 66/66 | 66/66 (51 high risk, 15 suspicious) |

Why the change: the legitimate training examples were bare names (company.com) while many
phishing examples had subdomains, so the first model learned "subdomain = phishing" and
flagged most live certificate hostnames. Training now adds realistic subdomain copies of
legitimate domains (`ml/common.py`). Variants compared: replace 50% (acc 0.866),
**add copies 50% (acc 0.897, chosen)**, add copies + balanced weights (0.887), replace 30% (0.887).

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
