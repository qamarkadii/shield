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

## How the risk score works

1. **Official check (fact)**: the domain belongs to a registered UAE brand (`backend/app/registry.py`).
2. **Learned score**: a two-stage model (`ml/model.py`) — a character-pattern text model, then a combiner that
   **learns the weight of each warning sign** from labelled data. Score = 100 × probability (capped at 99). Nothing is added by hand.
3. **Levels**: *High risk* / *Suspicious* cut-offs are set on held-out data for 0.5% / 3% false alarms on legitimate domains.
4. **Labelled rules**: imitating a *registered UAE brand* (look-alike letters, re-spelling, brand + lure word, brand in front of an
   unrelated domain, fake `.ae`) always sends the domain to analyst review. Public data has too few of these to learn a weight.
   Rules never change the score and are shown as "Rule".
5. **Link facts** (citizen check): on a phishing list, `@` trick, raw IP, foreign look-alike letters, shortened link (→ *Unknown*).

## Results (Nov 1, measured — full report in `docs/model_card.md`)

| Measure (test data never used in training) | Result |
|---|---|
| AUC | 0.951 |
| Suspicious or higher: precision / recall / false alarms | 95.4% / 84.1% / 4.1% |
| High risk: precision / recall / false alarms | 99.3% / 77.1% / 0.58% |
| Legitimate hostnames (mail.company.com) flagged | 0.38% |
| 66 real UAE fakes, model alone | 57 high, 6 suspicious, 3 missed |
| 66 real UAE fakes, full app (model + rules) | 57 high, 9 suspicious, **0 missed** |

Earlier versions added hand-picked points (+50 brand, +10 .xyz ...), double-counted signs the model already saw, and
matched brands too loosely (`hyderabadpolice.gov.in` was read as Abu Dhabi Police). All replaced by the above.

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
