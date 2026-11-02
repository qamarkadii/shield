---
title: Shield
emoji: 🛡️
colorFrom: indigo
colorTo: yellow
sdk: docker
app_port: 7860
pinned: false
short_description: Early warning for fake UAE government websites
---

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

## Two sites

| Site | Port | Who | Code |
|---|---|---|---|
| Analyst dashboard | 8000 | Team only (behind Cloudflare Access) | `backend/app/main.py`, `static/index.html` |
| Public "Is this link official?" (Arabic/English) | 8001 | Anyone | `backend/app/public.py`, `static/public.html` |

The public site can only check links and, if the visitor chooses, report one to the analysts.
It has no admin functions, hides its API docs, never opens links, stores nothing unless the visitor
presses *Report*, and limits each visitor to 20 checks a minute.

`python run_shield.py` runs both in one program (one copy of the model in memory);
add `--radar` to start the live radar too. On Windows, just double-click **`start_shield.bat`** (both sites + radar).

**Live at aidashield.tech:** the team runs Shield on a laptop behind a Cloudflare Tunnel —
`aidashield.tech` (public) and `app.aidashield.tech` (dashboard, Cloudflare Access login). Setup: **`deploy/DEPLOY_LAPTOP.md`**.
Other hosting options: `deploy/DEPLOY_FREE.md` (Hugging Face Docker Spaces, now needs a paid plan), `deploy/DEPLOY.md` (Azure), `deploy/DEPLOY_ORACLE.md` (Oracle).

## Setup (Windows, Command Prompt)

```
cd C:\shield
python -m pip install -r requirements.txt
python backend\scripts\download_data.py
python ml\train_baseline.py
python backend\scripts\update_feeds.py
python run_shield.py
```

Dashboard: **http://127.0.0.1:8000** (API docs at `/docs`). Public check: **http://127.0.0.1:8001**.

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
2. **Learned score**: a two-stage model (`ml/model.py`, inference in `backend/app/riskmodel.py`) — a character-pattern
   text model, then a gradient-boosted combiner that **learns the effect of each warning sign** (brand tricks, learned
   ending/host risk, site popularity from Tranco, look-alike letters incl. Cyrillic, ...). Training is grouped by
   **owner** (the real registered site or hosting tenant), so no site is in both training and test.
   Score = calibrated probability × 100 (capped at 99); `live_probability` = the same at a realistic 1% phishing rate.
3. **Levels**: *High risk* / *Suspicious* cut-offs are set on held-out data for 0.5% / 3% false alarms on legitimate domains.
   Each reason shows its learned effect ("x7.5 odds"), measured by switching that sign off.
4. **Labelled rules**: imitating a *registered UAE brand* (look-alike letters, re-spelling, brand + lure word, brand in front of an
   unrelated domain, fake `.ae`) always sends the domain to analyst review. Public data has too few of these to learn a weight.
   Rules never change the score and are shown as "Rule".
5. **Link facts** (citizen check): on a phishing list, `@` trick, raw IP, foreign look-alike letters, shortened link (→ *Unknown*).

## Results (model v2, Nov 2, measured — full report in `docs/model_card.md`)

| Measure (owners never used in training) | Result |
|---|---|
| AUC | 0.943 (the earlier 0.951 was inflated: the same sites were in training and test) |
| Suspicious or higher: recall / false alarms | 80.4% / 2.78% (was 4.1%) |
| High risk: recall / false alarms | 70.8% / 0.30% (was 0.58%) |
| Share of *High risk* alerts that are real if 1% of domains seen are phishing | ~70% (was ~56%) |
| 42,284 real legitimate hostnames (console.aws.amazon.com ...) flagged | 2.0% (0.9% High) |
| 66 real UAE fakes, model alone | 57 high, 6 suspicious, 3 missed |
| 66 real UAE fakes, full app (model + rules) | 57 high, 9 suspicious, **0 missed** |

Known weak spot: legitimate sites on free hosting (`*.vercel.app`, `*.github.io`) are flagged about half the time,
because phishing feeds are full of them.

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
