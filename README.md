# Shield (درع)

AI early-warning system that helps UAE government entities find websites and domains
impersonating official services, group them into campaigns, and produce takedown-ready
evidence. UAE Hackathon 2026 (TDRA) — Pioneers Track, team AIDA.

## Folder structure

| Folder | What's in it | Owner |
|---|---|---|
| `backend/app/` | FastAPI server: `/check`, `/replay`, `/health`; `scoring.py` = lookalike rules + ML | B: Backend |
| `backend/scripts/` | Data and certificate-stream scripts (`certstream_test.py`, `crtsh_search.py`, `download_data.py`) | B: Backend |
| `ml/` | `train_baseline.py` — trains the domain classifier | A: Data and ML |
| `data/` | Training, test and real UAE phishing datasets (see `data/README.md`) | A: Data and ML |
| `frontend/` | Dashboard (to build on Day 1) | C: Frontend |
| `docs/` | Build guide link, pitch notes | D: Pitch and product |

## Setup (Windows, Command Prompt)

```
cd C:\shield
python -m pip install -r requirements.txt
python ml\train_baseline.py
uvicorn backend.app.main:app --reload
```

Then open http://127.0.0.1:8000/docs and try `/check` with `emirates-post.org`.

## Current results (Nov 1)

- ML model alone: 90.6% accuracy on 10,000 unseen domains; 63/66 real UAE fakes caught.
- Model + lookalike rules: all 66 real UAE fakes flagged; the 3 the model missed
  (`emirates-post.org`, `etisalatebills.com`, `aramex.valeriair.com`) score high risk.

## Safety rules

- Never open domains from `data/` in a browser — they are real phishing sites.
- The "send takedown" action in the demo only changes a status; nothing is sent.
- Verify every official domain in `backend/app/scoring.py` (`BRANDS`) before the demo.
