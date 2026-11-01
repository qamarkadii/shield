"""
Shield backend (starting point).

Run from the repo folder:
    python -m pip install -r requirements.txt
    python ml\\train_baseline.py          (once, creates the model)
    uvicorn backend.app.main:app --reload

Then open http://127.0.0.1:8000/docs to try the endpoints.
"""

import csv
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .scoring import score_domain

app = FastAPI(title="Shield API", version="0.1")

# Let the frontend (running on another port) call the API
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

DATA = os.path.join(os.path.dirname(__file__), "..", "..", "data")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/check")
def check(domain: str):
    """Score one domain or link, e.g. /check?domain=emirates-post.org"""
    return score_domain(domain)


@app.get("/replay")
def replay(limit: int = 100):
    """Score the real UAE-targeted fakes, for the replay demo."""
    path = os.path.join(DATA, "uae_phishing_domains_real.csv")
    with open(path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))[:limit]
    results = [score_domain(r["domain"]) | {"impersonates": r["impersonates"]} for r in rows]
    return sorted(results, key=lambda r: r["score"], reverse=True)
