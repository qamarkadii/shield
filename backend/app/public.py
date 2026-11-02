"""
Shield PUBLIC site: the citizen "Is this link official?" check. Safe to open to everyone.

It can ONLY:
  GET  /             the bilingual citizen page
  POST /api/check    check one link (nothing is stored)
  POST /api/report   send a checked link to the analysts' review queue (only if the person chooses to)
  POST /api/chat     chat assistant: explains Shield's check of any link in the message (see chat.py)
  GET  /api/health

It has no admin functions (no alerts, retraining, radar or labels), no API docs page,
and it never opens the links people paste. Each visitor is limited to a few requests
per minute so nobody can flood it.

Run (on its own):   python -m uvicorn backend.app.public:app --port 8001
Run with the analyst dashboard in one process:   python run_shield.py
"""

import os
import time
from collections import defaultdict, deque

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from . import db, linkcheck
from .i18n import ADVICE_AR, BRAND_AR, to_ar
from .registry import UAE_BRANDS

app = FastAPI(title="Shield public check", docs_url=None, redoc_url=None, openapi_url=None)
HERE = os.path.dirname(__file__)


@app.on_event("startup")
def _warm_up():
    # Load the model in the background so the first visitor's check/chat isn't slow (~7 s cold).
    import threading
    threading.Thread(target=lambda: linkcheck.check_link("example.org"), daemon=True).start()

LIMITS = {"check": (20, 60), "report": (5, 60), "chat": (12, 60)}      # requests per seconds, per visitor
_hits = defaultdict(deque)


def _visitor(request: Request) -> str:
    # The real visitor address (Cloudflare header, else the first forwarded address). Used only
    # for rate limiting, kept in memory for a minute, never stored.
    fwd = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    return request.headers.get("cf-connecting-ip") or fwd or (request.client.host if request.client else "?")


def _limit(request: Request, kind: str):
    n, window = LIMITS[kind]
    q = _hits[(kind, _visitor(request))]
    now = time.time()
    while q and q[0] < now - window:
        q.popleft()
    if len(q) >= n:
        raise HTTPException(429, "Too many requests, please wait a minute. / طلبات كثيرة، انتظر دقيقة من فضلك.")
    q.append(now)


class Link(BaseModel):
    url: str = Field(..., max_length=2000)


class ChatMessage(BaseModel):
    role: str = Field(..., max_length=16)
    content: str = Field(..., max_length=4000)


class Chat(BaseModel):
    messages: list[ChatMessage] = Field(..., min_length=1, max_length=40)


def _official_sites(brand):
    if not brand:
        return []
    for name, domains in UAE_BRANDS.values():
        if name == brand:
            return domains
    return []


def _public_view(r: dict) -> dict:
    """Only what a citizen needs, in English and Arabic."""
    # Small model signs on a "no warning signs" result only confuse a citizen
    # ("looks randomly generated" on google.com), so they're shown only with a warning.
    signals = [] if r["verdict"] in ("no warning signs", "official") else \
        [s["text"] for s in r.get("signals", []) + r.get("fact_signals", [])
         if s.get("effect", 0) > 0.3 or (s.get("feature") == "age_days_log" and s.get("effect", 0) > 0)]
    cap = lambda x: x[:1].upper() + x[1:]
    facts = [cap(x.replace("Fact: ", "", 1)) for x in r.get("facts", [])]
    rules = [cap(x.replace("Rule: ", "", 1)) for x in r.get("rules", [])]
    out = {
        "url": r.get("url"), "domain": r.get("domain"), "verdict": r["verdict"], "score": r.get("score"),
        "brand": r.get("brand"), "brand_ar": BRAND_AR.get(r.get("brand") or "", r.get("brand")),
        "official_sites": _official_sites(r.get("brand")),
        "en": {"facts": facts, "rules": rules, "signals": signals, "notes": r.get("notes", []),
               "advice": r.get("advice", "")},
        "ar": {"facts": [to_ar("Fact: " + x[:1].lower() + x[1:]).replace("حقيقة: ", "", 1) for x in facts],
               "rules": [to_ar("Rule: " + x[:1].lower() + x[1:]).replace("قاعدة: ", "", 1) for x in rules],
               "signals": [to_ar(x) for x in signals], "notes": [to_ar(x) for x in r.get("notes", [])],
               "advice": ADVICE_AR.get(r["verdict"], "")},
    }
    if r["verdict"] == "no warning signs" and not (facts or rules or signals):
        out["en"]["signals"] = ["No warning signs found in the name. This does not prove the site is safe."]
        out["ar"]["signals"] = [to_ar(out["en"]["signals"][0])]
    return out


@app.get("/", include_in_schema=False)
def page():
    return FileResponse(os.path.join(HERE, "static", "public.html"))


# AIDA showcase website (3D hero, live demo, model performance), built from frontend/ into frontend/dist.
# Open it at /site/ . Rebuild after changing the site:  cd frontend && npm install && npm run build:shield
SITE = os.path.join(HERE, "..", "..", "frontend", "dist")
if os.path.isdir(SITE):
    from fastapi.responses import RedirectResponse
    from fastapi.staticfiles import StaticFiles

    @app.get("/site", include_in_schema=False)
    def site_redirect():
        return RedirectResponse("/site/")

    app.mount("/site", StaticFiles(directory=SITE, html=True), name="site")


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/check")
def check(body: Link, request: Request):
    _limit(request, "check")
    r = linkcheck.check_link(body.url)
    if "error" in r:
        raise HTTPException(400, r["error"])
    return _public_view(r)


@app.post("/api/report")
def report(body: Link, request: Request):
    """The visitor chose to send this link to the analysts. Only the link and Shield's result are stored."""
    _limit(request, "report")
    r = linkcheck.check_link(body.url)
    if "error" in r:
        raise HTTPException(400, r["error"])
    if r["verdict"] == "official":
        return {"stored": False, "message": "Official site, nothing to report."}
    db.add_detection(r, "citizen", url=body.url.strip()[:2000])
    return {"stored": True}


@app.post("/api/chat")
def chat(body: Chat, request: Request):
    """Streams NDJSON: Shield's check of each link in the message, then the assistant's explanation."""
    from fastapi.responses import StreamingResponse
    from . import chat as chatbot
    _limit(request, "chat")
    msgs = [m.model_dump() for m in body.messages]
    return StreamingResponse(chatbot.run(msgs, _public_view), media_type="application/x-ndjson",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})
