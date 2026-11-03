"""
Shield backend + demo dashboard.

Run from the repo folder:
    python -m pip install -r requirements.txt
    python ml\\train_baseline.py              (once, creates the model)
    python -m uvicorn backend.app.main:app --reload

Dashboard: http://127.0.0.1:8000        API docs: http://127.0.0.1:8000/docs
"""

import csv
import os
import threading

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from . import alerts, ctlog, db, linkcheck
from .scoring import assess, model_info, reload_facts_model, reload_model, score_domain

app = FastAPI(title="Shield API", version="0.2")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

HERE = os.path.dirname(__file__)
DATA = os.path.join(HERE, "..", "..", "data")

training = {"running": False, "log": [], "last": None}


class Report(BaseModel):
    url: str
    note: str | None = None


class Label(BaseModel):
    is_phishing: bool


# ---------- pages ----------

# New analyst console (React, built from frontend/src/admin into frontend/dist/admin.html).
# Falls back to the classic static/index.html only if the built console is missing.
CONSOLE = os.path.join(HERE, "..", "..", "frontend", "dist")


@app.get("/", include_in_schema=False)
def dashboard():
    built = os.path.join(CONSOLE, "admin.html")
    if os.path.isfile(built):
        return FileResponse(built, headers={"Cache-Control": "no-cache"})
    return FileResponse(os.path.join(HERE, "static", "index.html"))


@app.get("/health")
def health():
    return {"status": "ok"}


# ---------- checking ----------

@app.get("/check")
def check(domain: str):
    """Score one domain (no saving)."""
    return score_domain(domain)


@app.post("/report")
def report(r: Report):
    """A citizen submits a suspicious link: check it and add it to the feed."""
    result = linkcheck.check_link(r.url)
    if "error" in result:
        raise HTTPException(400, result["error"])
    if result.get("verdict") != "official":
        result["id"] = db.add_detection(result, "citizen", url=r.url.strip(), note=r.note)
    return result


# ---------- live radar ----------

@app.post("/radar/start")
def radar_start(logs: int = 6):
    return {"started": ctlog.start(max_logs=logs), **ctlog.status()}


@app.post("/radar/stop")
def radar_stop():
    ctlog.stop()
    return ctlog.status()


@app.get("/radar")
def radar():
    return ctlog.status()


@app.post("/replay/load")
def replay_load():
    """Add the 66 real UAE-targeted fakes to the feed (for the demo)."""
    path = os.path.join(DATA, "uae_phishing_domains_real.csv")
    n = 0
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            res = score_domain(row["domain"])
            db.add_detection(res, "replay", note=f"Impersonates {row['impersonates']}")
            n += 1
    return {"loaded": n}


# ---------- feed, labels, alerts ----------

@app.get("/feed")
def feed(limit: int = 100, source: str | None = None, flagged_only: bool = True):
    return db.list_detections(limit=limit, source=source, flagged_only=flagged_only)


@app.post("/detections/{det_id}/label")
def label(det_id: int, body: Label):
    det = db.get_detection(det_id)
    if not det:
        raise HTTPException(404, "Not found")
    db.set_label(det["domain"], body.is_phishing)
    return {"domain": det["domain"], "status": "confirmed" if body.is_phishing else "legit"}


@app.post("/detections/{det_id}/alert")
def alert(det_id: int):
    """Analyst-approved alert email (demo: goes to the team inbox in .env)."""
    det = db.get_detection(det_id)
    if not det:
        raise HTTPException(404, "Not found")
    if det.get("status") == "legit":
        raise HTTPException(400, "Marked as not phishing; no alert sent")
    return alerts.send_alert(det)


@app.get("/alerts")
def alert_list():
    return db.list_alerts()


# ---------- investigation: domain facts, page check, evidence pack ----------

@app.get("/investigate")
def investigate(domain: str):
    """Name score + domain facts (registration age, registrar, hosting, certificate)."""
    return assess(domain, tls=True)


@app.post("/pagecheck")
def page_check(domain: str, url: str | None = None):
    """Open the page in the isolated server-side browser (never in the analyst's browser)."""
    from . import evidence, pagecheck
    from .features import clean
    d = clean(domain)
    out = os.path.join(evidence.EVIDENCE, evidence.slug(d))
    r = pagecheck.check_page(url or ("https://" + d), out, d)
    if r.get("screenshot"):
        r["screenshot_url"] = f"evidence/{evidence.slug(d)}/screenshot.png"
    return r


@app.post("/detections/{det_id}/evidence")
def detection_evidence(det_id: int, page: bool = True):
    """Takedown-ready evidence pack (facts + page check + bilingual takedown requests)."""
    from . import evidence
    det = db.get_detection(det_id)
    if not det:
        raise HTTPException(404, "Not found")
    ev = evidence.build(det["domain"], url=det.get("url"), det=det, page=page)
    db.set_evidence(det_id, ev["report_path"])
    return {k: ev[k] for k in ("domain", "report_path", "abuse_contacts", "summary_signs", "evidence_sha256",
                               "timeline", "report_links")} | {"page_verdict": (ev.get("page") or {}).get("verdict")}


@app.post("/evidence")
def evidence_for(domain: str, url: str | None = None, page: bool = True):
    from . import evidence
    ev = evidence.build(domain, url=url, page=page)
    return {k: ev[k] for k in ("domain", "report_path", "abuse_contacts", "summary_signs", "evidence_sha256")}


@app.get("/evidence/{name}/{file}", include_in_schema=False)
def evidence_file(name: str, file: str):
    from . import evidence
    if file not in ("report.html", "screenshot.png", "evidence.json", "pagecheck.json") or "/" in name or "\\" in name or ".." in name:
        raise HTTPException(404, "Not found")
    path = os.path.join(evidence.EVIDENCE, name, file)
    if not os.path.isfile(path):
        raise HTTPException(404, "Not found")
    return FileResponse(path)


# ---------- model ----------

def _retrain_job():
    import sys
    sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..")))
    from ml.retrain import retrain
    training.update(running=True, log=[])
    try:
        metrics = retrain(labels=db.all_labels(), log=lambda m: training["log"].append(str(m)))
        reload_model()
        reload_facts_model()
        linkcheck.reload_known()
        db.set_stat("model", metrics)
        training["last"] = metrics
    except Exception as ex:
        training["log"].append(f"Retrain failed: {ex}")
    finally:
        training["running"] = False


@app.post("/model/retrain")
def model_retrain():
    if training["running"]:
        return {"started": False, "reason": "already running"}
    threading.Thread(target=_retrain_job, daemon=True).start()
    return {"started": True}


@app.get("/model")
def model_status():
    return {"running": training["running"], "log": training["log"][-5:],
            "last": training["last"] or db.get_stats().get("model"), "model": model_info()}


@app.get("/stats")
def stats():
    s = db.get_stats()
    r = ctlog.status()
    s["certs_checked_now"] = r["certs_checked"]
    s["certs_per_second"] = r["certs_per_second"]
    s["uae_seen_now"] = r["uae_seen"]
    s["radar_running"] = r["running"]
    s["review"] = db.review_metrics()
    return s


@app.get("/review/queue")
def pending_review(limit: int = 100):
    """Analyst queue; only available on the Access-protected dashboard service."""
    return {"metrics": db.review_metrics(), "detections": db.review_queue(max(1, min(limit, 500)))}


@app.get("/review/brand-activity")
def recent_brand_activity(hours: int = 24):
    """Possible campaign leads for analysts; common brand alone is not proof of a campaign."""
    return {"window_hours": max(1, min(hours, 720)), "groups": db.brand_activity(hours),
            "note": "Shared brand and timing suggest review; verify hosting, registrar and page evidence before linking domains."}


# JS/CSS/fonts for the analyst console (frontend/dist/assets). Mounted last so API routes win.
if os.path.isdir(os.path.join(CONSOLE, "assets")):
    from fastapi.staticfiles import StaticFiles
    app.mount("/assets", StaticFiles(directory=os.path.join(CONSOLE, "assets")), name="console-assets")
