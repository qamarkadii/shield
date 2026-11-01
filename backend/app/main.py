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
from .scoring import model_info, reload_model, score_domain

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

@app.get("/", include_in_schema=False)
def dashboard():
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


# ---------- model ----------

def _retrain_job():
    import sys
    sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..")))
    from ml.retrain import retrain
    training.update(running=True, log=[])
    try:
        metrics = retrain(labels=db.all_labels(), log=lambda m: training["log"].append(str(m)))
        reload_model()
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
    return s
