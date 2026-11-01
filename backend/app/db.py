"""
Shield database (SQLite, one file: data/shield.db).

Tables
- detections: every domain Shield flagged (live certificates, citizen reports, replay)
- labels:     analyst decisions (phishing / legit) -> used to retrain the model
- alerts:     alert emails sent (or saved to the outbox) for each domain
- stats:      counters (certificates checked, etc.)
"""

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "shield.db")
_lock = threading.Lock()
_conn = None


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def conn():
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.executescript("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            url TEXT,
            source TEXT NOT NULL,            -- live / citizen / replay
            score INTEGER, verdict TEXT, brand TEXT,
            ml_probability REAL, reasons TEXT,
            cert_issuer TEXT, ct_log TEXT, note TEXT,
            status TEXT DEFAULT 'pending',   -- pending / confirmed / legit
            first_seen TEXT, last_seen TEXT,
            UNIQUE(domain, source)
        );
        CREATE TABLE IF NOT EXISTS labels (
            domain TEXT PRIMARY KEY, is_phishing INTEGER, labelled_at TEXT
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT, recipient TEXT, subject TEXT, status TEXT,
            detail TEXT, created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS stats (key TEXT PRIMARY KEY, value TEXT);
        """)
    return _conn


def add_detection(result: dict, source: str, url=None, cert_issuer=None, ct_log=None, note=None):
    """Insert or refresh a detection. Returns the row id."""
    with _lock:
        c = conn()
        t = now()
        c.execute("""
        INSERT INTO detections (domain, url, source, score, verdict, brand, ml_probability,
                                reasons, cert_issuer, ct_log, note, first_seen, last_seen)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(domain, source) DO UPDATE SET
            url=COALESCE(excluded.url, url), score=excluded.score, verdict=excluded.verdict,
            brand=excluded.brand, ml_probability=excluded.ml_probability,
            reasons=excluded.reasons, note=COALESCE(excluded.note, note), last_seen=excluded.last_seen
        """, (result["domain"], url, source, result.get("score"), result.get("verdict"),
              result.get("brand"), result.get("ml_probability"),
              json.dumps(result.get("reasons", []), ensure_ascii=False),
              cert_issuer, ct_log, note, t, t))
        c.commit()
        row = c.execute("SELECT id FROM detections WHERE domain=? AND source=?",
                        (result["domain"], source)).fetchone()
        return row["id"]


def _row(r):
    d = dict(r)
    d["reasons"] = json.loads(d.get("reasons") or "[]")
    return d


def list_detections(limit=100, source=None, min_score=0):
    q = "SELECT * FROM detections WHERE score >= ?"
    args = [min_score]
    if source:
        q += " AND source = ?"
        args.append(source)
    q += " ORDER BY last_seen DESC, score DESC LIMIT ?"
    args.append(limit)
    with _lock:
        return [_row(r) for r in conn().execute(q, args).fetchall()]


def get_detection(det_id: int):
    with _lock:
        r = conn().execute("SELECT * FROM detections WHERE id=?", (det_id,)).fetchone()
    return _row(r) if r else None


def set_label(domain: str, is_phishing: bool):
    with _lock:
        c = conn()
        c.execute("INSERT OR REPLACE INTO labels VALUES (?,?,?)", (domain, int(is_phishing), now()))
        c.execute("UPDATE detections SET status=? WHERE domain=?",
                  ("confirmed" if is_phishing else "legit", domain))
        c.commit()


def all_labels():
    with _lock:
        return [dict(r) for r in conn().execute("SELECT domain, is_phishing FROM labels").fetchall()]


def add_alert(domain, recipient, subject, status, detail=""):
    with _lock:
        c = conn()
        c.execute("INSERT INTO alerts (domain, recipient, subject, status, detail, created_at) VALUES (?,?,?,?,?,?)",
                  (domain, recipient, subject, status, detail, now()))
        c.commit()


def list_alerts(limit=50):
    with _lock:
        return [dict(r) for r in conn().execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]


def bump(key: str, n: int = 1):
    with _lock:
        c = conn()
        c.execute("INSERT INTO stats VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?",
                  (key, str(n), n))
        c.commit()


def set_stat(key: str, value):
    with _lock:
        c = conn()
        c.execute("INSERT OR REPLACE INTO stats VALUES (?, ?)", (key, json.dumps(value)))
        c.commit()


def get_stats():
    with _lock:
        c = conn()
        out = {}
        for r in c.execute("SELECT key, value FROM stats").fetchall():
            try:
                out[r["key"]] = json.loads(r["value"])
            except (ValueError, TypeError):
                out[r["key"]] = r["value"]
        out["flagged"] = c.execute("SELECT COUNT(*) FROM detections WHERE score >= 30").fetchone()[0]
        out["high_risk"] = c.execute("SELECT COUNT(*) FROM detections WHERE score >= 60").fetchone()[0]
        out["citizen_reports"] = c.execute("SELECT COUNT(*) FROM detections WHERE source='citizen'").fetchone()[0]
        out["alerts_sent"] = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        out["labels"] = c.execute("SELECT COUNT(*) FROM labels").fetchone()[0]
        return out
