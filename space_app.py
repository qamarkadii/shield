"""
Shield on ONE port (for Hugging Face Spaces and other hosts that expose a single port).

    /          public "Is this link official?" site   (anyone)
    /admin/    analyst dashboard                       (password: SHIELD_ADMIN_PASSWORD)

Run:   python -m uvicorn space_app:app --host 0.0.0.0 --port 7860

Settings (Space "Settings -> Variables and secrets"):
    SHIELD_ADMIN_PASSWORD   required to open /admin (no password = dashboard locked)
    SHIELD_RADAR=1          start the live radar
    HF_TOKEN + SHIELD_BACKUP_REPO   keep the database across restarts (backup.py)
    RESEND_API_KEY, ALERT_FROM, ALERT_TO   alert emails over HTTPS (alerts.py)
"""

import base64
import hmac
import os
import threading
import time

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse, Response

from backend.app import backup, ctlog, linkcheck, scoring
from backend.app.main import app as dashboard_app
from backend.app.public import app as public_app

ADMIN_USER = "aida"


class AdminAuth:
    """HTTP Basic login in front of the dashboard. The browser asks once and remembers it."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        password = os.getenv("SHIELD_ADMIN_PASSWORD", "")
        if not password:
            res = PlainTextResponse("Dashboard locked: set SHIELD_ADMIN_PASSWORD in the Space settings.", 503)
            return await res(scope, receive, send)
        headers = dict(scope.get("headers") or [])
        auth = headers.get(b"authorization", b"").decode()
        ok = False
        if auth.startswith("Basic "):
            try:
                user, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
                ok = hmac.compare_digest(user, ADMIN_USER) and hmac.compare_digest(pw, password)
            except Exception:
                ok = False
        if not ok:
            res = Response("Login required", 401, {"WWW-Authenticate": 'Basic realm="Shield analysts"'})
            return await res(scope, receive, send)
        return await self.app(scope, receive, send)


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/admin", include_in_schema=False)
def admin_redirect():
    return RedirectResponse("/admin/")


app.mount("/admin", AdminAuth(dashboard_app))
app.mount("/", public_app)


def _nightly_feeds():
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from ml.retrain import download_feeds
    while True:
        try:
            print("Feeds:", download_feeds())
            print("Known phishing domains:", linkcheck.reload_known())
        except Exception as ex:
            print("Feed refresh failed:", ex)
        time.sleep(24 * 3600)


@app.on_event("startup")
def startup():
    print("Database:", backup.restore())
    print("Model:", "ok" if scoring.reload_model() else "MISSING - run python ml/train_baseline.py")
    threading.Thread(target=_nightly_feeds, daemon=True).start()     # downloads feeds now, then daily
    print("Backups every 10 min:", backup.start_loop())
    if os.getenv("SHIELD_RADAR") == "1":
        ctlog.start()
        print("Live radar started")
