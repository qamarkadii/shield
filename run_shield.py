"""
Run both Shield sites in ONE program (they share one copy of the model, which saves memory):

    analyst dashboard  ->  http://127.0.0.1:8000   (put behind Cloudflare Access login)
    public check site  ->  http://127.0.0.1:8001   (open to everyone)

Both listen on 127.0.0.1 only: nothing is reachable from the internet except through
the Cloudflare Tunnel.

    python run_shield.py                  run both
    python run_shield.py --radar          also start the live CT radar at startup (servers)

Settings can also come from environment variables: SHIELD_RADAR=1 starts the radar.
"""

import asyncio
import os
import sys

import uvicorn

from backend.app import ctlog
from backend.app.main import app as dashboard_app
from backend.app.public import app as public_app


async def main():
    # load the model and phishing lists now, so the first visitor doesn't wait
    from backend.app import linkcheck, scoring
    print("Loading model:", "ok" if scoring.reload_model() else "MISSING - run python ml/train_baseline.py")
    print("Known phishing domains loaded:", len(linkcheck.known_phishing()))
    if "--radar" in sys.argv or os.getenv("SHIELD_RADAR") == "1":
        ctlog.start()
        print("Live radar started.")
    servers = [
        uvicorn.Server(uvicorn.Config(dashboard_app, host="127.0.0.1", port=8000, log_level="warning")),
        uvicorn.Server(uvicorn.Config(public_app, host="127.0.0.1", port=8001, log_level="warning",
                                      proxy_headers=True, forwarded_allow_ips="127.0.0.1")),
    ]
    print("Shield running:\n  dashboard  http://127.0.0.1:8000\n  public     http://127.0.0.1:8001")
    await asyncio.gather(*(s.serve() for s in servers))


if __name__ == "__main__":
    asyncio.run(main())
