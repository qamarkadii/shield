"""
Keep the database across restarts on hosts with a temporary disk (Hugging Face Spaces).

If HF_TOKEN and SHIELD_BACKUP_REPO (e.g. "yourname/shield-data", a PRIVATE dataset) are set:
  - at startup: download the last saved shield.db (if there is one)
  - every 10 minutes: save a consistent copy of shield.db to that dataset
Without those settings it does nothing (laptop / normal servers keep their disk).
"""

import os
import shutil
import sqlite3
import tempfile
import threading

from . import db

INTERVAL = 600
FILENAME = "shield.db"


def _config():
    token, repo = os.getenv("HF_TOKEN"), os.getenv("SHIELD_BACKUP_REPO")
    return (token, repo) if token and repo else (None, None)


def enabled() -> bool:
    return _config()[0] is not None


def restore() -> str:
    token, repo = _config()
    if not token:
        return "backup off"
    try:
        from huggingface_hub import hf_hub_download
        path = hf_hub_download(repo_id=repo, repo_type="dataset", filename=FILENAME, token=token)
        os.makedirs(os.path.dirname(db.DB_PATH), exist_ok=True)
        shutil.copyfile(path, db.DB_PATH)
        return f"restored database from {repo}"
    except Exception as ex:          # first run: nothing saved yet
        return f"no backup restored ({type(ex).__name__})"


def save() -> str:
    token, repo = _config()
    if not token or not os.path.exists(db.DB_PATH):
        return "nothing to save"
    from huggingface_hub import HfApi
    api = HfApi(token=token)
    api.create_repo(repo_id=repo, repo_type="dataset", private=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        copy = os.path.join(tmp, FILENAME)
        src = sqlite3.connect(db.DB_PATH)
        dst = sqlite3.connect(copy)
        with dst:
            src.backup(dst)          # consistent snapshot even while Shield is writing
        src.close()
        dst.close()
        api.upload_file(path_or_fileobj=copy, path_in_repo=FILENAME, repo_id=repo,
                        repo_type="dataset", commit_message="Shield database backup")
    return f"saved to {repo}"


def start_loop():
    if not enabled():
        return False

    def loop():
        stop = threading.Event()
        while not stop.wait(INTERVAL):
            try:
                save()
            except Exception as ex:
                print("Backup failed:", ex)
    threading.Thread(target=loop, daemon=True).start()
    return True
