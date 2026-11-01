"""
Live Radar: reads new certificates DIRECTLY from public Certificate Transparency logs
(RFC 6962 API), so there is no middleman server (like CertStream) that can go down.

How it works
1. Downloads Google's official list of CT logs and picks a few that are live now.
2. Every few seconds asks each log for its newest entries.
3. Pulls the domain names out of each certificate.
4. Domains that mention a watched UAE brand are scored and saved as detections.
   Everything is counted, so the dashboard shows how many certificates were checked.

Logs grow by hundreds of certificates per second; on a laptop we read the newest
window of each log, which is a sample of the full stream (the dashboard says so).
"""

import base64
import struct
import threading
import time
from collections import deque

import requests
from cryptography import x509
from cryptography.x509.oid import NameOID

from . import db
from .scoring import mentions_brand, score_domain

LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
HEADERS = {"User-Agent": "Shield-hackathon-radar/0.2"}

state = {
    "running": False,
    "logs": [],
    "certs_checked": 0,
    "matches": 0,
    "errors": deque(maxlen=10),
    "recent": deque(maxlen=25),    # newest domains seen (all, for the live ticker)
    "started_at": None,
}
_thread = None
_stop = threading.Event()


# ---------- parsing (RFC 6962) ----------

def _read_len3(buf: bytes, pos: int):
    n = int.from_bytes(buf[pos:pos + 3], "big")
    return buf[pos + 3: pos + 3 + n], pos + 3 + n


def cert_from_entry(leaf_input_b64: str, extra_data_b64: str):
    """Return the certificate (x509 object) inside one CT log entry, or None."""
    leaf = base64.b64decode(leaf_input_b64)
    # MerkleTreeLeaf: version(1) leaf_type(1) timestamp(8) entry_type(2) ...
    entry_type = struct.unpack(">H", leaf[10:12])[0]
    if entry_type == 0:                       # normal certificate
        der, _ = _read_len3(leaf, 12)
    elif entry_type == 1:                     # precertificate: full cert is in extra_data
        extra = base64.b64decode(extra_data_b64)
        der, _ = _read_len3(extra, 0)
    else:
        return None
    return x509.load_der_x509_certificate(der)


def names_from_cert(cert) -> list:
    names = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    if not names:
        names = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    clean = []
    for n in names:
        n = n.lower().lstrip("*.").strip()
        if n and n not in clean:
            clean.append(n)
    return clean


def issuer_of(cert) -> str:
    try:
        org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        return org[0].value if org else cert.issuer.rfc4514_string()
    except Exception:
        return ""


# ---------- log discovery ----------

def pick_logs(max_logs=3):
    """Choose currently-live RFC 6962 logs from Google's official log list."""
    data = requests.get(LOG_LIST_URL, headers=HEADERS, timeout=20).json()
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    found = []
    for op in data.get("operators", []):
        for log in op.get("logs", []):          # "logs" = RFC 6962 API (tiled logs are separate)
            st = log.get("state", {})
            if "usable" not in st and "qualified" not in st:
                continue
            ti = log.get("temporal_interval")
            if ti and not (ti["start_inclusive"] <= now < ti["end_exclusive"]):
                continue
            found.append({"name": f'{op.get("name")} - {log.get("description")}',
                          "url": log["url"].rstrip("/") + "/"})
    # spread across operators for variety
    seen_ops, picked = set(), []
    for lg in found:
        op = lg["name"].split(" - ")[0]
        if op not in seen_ops:
            picked.append(lg)
            seen_ops.add(op)
        if len(picked) >= max_logs:
            break
    return picked or found[:max_logs]


# ---------- polling ----------

def _process(entries, log_name):
    for e in entries:
        try:
            cert = cert_from_entry(e["leaf_input"], e.get("extra_data", ""))
        except Exception:
            continue
        if cert is None:
            continue
        state["certs_checked"] += 1
        names = names_from_cert(cert)
        if names:
            state["recent"].appendleft(names[0])
        for name in names:
            if not mentions_brand(name):
                continue
            result = score_domain(name)
            if result["verdict"] == "official" or result["score"] < 30:
                continue
            state["matches"] += 1
            db.add_detection(result, "live", cert_issuer=issuer_of(cert), ct_log=log_name)


def _run(max_logs, batch, interval):
    try:
        logs = pick_logs(max_logs)
    except Exception as ex:
        state["errors"].appendleft(f"Could not load CT log list: {ex}")
        state["running"] = False
        return
    state["logs"] = [lg["name"] for lg in logs]
    pos = {lg["url"]: None for lg in logs}
    session = requests.Session()
    session.headers.update(HEADERS)
    last_saved = 0
    while not _stop.is_set():
        for lg in logs:
            url = lg["url"]
            try:
                size = session.get(url + "ct/v1/get-sth", timeout=15).json()["tree_size"]
                if pos[url] is None or size - pos[url] > batch * 20:
                    pos[url] = max(0, size - batch)      # jump to the newest window
                if pos[url] < size:
                    end = min(pos[url] + batch - 1, size - 1)
                    r = session.get(url + "ct/v1/get-entries",
                                    params={"start": pos[url], "end": end}, timeout=20)
                    entries = r.json().get("entries", [])
                    _process(entries, lg["name"])
                    pos[url] += max(len(entries), 1)
            except Exception as ex:
                state["errors"].appendleft(f"{lg['name']}: {ex}")
        if state["certs_checked"] - last_saved >= 500:
            db.set_stat("certs_checked_total", state["certs_checked"])
            last_saved = state["certs_checked"]
        _stop.wait(interval)
    state["running"] = False


def start(max_logs=3, batch=256, interval=2.0):
    global _thread
    if state["running"]:
        return False
    _stop.clear()
    state.update(running=True, started_at=db.now())
    _thread = threading.Thread(target=_run, args=(max_logs, batch, interval), daemon=True)
    _thread.start()
    return True


def stop():
    _stop.set()
    return True


def status():
    return {
        "running": state["running"],
        "logs": state["logs"],
        "certs_checked": state["certs_checked"],
        "matches": state["matches"],
        "started_at": state["started_at"],
        "recent": list(state["recent"])[:15],
        "errors": list(state["errors"])[:5],
    }
