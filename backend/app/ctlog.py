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
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from . import db
from .scoring import score_domain, uae_reason

LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
HEADERS = {"User-Agent": "Shield-hackathon-radar/0.2"}

state = {
    "running": False,
    "logs": [],
    "certs_checked": 0,
    "matches": 0,
    "uae_seen": 0,
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

def pick_logs(max_logs=6):
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

_lock = threading.Lock()
_seen_set, _seen_order = set(), deque()
_rate = deque(maxlen=60)          # (time, certs_checked) samples for certs/second


def _first_time(fp: bytes) -> bool:
    """The same certificate is published in 2-3 logs; count it once."""
    with _lock:
        if fp in _seen_set:
            return False
        _seen_set.add(fp)
        _seen_order.append(fp)
        if len(_seen_order) > 300_000:
            _seen_set.discard(_seen_order.popleft())
        return True


def _process(entries, log_name):
    for e in entries:
        try:
            cert = cert_from_entry(e["leaf_input"], e.get("extra_data", ""))
        except Exception:
            continue
        if cert is None or not _first_time(cert.fingerprint(hashes.SHA256())):
            continue
        names = names_from_cert(cert)
        with _lock:
            state["certs_checked"] += 1
            if names:
                state["recent"].appendleft(names[0])
        for name in names:
            why = uae_reason(name)
            if not why:
                continue
            result = score_domain(name)
            with _lock:
                state["uae_seen"] += 1
                if result["score"] >= 30 and result["verdict"] != "official":
                    state["matches"] += 1
            # every UAE-related domain goes to the UAE watch; only score >= 30 counts as flagged
            db.add_detection(result, "live", cert_issuer=issuer_of(cert), ct_log=log_name, note=why)


def _reader(lg, batch, max_lag):
    """One thread per log: read every new entry, as fast as the log allows."""
    url, name = lg["url"], lg["name"]
    session = requests.Session()
    session.headers.update(HEADERS)
    pos, size, backoff = None, 0, 1
    while not _stop.is_set():
        try:
            if pos is None or pos >= size:
                size = session.get(url + "ct/v1/get-sth", timeout=15).json()["tree_size"]
                if pos is None or size - pos > max_lag:
                    pos = max(0, size - batch)          # start at (or jump to) the newest entries
                if pos >= size:
                    _stop.wait(2)                       # caught up: wait for new certificates
                    continue
            end = min(pos + batch - 1, size - 1)
            r = session.get(url + "ct/v1/get-entries", params={"start": pos, "end": end}, timeout=20)
            if r.status_code == 429:                    # the log asks us to slow down
                _stop.wait(backoff)
                backoff = min(backoff * 2, 30)
                continue
            r.raise_for_status()
            entries = r.json().get("entries", [])
            _process(entries, name)
            pos += max(len(entries), 1)
            backoff = 1
        except Exception as ex:
            with _lock:
                state["errors"].appendleft(f"{name}: {str(ex)[:160]}")
            _stop.wait(3)


def _run(max_logs, batch, max_lag):
    try:
        logs = pick_logs(max_logs)
    except Exception as ex:
        state["errors"].appendleft(f"Could not load CT log list: {ex}")
        state["running"] = False
        return
    if not logs:
        state["errors"].appendleft("No usable CT logs found in Google's log list.")
        state["running"] = False
        return
    state["logs"] = [lg["name"] for lg in logs]
    threads = [threading.Thread(target=_reader, args=(lg, batch, max_lag), daemon=True) for lg in logs]
    for t in threads:
        t.start()
    while not _stop.is_set():
        _rate.append((time.time(), state["certs_checked"]))
        db.set_stat("certs_checked_total", state["certs_checked"])
        _stop.wait(5)
    for t in threads:
        t.join(timeout=5)
    state["running"] = False


def start(max_logs=6, batch=256, max_lag=50_000):
    global _thread
    if state["running"]:
        return False
    _stop.clear()
    state.update(running=True, started_at=db.now())
    _thread = threading.Thread(target=_run, args=(max_logs, batch, max_lag), daemon=True)
    _thread.start()
    return True


def stop():
    _stop.set()
    return True


def certs_per_second():
    if len(_rate) < 2:
        return 0.0
    (t0, c0), (t1, c1) = _rate[0], _rate[-1]
    return round((c1 - c0) / (t1 - t0), 1) if t1 > t0 else 0.0


def status():
    return {
        "running": state["running"],
        "logs": state["logs"],
        "certs_checked": state["certs_checked"],
        "certs_per_second": certs_per_second(),
        "uae_seen": state["uae_seen"],
        "matches": state["matches"],
        "started_at": state["started_at"],
        "recent": list(state["recent"])[:15],
        "errors": list(state["errors"])[:5],
    }
