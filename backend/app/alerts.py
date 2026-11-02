"""
Alert emails to the responsible entity, sent only after an analyst approves.

DEMO SAFETY: during the hackathon every alert goes to ALERT_TO (your team's own inbox),
never to a real government address. Real recipients would be added only with the
entities' agreement (ENTITY_CONTACTS below stays empty until then).

Settings come from the .env file in the repo folder (see .env.example).
If no email settings are filled in, the email is saved to data/outbox/ instead,
so the demo still works offline.
"""

import hashlib
import json
import os
import smtplib
from email.message import EmailMessage

from dotenv import load_dotenv

from . import db

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
load_dotenv(os.path.join(ROOT, ".env"))
OUTBOX = os.path.join(ROOT, "data", "outbox")

# Brand -> entity responsible for it. Real addresses ONLY with the entity's agreement.
ENTITY_CONTACTS = {
    # "Salik": "security-team@example.ae",
}


def _settings():
    return {
        "host": os.getenv("SMTP_HOST", ""),
        "port": int(os.getenv("SMTP_PORT", "587")),
        "user": os.getenv("SMTP_USER", ""),
        "password": os.getenv("SMTP_PASSWORD", "").replace(" ", ""),   # Gmail shows it with spaces
        "sender": os.getenv("ALERT_FROM") or os.getenv("SMTP_USER", "shield-demo@localhost"),
        "demo_to": os.getenv("ALERT_TO", ""),
    }


def evidence(det: dict) -> dict:
    ev = {
        "domain": det["domain"],
        "url_reported": det.get("url"),
        "impersonates": det.get("brand"),
        "risk_score": det.get("score"),
        "verdict": det.get("verdict"),
        "reasons": det.get("reasons", []),
        "ml_probability": det.get("ml_probability"),
        "source": det.get("source"),
        "first_seen_utc": det.get("first_seen"),
        "last_seen_utc": det.get("last_seen"),
        "certificate_issuer": det.get("cert_issuer"),
        "ct_log": det.get("ct_log"),
        "analyst_status": det.get("status"),
    }
    body = json.dumps(ev, ensure_ascii=False, indent=2, sort_keys=True)
    ev["sha256"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return ev


def build_email(det: dict, recipient: str):
    ev = evidence(det)
    brand = det.get("brand") or "a UAE entity"
    msg = EmailMessage()
    msg["Subject"] = f"[Shield DEMO] Suspected impersonation of {brand}: {det['domain']}"
    msg["From"] = _settings()["sender"]
    msg["To"] = recipient
    reasons = "\n".join(f"  - {r}" for r in ev["reasons"]) or "  - (none recorded)"
    msg.set_content(f"""This is a DEMO alert from Shield (UAE Hackathon 2026, team AIDA).

Suspected impersonation of: {brand}
Domain: {det['domain']}
Risk score: {ev['risk_score']}/100 ({ev['verdict']})
First seen (UTC): {ev['first_seen_utc']}
Source: {ev['source']}{' - CT log: ' + ev['ct_log'] if ev.get('ct_log') else ''}
Certificate issuer: {ev.get('certificate_issuer') or 'n/a'}

Why it was flagged:
{reasons}

Recommended action: verify, then request blocking / takedown from the registrar,
hosting provider and telecom operators.

Evidence file attached (shield_evidence.json), SHA-256: {ev['sha256']}
Approved by a Shield analyst before sending. Do not open the domain in a normal browser.
""")
    msg.add_attachment(json.dumps(ev, ensure_ascii=False, indent=2).encode("utf-8"),
                       maintype="application", subtype="json", filename="shield_evidence.json")
    # evidence pack (evidence.py), if the analyst made one: report, screenshot, full evidence
    if det.get("evidence"):
        from .evidence import EVIDENCE
        folder = os.path.join(EVIDENCE, det["evidence"].strip("/").split("/")[1])
        for name, (mt, st) in {"report.html": ("text", "html"), "screenshot.png": ("image", "png"),
                               "evidence.json": ("application", "json")}.items():
            p = os.path.join(folder, name)
            if os.path.isfile(p) and os.path.getsize(p) < 5_000_000:
                with open(p, "rb") as f:
                    msg.add_attachment(f.read(), maintype=mt, subtype=st, filename=f"evidence_{name}")
    return msg


def smtp_send(msg, s):
    """Send through Gmail: try STARTTLS on the configured port (587), then SSL on 465.
    Some networks block one port but not the other. Returns the method that worked."""
    errors = []
    attempts = []
    if s["port"] == 465:
        attempts.append(("SSL", 465))
    else:
        attempts += [("STARTTLS", s["port"]), ("SSL", 465)]
    for mode, port in attempts:
        try:
            if mode == "SSL":
                with smtplib.SMTP_SSL(s["host"], port, timeout=20) as server:
                    server.login(s["user"], s["password"])
                    server.send_message(msg)
            else:
                with smtplib.SMTP(s["host"], port, timeout=20) as server:
                    server.ehlo()
                    server.starttls()
                    server.ehlo()
                    server.login(s["user"], s["password"])
                    server.send_message(msg)
            return f"{mode} port {port}"
        except smtplib.SMTPAuthenticationError as ex:
            raise RuntimeError("Gmail rejected the login: check SMTP_USER and the App password "
                               f"(no spaces). Details: {ex}") from ex
        except Exception as ex:
            errors.append(f"{mode} {port}: {ex}")
    raise RuntimeError("Could not reach Gmail. " + " | ".join(errors) +
                       " — try another network (e.g. phone hotspot) or pause antivirus email scanning.")


def resend_send(msg, s) -> str:
    """Send through Resend's HTTPS API (works where email ports are blocked, e.g. Hugging Face).
    Needs RESEND_API_KEY and ALERT_FROM on a domain verified in Resend (e.g. alerts@aidashield.tech)."""
    import base64
    import requests
    text = next(p for p in msg.walk() if p.get_content_type() == "text/plain").get_content()
    attachments = [{"filename": p.get_filename(), "content": base64.b64encode(p.get_payload(decode=True)).decode()}
                   for p in msg.walk() if p.get_filename()]
    r = requests.post("https://api.resend.com/emails", timeout=20,
                      headers={"Authorization": f"Bearer {os.getenv('RESEND_API_KEY')}"},
                      json={"from": s["sender"], "to": [s["demo_to"]], "subject": msg["Subject"],
                            "text": text, "attachments": attachments})
    if r.status_code >= 300:
        raise RuntimeError(f"Resend error {r.status_code}: {r.text[:200]}")
    return "Resend API"


def send_alert(det: dict) -> dict:
    s = _settings()
    brand = det.get("brand") or ""
    recipient = s["demo_to"] or "team-inbox-not-set@localhost"
    real_contact = ENTITY_CONTACTS.get(brand)
    msg = build_email(det, recipient)

    if os.getenv("RESEND_API_KEY") and s["demo_to"]:
        try:
            how = resend_send(msg, s)
            status, detail = "sent", f"Emailed to demo inbox {recipient} ({how})"
        except Exception as ex:
            status, detail = "failed", f"Email error: {ex}"
    elif s["host"] and s["user"] and s["password"] and s["demo_to"]:
        try:
            how = smtp_send(msg, s)
            status = "sent"
            detail = f"Emailed to demo inbox {recipient} ({how})"
        except Exception as ex:
            status, detail = "failed", f"Email error: {ex}"
    else:
        os.makedirs(OUTBOX, exist_ok=True)
        path = os.path.join(OUTBOX, f"alert_{det['id']}_{det['domain'].replace('.', '_')}.eml")
        with open(path, "wb") as f:
            f.write(bytes(msg))
        status = "saved"
        detail = f"No email settings in .env, saved to {os.path.normpath(path)}"

    if real_contact:
        detail += f" (entity contact on file: {real_contact}, not used in demo)"
    db.add_alert(det["domain"], recipient, msg["Subject"], status, detail)
    return {"status": status, "detail": detail, "subject": msg["Subject"], "recipient": recipient}
