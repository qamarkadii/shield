"""
Check the Gmail settings in .env step by step, without starting Shield.

Run from the repo folder (with .venv active):
    python backend\\scripts\\test_email.py          checks connection + login only
    python backend\\scripts\\test_email.py --send   also sends one test email to ALERT_TO
"""

import os
import smtplib
import socket
import sys
from email.message import EmailMessage

from dotenv import dotenv_values

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
env_path = os.path.join(ROOT, ".env")
if not os.path.exists(env_path):
    sys.exit(f"No .env file at {env_path}. Run: copy .env.example .env")

cfg = dotenv_values(env_path)
host = cfg.get("SMTP_HOST", "")
user = cfg.get("SMTP_USER", "")
pw = (cfg.get("SMTP_PASSWORD") or "").replace(" ", "")
to = cfg.get("ALERT_TO", "")
print(f"SMTP_HOST={host}  SMTP_PORT={cfg.get('SMTP_PORT')}  SMTP_USER={user}  ALERT_TO={to}")
print(f"Password length: {len(pw)} (a Gmail App password is 16)")
if "your" in (user + to) or not pw or "your" in pw:
    print("!! .env still contains example values. Fill in your real ones.")

ok_login = False
for mode, port in [("STARTTLS", 587), ("SSL", 465)]:
    print(f"\n--- {mode} on port {port} ---")
    try:
        socket.create_connection((host, port), timeout=10).close()
        print("1. Network connection: OK")
    except Exception as ex:
        print(f"1. Network connection: FAILED ({ex})  -> this network blocks port {port}")
        continue
    try:
        server = smtplib.SMTP_SSL(host, port, timeout=20) if mode == "SSL" else smtplib.SMTP(host, port, timeout=20)
        if mode == "STARTTLS":
            server.ehlo(); server.starttls(); server.ehlo()
        print("2. Secure connection: OK")
        server.login(user, pw)
        print("3. Gmail login: OK")
        ok_login = True
        if "--send" in sys.argv:
            msg = EmailMessage()
            msg["Subject"], msg["From"], msg["To"] = "[Shield] Test email", user, to
            msg.set_content("If you can read this, Shield's alert emails work.")
            server.send_message(msg)
            print(f"4. Test email sent to {to}: OK (check Spam too)")
        server.quit()
        break
    except smtplib.SMTPAuthenticationError as ex:
        print(f"3. Gmail login: REJECTED -> wrong SMTP_USER or App password. {ex}")
        break
    except Exception as ex:
        print(f"FAILED: {type(ex).__name__}: {ex}")

print("\nResult:", "email settings work" if ok_login else "email not working yet (see the failed step above)")
