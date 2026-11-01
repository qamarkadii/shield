"""
Shield - tonight's test: is the live certificate stream working?

Setup:   pip install certstream
Run:     python certstream_test.py
Stop:    Ctrl + C

It prints every newly issued certificate whose domain mentions a UAE brand.
Leave it running ~10 minutes. Any hits = the Radar idea works live.
"""

import datetime
import certstream

# Brand keywords to watch (add more as you build the brand list)
KEYWORDS = [
    "salik", "uaepass", "uae-pass", "dubaipolice", "dubai-police",
    "adpolice", "rta", "emiratespost", "emirates-post", "tamm",
    "icp", "moi", "tdra", "etisalat", "du-ae", "nol", "rakbank",
    "enbd", "emiratesnbd", "adcb", "fab", "mashreq",
]

# Real official domains, so they don't count as hits (verify and extend)
OFFICIAL = ["salik.ae", "uaepass.ae", "dubaipolice.gov.ae", "rta.ae", "u.ae"]

seen = 0
hits = 0


def is_official(domain):
    return any(domain == d or domain.endswith("." + d) for d in OFFICIAL)


def on_message(message, context):
    global seen, hits
    if message.get("message_type") != "certificate_update":
        return
    domains = message["data"]["leaf_cert"]["all_domains"]
    seen += 1
    if seen % 5000 == 0:
        print(f"... {seen} certificates checked, {hits} hits so far")
    for domain in domains:
        d = domain.lower().lstrip("*.")
        if is_official(d):
            continue
        matched = [k for k in KEYWORDS if k in d]
        if matched:
            hits += 1
            now = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"[{now}] {d}   <- matches: {', '.join(matched)}")


def on_error(instance, exception):
    print("Connection error:", exception)
    print("If this keeps happening, the public feed is down -> use crt.sh as backup.")


print("Connecting to the certificate stream... (Ctrl + C to stop)")
certstream.listen_for_events(
    on_message,
    on_error=on_error,
    url="wss://certstream.calidog.io/",
)
