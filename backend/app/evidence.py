"""
Takedown-ready evidence pack for one suspicious domain.

    build(domain, url=None, det=None, page=True) -> dict   (also written to data/evidence/<slug>/)

Collects, in one place:
  - Shield's score, level and reasons (the name, the learned model, the UAE rules)
  - domain facts (enrich.py): registration date and age, registrar and its abuse e-mail,
    hosting network / country and the host's abuse e-mail, DNS records, certificate
  - the page check (pagecheck.py, isolated browser): screenshot, what the page asks for,
    which brand it claims to be, look-alike score
  - a timeline (first seen by Shield, registered, certificate issued, checked)
  - ready-to-send takedown requests in English and Arabic for the registrar and the host,
    and links to report it to Google Safe Browsing, Microsoft, Netcraft and APWG
  - SHA-256 of every evidence file, so the pack can be shown to be unchanged

Files: report.html (bilingual, printable), evidence.json, screenshot.png, pagecheck.json.
Nothing is sent from here: the analyst reviews the pack and sends it (alerts.py).
"""

import hashlib
import html
import json
import os
import re
from datetime import datetime, timezone

from . import enrich, pagecheck
from .features import clean, split_domain
from .i18n import BRAND_AR, to_ar
from .scoring import score_domain

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
EVIDENCE = os.path.normpath(os.path.join(ROOT, "data", "evidence"))

REPORT_LINKS = [
    ("Google Safe Browsing", "https://safebrowsing.google.com/safebrowsing/report_phish/?url={url}"),
    ("Microsoft (SmartScreen)", "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest"),
    ("Netcraft", "https://report.netcraft.com/report"),
    ("APWG (e-mail)", "mailto:reportphishing@apwg.org"),
]


def slug(domain: str) -> str:
    return re.sub(r"[^a-z0-9.-]", "_", domain.lower())[:120]


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _defang(s: str) -> str:
    """example[.]com / hxxps:// : safe to paste in e-mails and documents."""
    return (s or "").replace("http", "hxxp").replace(".", "[.]")


def takedown_text(ev: dict, to: str) -> dict:
    d, brand = ev["domain"], ev.get("brand") or "a UAE government entity or company"
    off = ", ".join(ev.get("official_domains") or []) or "n/a"
    lines = "\n".join(f"  - {r}" for r in ev["summary_signs"][:8])
    ip = ((ev.get("facts") or {}).get("hosting") or {}).get("ip") or "n/a"
    created = ((ev.get("facts") or {}).get("rdap") or {}).get("created") or "unknown"
    en = f"""Subject: Phishing site impersonating {brand}: {_defang(d)}

Hello {to} abuse team,

We are reporting a phishing website that impersonates {brand} and targets people in the UAE.

  Domain:            {_defang(d)}
  Reported link:     {_defang(ev.get('url') or d)}
  IP address:        {ip}
  Registered on:     {created}
  Official site(s):  {off}
  Checked at (UTC):  {ev['checked_at']}

Evidence:
{lines}

A screenshot and the full evidence file (SHA-256 {ev.get('evidence_sha256', 'n/a')}) are attached.
Please suspend the domain / remove the content in line with your abuse policy.

Thank you,
Shield (UAE anti-phishing), on behalf of the analyst who reviewed this report
"""
    brand_ar = BRAND_AR.get(ev.get("brand") or "", ev.get("brand") or "جهة إماراتية")
    lines_ar = "\n".join(f"  - {to_ar(r)}" for r in ev["summary_signs"][:8])
    ar = f"""الموضوع: موقع تصيّد احتيالي ينتحل صفة {brand_ar}: {_defang(d)}

فريق مكافحة إساءة الاستخدام لدى {to}،

نبلغكم عن موقع تصيّد احتيالي ينتحل صفة {brand_ar} ويستهدف المقيمين في دولة الإمارات.

  النطاق:            {_defang(d)}
  الرابط المُبلَّغ عنه: {_defang(ev.get('url') or d)}
  عنوان IP:          {ip}
  تاريخ التسجيل:      {created}
  الموقع الرسمي:      {off}
  وقت الفحص (UTC):   {ev['checked_at']}

الأدلة:
{lines_ar}

مرفق لقطة شاشة وملف الأدلة الكامل (SHA-256: {ev.get('evidence_sha256', 'n/a')}).
نرجو تعليق النطاق أو إزالة المحتوى وفق سياسة إساءة الاستخدام لديكم.

مع الشكر،
درع (منصة إماراتية لمكافحة التصيّد)، نيابةً عن المحلل الذي راجع البلاغ
"""
    return {"en": en, "ar": ar}


def build(domain: str, url: str | None = None, det: dict | None = None, page: bool = True) -> dict:
    d = clean(domain or url or "")
    _, registered = split_domain(d)
    out_dir = os.path.join(EVIDENCE, slug(d))
    os.makedirs(out_dir, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    s = score_domain(d)
    fx = enrich.facts(d, tls=True)
    pc = pagecheck.check_page(url or ("https://" + d), out_dir, d) if page else None

    from .registry import UAE_BRANDS
    official = next((doms for name, doms in UAE_BRANDS.values() if name == s.get("brand")), [])
    signs = list(s.get("reasons") or [])
    rd, host, cert = fx.get("rdap") or {}, fx.get("hosting") or {}, fx.get("certificate") or {}
    if rd.get("age_days") is not None:
        signs.append(f"Domain registered {rd['age_days']} days ago ({rd.get('created')}) at {rd.get('registrar') or 'unknown registrar'}")
    if cert.get("issued_days_ago") is not None:
        signs.append(f"Certificate issued {cert['issued_days_ago']} days ago by {cert.get('issuer') or '?'}")
    if pc:
        signs += pc.get("signs", [])

    contacts = []
    if rd.get("registrar_abuse_email"):
        contacts.append({"who": f"Registrar: {rd.get('registrar') or '?'}", "email": rd["registrar_abuse_email"]})
    ab = host.get("abuse") or {}
    if ab.get("abuse_email"):
        contacts.append({"who": f"Hosting: {host.get('as_name') or ab.get('network') or '?'}", "email": ab["abuse_email"]})

    timeline = []
    if rd.get("created"):
        timeline.append((rd["created"], "Domain registered"))
    if cert.get("issued_days_ago") is not None:
        from datetime import timedelta
        timeline.append(((datetime.now(timezone.utc) - timedelta(days=cert["issued_days_ago"])).date().isoformat(),
                         f"HTTPS certificate issued ({cert.get('issuer')})"))
    if det and det.get("first_seen"):
        timeline.append((det["first_seen"][:10], f"First seen by Shield ({det.get('source')})"))
    timeline.append((now[:10], "Evidence pack created"))
    timeline.sort()

    ev = {"domain": d, "registered_domain": registered, "url": url, "checked_at": now,
          "brand": s.get("brand"), "official_domains": official,
          "shield": {k: s.get(k) for k in ("score", "verdict", "live_probability", "rule", "reasons")},
          "facts": fx, "page": pc, "summary_signs": signs, "abuse_contacts": contacts,
          "timeline": [{"date": t, "event": e} for t, e in timeline],
          "report_links": [{"name": n, "url": u.format(url=(url or "https://" + d))} for n, u in REPORT_LINKS],
          "detection": {k: det.get(k) for k in ("id", "source", "first_seen", "last_seen", "status")} if det else None}
    files = {}
    for name in ("screenshot.png", "pagecheck.json"):
        p = os.path.join(out_dir, name)
        if os.path.exists(p):
            files[name] = _sha(p)
    ev["files_sha256"] = files
    body = json.dumps(ev, ensure_ascii=False, indent=1, sort_keys=True, default=str)
    ev["evidence_sha256"] = hashlib.sha256(body.encode("utf-8")).hexdigest()
    ev["takedown"] = {c["email"]: takedown_text(ev, c["who"]) for c in contacts} or \
                     {"(no abuse contact found)": takedown_text(ev, "the registrar / hosting provider")}
    with open(os.path.join(out_dir, "evidence.json"), "w", encoding="utf-8") as f:
        json.dump(ev, f, ensure_ascii=False, indent=1, default=str)
    with open(os.path.join(out_dir, "report.html"), "w", encoding="utf-8") as f:
        f.write(render_html(ev))
    ev["folder"] = out_dir
    ev["report_path"] = f"/evidence/{slug(d)}/report.html"
    return ev


def render_html(ev: dict) -> str:
    e = lambda x: html.escape(str(x if x is not None else "—"))
    fx, sh = ev.get("facts") or {}, ev.get("shield") or {}
    rd, host, cert = fx.get("rdap") or {}, fx.get("hosting") or {}, fx.get("certificate") or {}
    pc = ev.get("page") or {}
    rows = lambda pairs: "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in pairs)
    signs = "".join(f"<li>{e(s)}</li>" for s in ev["summary_signs"])
    signs_ar = "".join(f"<li>{e(to_ar(s))}</li>" for s in ev["summary_signs"])
    contacts = "".join(f"<li>{e(c['who'])}: <code>{e(c['email'])}</code></li>" for c in ev["abuse_contacts"]) or "<li>None found</li>"
    links = "".join(f"<li><a href='{e(l['url'])}'>{e(l['name'])}</a></li>" for l in ev["report_links"])
    tl = "".join(f"<tr><td>{e(t['date'])}</td><td>{e(t['event'])}</td></tr>" for t in ev["timeline"])
    shot = "<img src='screenshot.png' alt='Screenshot of the page' style='max-width:100%;border:1px solid #ccc'>" \
        if "screenshot.png" in ev.get("files_sha256", {}) else "<p>No screenshot (page not opened or not reachable).</p>"
    mails = "".join(f"<h3>To {e(k)}</h3><pre>{e(v['en'])}</pre><pre dir='rtl' lang='ar'>{e(v['ar'])}</pre>"
                    for k, v in ev.get("takedown", {}).items())
    files = "".join(f"<tr><td>{e(k)}</td><td><code>{e(v)}</code></td></tr>" for k, v in ev.get("files_sha256", {}).items())
    asks = ", ".join(k for k, v in (pc.get("asks_for") or {}).items() if v) or "nothing sensitive found"
    look = pc.get("looks_like") or []
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Shield evidence: {e(ev['domain'])}</title>
<style>body{{font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:960px;margin:24px auto;padding:0 16px;color:#111;background:#fff}}
table{{border-collapse:collapse;width:100%;margin:8px 0}}th,td{{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}}
th{{width:30%;background:#f6f6f6}}pre{{white-space:pre-wrap;background:#f6f6f6;padding:10px;border-radius:6px}}
.v{{font-size:20px;font-weight:700}}.ar{{direction:rtl;text-align:right}}code{{word-break:break-all}}</style></head><body>
<h1>Shield evidence pack</h1>
<p class="v">{e(_defang(ev['domain']))} — {e(sh.get('verdict'))} (score {e(sh.get('score'))}/100)</p>
<p>Impersonates: <b>{e(ev.get('brand') or 'no specific brand')}</b>; official: {e(', '.join(ev.get('official_domains') or []) or '—')}.
Checked {e(ev['checked_at'])} UTC. Evidence SHA-256: <code>{e(ev['evidence_sha256'])}</code></p>
<h2>Why it is suspicious</h2><ul>{signs}</ul>
<div class="ar" dir="rtl" lang="ar"><h2>أسباب الاشتباه</h2><ul>{signs_ar}</ul></div>
<h2>Page (opened in an isolated browser)</h2>{shot}
<table>{rows([("Final address", _defang(pc.get('final_url') or '—')), ("Title", pc.get('title')), ("Asks for", asks),
              ("Claims to be", ', '.join(pc.get('claims_brand_off_domain') or []) or '—'),
              ("Looks like", ', '.join(f"{x['brand']} {x['similarity']:.0%}" for x in look) or '—'),
              ("Form sends data to", ', '.join(pc.get('form_targets') or []) or '—'), ("Page verdict", pc.get('verdict'))])}</table>
<h2>Domain facts</h2>
<table>{rows([("Registered", f"{rd.get('created') or 'unknown'} ({rd.get('age_days')} days ago)" if rd.get('age_days') is not None else rd.get('not_applicable') or 'unknown'),
              ("Registrar", rd.get('registrar')), ("Registered until", rd.get('expires')), ("Status", ', '.join(rd.get('status') or [])),
              ("IP / network", f"{host.get('ip')} — AS{host.get('asn')} {host.get('as_name') or ''}" if host else '—'),
              ("Hosting country", host.get('country')), ("Name servers", ', '.join((fx.get('dns') or {}).get('ns') or [])),
              ("Mail (MX)", ', '.join((fx.get('dns') or {}).get('mx') or []) or 'none'),
              ("Certificate", f"{cert.get('issuer')} — issued {cert.get('issued_days_ago')} days ago, covers {cert.get('names_covered')} names" if cert.get('https') else 'no HTTPS / not checked')])}</table>
<h2>Timeline</h2><table>{tl}</table>
<h2>Where to send the takedown request</h2><ul>{contacts}</ul><p>Also report it to:</p><ul>{links}</ul>
<h2>Takedown requests (ready to send)</h2>{mails}
<h2>Evidence files</h2><table><tr><th>File</th><th>SHA-256</th></tr>{files}</table>
<p style="color:#666">Links and domains are written defanged (hxxp, [.]) so they can't be clicked by accident.
Generated by Shield. Reviewed and sent by an analyst; nothing is sent automatically.</p>
</body></html>"""
