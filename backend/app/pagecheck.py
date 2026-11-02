"""
Page check: open a suspicious page in an isolated headless browser ON THE SERVER and record
what it shows: screenshot, title, forms asking for passwords / card numbers / OTP codes,
where those forms send data, which UAE brand the page claims to be, and how much it LOOKS
like that brand's official site.

Used only from the analyst dashboard (and evidence packs). The public citizen site never
opens links.

Isolation:
  - runs in its own process (python -m backend.app.pagecheck URL OUTDIR), killed after 45 s
  - a fresh browser profile every time, no downloads, no permissions, no service workers
  - EVERY request the page makes is checked: names resolving to private/local addresses
    (127.0.0.1, 10.x, 192.168.x, ...) are blocked, so a page can't reach the Shield server's
    own network (e.g. the admin API on 127.0.0.1:8000)
  - nothing is typed into the page, nothing is clicked
For production, run it inside a separate container or VM as well.

Brand look-alike: reference screenshots of the official sites (data/brand_refs/, made with
`python -m backend.app.pagecheck --refs`) are compared with the page's screenshot
(difference hash of the layout + colour histogram), plus the official favicon.
"""

import hashlib
import io
import json
import os
import re
import socket
import subprocess
import sys
import time
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
REFS = os.path.join(ROOT, "data", "brand_refs")
TIMEOUT_S = 45


# ---------- safety: only public addresses ----------

_ok_hosts = {}


def host_is_public(host: str) -> bool:
    from .enrich import is_public_ip
    if not host:
        return False
    if host in _ok_hosts:
        return _ok_hosts[host]
    try:
        ips = {ai[4][0] for ai in socket.getaddrinfo(host, None)}
        ok = bool(ips) and all(is_public_ip(ip.split("%")[0]) for ip in ips)
    except Exception:
        ok = False
    _ok_hosts[host] = ok
    return ok


# ---------- image similarity (Pillow only) ----------

def _dhash(img, size=16):
    g = img.convert("L").resize((size + 1, size))
    px = list(g.getdata())
    bits = []
    for r in range(size):
        row = px[r * (size + 1):(r + 1) * (size + 1)]
        bits += [row[c] > row[c + 1] for c in range(size)]
    return bits


def _hist(img):
    h = img.convert("RGB").resize((64, 40)).quantize(colors=16).convert("RGB").histogram()
    s = float(sum(h)) or 1.0
    return [v / s for v in h]


def similarity(a, b) -> float:
    """0..1: layout (difference hash) and colours (histogram intersection), averaged."""
    da, db = _dhash(a), _dhash(b)
    layout = sum(x == y for x, y in zip(da, db)) / len(da)
    ha, hb = _hist(a), _hist(b)
    colour = sum(min(x, y) for x, y in zip(ha, hb))
    return round(0.5 * layout + 0.5 * colour, 3)


def load_refs():
    from PIL import Image
    refs = {}
    if not os.path.isdir(REFS):
        return refs
    meta_path = os.path.join(REFS, "refs.json")
    meta = json.load(open(meta_path)) if os.path.exists(meta_path) else {}
    for name in os.listdir(REFS):
        if name.endswith(".png"):
            key = name[:-4]
            try:
                refs[key] = {"img": Image.open(os.path.join(REFS, name)).copy(), **meta.get(key, {})}
            except Exception:
                pass
    return refs


# ---------- the browser part (runs in the child process) ----------

CARD = re.compile(r"card|cc-?num|cvv|cvc|expir|exp-?date|ccexp|pan\b", re.I)
OTP = re.compile(r"otp|one.?time|verification.?code|sms.?code|pin\b", re.I)
ID = re.compile(r"emirates.?id|national.?id|passport|iban", re.I)


def _run_browser(url: str, outdir: str) -> dict:
    from playwright.sync_api import sync_playwright
    os.makedirs(outdir, exist_ok=True)
    res = {"url": url, "blocked_requests": [], "redirects": [], "requests": 0, "error": None}
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True, args=["--disable-dev-shm-usage", "--no-first-run",
                                                    "--disable-extensions", "--disable-background-networking",
                                                    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"])
        ctx = b.new_context(accept_downloads=False, java_script_enabled=True, ignore_https_errors=True,
                            service_workers="block", viewport={"width": 1280, "height": 800},
                            user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                        "(KHTML, like Gecko) Chrome/130.0 Safari/537.36"))

        def guard(route):
            h = urlparse(route.request.url).hostname or ""
            if route.request.url.startswith(("data:", "blob:")) or host_is_public(h):
                res["requests"] += 1
                return route.continue_()
            res["blocked_requests"].append(route.request.url[:200])
            return route.abort()
        ctx.route("**/*", guard)

        def ws_guard(ws):           # WebSockets are not covered by route(): same rule
            if host_is_public(urlparse(ws.url).hostname or ""):
                ws.connect_to_server()
            else:
                res["blocked_requests"].append(ws.url[:200])
                ws.close()
        try:
            ctx.route_web_socket("**/*", ws_guard)
        except Exception:
            pass
        page = ctx.new_page()
        page.on("framenavigated", lambda fr: fr == page.main_frame and res["redirects"].append(fr.url[:300]))
        try:
            resp = page.goto(url, wait_until="domcontentloaded", timeout=20_000)
            res["status"] = resp.status if resp else None
            try:
                page.wait_for_load_state("networkidle", timeout=6_000)
            except Exception:
                pass
            res["final_url"] = page.url
            res["title"] = (page.title() or "")[:300]
            res["text"] = (page.inner_text("body", timeout=3_000) or "")[:6000]
            res["forms"] = page.evaluate("""() => Array.from(document.querySelectorAll('form')).map(f => ({
                action: f.action || '', method: (f.method||'get').toLowerCase(),
                inputs: Array.from(f.querySelectorAll('input,select,textarea')).map(i => ({
                    type: (i.type||'').toLowerCase(), name: i.name||'', id: i.id||'',
                    placeholder: i.placeholder||'', autocomplete: i.autocomplete||''}))}))""")
            res["loose_inputs"] = page.evaluate("""() => Array.from(document.querySelectorAll('input'))
                .filter(i => !i.form).map(i => ({type:(i.type||'').toLowerCase(), name:i.name||'', id:i.id||'',
                 placeholder:i.placeholder||'', autocomplete:i.autocomplete||''}))""")
            res["favicon"] = page.evaluate("""() => { const l = document.querySelector("link[rel*='icon']");
                return l ? l.href : (location.origin + '/favicon.ico'); }""")
            res["images_alt"] = page.evaluate("""() => Array.from(document.images).slice(0,60)
                .map(i => (i.alt||'') + ' ' + (i.src||'').split('/').pop()).join(' | ')""")[:2000]
            page.screenshot(path=os.path.join(outdir, "screenshot.png"), full_page=False)
            res["screenshot"] = os.path.join(outdir, "screenshot.png")
            if res["favicon"] and host_is_public(urlparse(res["favicon"]).hostname or ""):
                try:
                    r = ctx.request.get(res["favicon"], timeout=6_000)
                    if r.ok and len(r.body()) < 500_000:
                        res["favicon_sha256"] = hashlib.sha256(r.body()).hexdigest()
                except Exception:
                    pass
        except Exception as ex:
            res["error"] = f"{type(ex).__name__}: {str(ex)[:200]}"
        finally:
            ctx.close()
            b.close()
    return res


# ---------- analysis (parent process) ----------

def _inputs(res):
    out = list(res.get("loose_inputs") or [])
    for f in res.get("forms") or []:
        out += f.get("inputs", [])
    return out


def analyse(res: dict, domain: str) -> dict:
    from .features import clean, split_domain
    from .i18n import BRAND_AR
    from .registry import UAE_BRANDS
    d = clean(domain)
    _, registered = split_domain(d)
    ins = _inputs(res)
    desc = lambda i: " ".join([i.get("name", ""), i.get("id", ""), i.get("placeholder", ""), i.get("autocomplete", "")])
    asks = {
        "password": any(i.get("type") == "password" for i in ins),
        "card": any(CARD.search(desc(i)) for i in ins),
        "otp": any(OTP.search(desc(i)) for i in ins),
        "id_number": any(ID.search(desc(i)) for i in ins),
    }
    text = " ".join([res.get("title") or "", res.get("text") or "", res.get("images_alt") or ""]).lower()
    shown = []
    for key, (name, official) in UAE_BRANDS.items():
        names = {name.lower().split(" (")[0], key}
        ar = BRAND_AR.get(name)
        hit = any(n and len(n) >= 4 and re.search(r"\b" + re.escape(n) + r"\b", text) for n in names) or (ar and ar.split(" (")[0] in text)
        if hit and name not in [s["brand"] for s in shown]:
            shown.append({"brand": name, "official": official})
    off_domain = lambda s: not any(registered == o or registered.endswith("." + o) for o in s["official"])
    claims = [s for s in shown if off_domain(s)]
    form_targets = sorted({urlparse(f.get("action") or "").hostname or "" for f in res.get("forms") or []} - {""})
    final_host = urlparse(res.get("final_url") or "").hostname or ""
    _, final_reg = split_domain(final_host) if final_host else (None, "")

    look = []
    shot = res.get("screenshot")
    if shot and os.path.exists(shot):
        try:
            from PIL import Image
            img = Image.open(shot)
            for key, ref in load_refs().items():
                if any(registered == o or registered.endswith("." + o) for o in ref.get("official", [])):
                    continue
                s = similarity(img, ref["img"])
                look.append({"brand": ref.get("brand", key), "similarity": s,
                             "favicon_match": bool(res.get("favicon_sha256") and res["favicon_sha256"] == ref.get("favicon_sha256"))})
            look.sort(key=lambda x: (-x["favicon_match"], -x["similarity"]))
        except Exception:
            look = []
    best = look[0] if look else None

    signs = []
    if asks["password"]:
        signs.append("The page asks for a password")
    if asks["card"]:
        signs.append("The page asks for card details")
    if asks["otp"]:
        signs.append("The page asks for a one-time code (OTP)")
    if asks["id_number"]:
        signs.append("The page asks for an Emirates ID / passport / IBAN number")
    for c in claims[:2]:
        signs.append(f"The page presents itself as {c['brand']}, but this is not an official {c['brand']} domain")
    if best and (best["favicon_match"] or best["similarity"] >= 0.80):
        signs.append(f"The page looks {best['similarity']:.0%} like the official {best['brand']} site"
                     + (" and uses its exact icon" if best["favicon_match"] else ""))
    ext_forms = [h for h in form_targets if split_domain(h)[1] != registered]
    if ext_forms and any(asks.values()):
        signs.append("The form sends what you type to another site: " + ", ".join(ext_forms[:3]))
    if final_reg and final_reg != registered:
        signs.append(f"The link redirects to another site: {final_reg}")
    if res.get("blocked_requests"):
        signs.append(f"The page tried to reach {len(res['blocked_requests'])} private/local addresses (blocked)")

    danger = (any(asks.values()) and bool(claims or (best and best["similarity"] >= 0.80))) or \
             bool(best and best["favicon_match"])
    return {"opened": res.get("error") is None, "error": res.get("error"), "status": res.get("status"),
            "final_url": res.get("final_url"), "title": res.get("title"), "asks_for": asks,
            "brands_shown": [s["brand"] for s in shown], "claims_brand_off_domain": [c["brand"] for c in claims],
            "looks_like": look[:3], "form_targets": form_targets, "redirects": res.get("redirects", [])[:8],
            "blocked_requests": res.get("blocked_requests", [])[:10], "requests": res.get("requests"),
            "screenshot": res.get("screenshot"), "favicon_sha256": res.get("favicon_sha256"),
            "signs": signs, "verdict": "phishing page" if danger else ("warning signs" if signs else "nothing found"),
            "text_excerpt": (res.get("text") or "")[:600]}


def check_page(url: str, outdir: str, domain: str | None = None) -> dict:
    """Open url in the isolated browser process; return the analysis."""
    from .features import clean
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    host = urlparse(url).hostname or ""
    if not host_is_public(host):
        return {"opened": False, "error": "refused: the name does not resolve to a public internet address",
                "signs": [], "verdict": "not checked"}
    os.makedirs(outdir, exist_ok=True)
    t = time.time()
    try:
        p = subprocess.run([sys.executable, "-m", "backend.app.pagecheck", url, outdir], cwd=ROOT,
                           capture_output=True, text=True, timeout=TIMEOUT_S)
        res = json.loads(p.stdout.strip().splitlines()[-1]) if p.stdout.strip() else {"error": p.stderr[-300:]}
    except subprocess.TimeoutExpired:
        res = {"error": f"page did not finish loading in {TIMEOUT_S} s"}
    except Exception as ex:
        res = {"error": f"{type(ex).__name__}: {ex}"}
    out = analyse(res, domain or clean(url))
    out["seconds"] = round(time.time() - t, 1)
    with open(os.path.join(outdir, "pagecheck.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
    return out


def make_refs():
    """Screenshot each brand's official site once (reference images for the look-alike check)."""
    from .registry import UAE_BRANDS
    os.makedirs(REFS, exist_ok=True)
    meta_path = os.path.join(REFS, "refs.json")
    meta = json.load(open(meta_path, encoding="utf-8")) if os.path.exists(meta_path) else {}
    done = {m.get("brand") for k, m in meta.items() if os.path.exists(os.path.join(REFS, f"{k}.png"))}
    for key, (name, official) in UAE_BRANDS.items():
        if name in done:
            continue
        done.add(name)
        dom = official[0]
        tmp = os.path.join(REFS, "_tmp")
        res = {}
        for url in ("https://" + dom, "https://www." + dom):     # official sites can be slow: 90 s each
            try:
                p = subprocess.run([sys.executable, "-m", "backend.app.pagecheck", url, tmp], cwd=ROOT,
                                   capture_output=True, text=True, timeout=90)
                res = json.loads(p.stdout.strip().splitlines()[-1])
            except Exception as ex:
                res = {"error": str(ex)[:120]}
            if res.get("screenshot") and os.path.exists(res["screenshot"]):
                break
        if res.get("screenshot") and os.path.exists(res["screenshot"]):
            os.replace(res["screenshot"], os.path.join(REFS, f"{key}.png"))
            meta[key] = {"brand": name, "official": official, "favicon_sha256": res.get("favicon_sha256"),
                         "title": res.get("title")}
            print(f"OK  {name} ({dom}): {ascii(res.get('title'))}", flush=True)   # ascii: Arabic titles on any console
            with open(meta_path, "w", encoding="utf-8") as f:                   # saved after each site
                json.dump(meta, f, indent=1, ensure_ascii=False)
        else:
            print(f"FAILED {name} ({dom}): {res.get('error')}", flush=True)


if __name__ == "__main__":
    if sys.argv[1:2] == ["--refs"]:
        make_refs()
    else:
        out = _run_browser(sys.argv[1], sys.argv[2])
        sys.stdout.write("\n" + json.dumps(out) + "\n")      # ASCII-only: safe on any console
