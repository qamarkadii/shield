"""
Domain facts: what the public internet says about a domain, beyond its name.

    facts(domain, tls=True) -> dict

  RDAP (the modern WHOIS)  registration date -> age in days, registrar, registrar abuse
                           e-mail, how long it was registered for, status
  DNS (over HTTPS)         does it resolve, A/AAAA/MX/NS records, CNAME
  Hosting network          the IP's network (ASN), its name and country (Team Cymru, via DNS)
                           and the hosting provider's abuse e-mail (RDAP for the IP)
  Certificate              (tls=True only) issuer, issue date -> age, how many names it covers.
                           This is a TLS handshake with the server; no page is requested.

Nothing here downloads or renders the website. All lookups go to public directories
(Cloudflare/Google DNS, rdap.org, Team Cymru). Results are cached for an hour.

SAFETY: names that resolve to private / local addresses (127.0.0.1, 10.x, 192.168.x ...)
are never contacted (that would let anyone probe the Shield server's own network).
"""

import ipaddress
import socket
import ssl
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import requests

from .features import FREE_HOSTS, clean, private_owner, split_domain

UA = {"User-Agent": "Shield/2 (UAE anti-phishing research; contact: see README)"}
DOH = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")
TIMEOUT = 8
FREE_CA = ("let's encrypt", "zerossl", "google trust services", "cpanel", "sectigo", "buypass",
           "ssl.com", "actalis", "cloudflare")   # free / automated certificates (also used by many real sites)
_cache, _lock = {}, threading.Lock()
CACHE_SECONDS = 3600


def _cached(key, fn):
    now = time.time()
    with _lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < CACHE_SECONDS:
            return hit[1]
    val = fn()
    with _lock:
        _cache[key] = (now, val)
        if len(_cache) > 20_000:
            for k in sorted(_cache, key=lambda k: _cache[k][0])[:5_000]:
                _cache.pop(k, None)
    return val


def is_public_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global and not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
                                or a.is_reserved or a.is_unspecified)


# ---------- DNS over HTTPS ----------

def dns(name: str, rtype: str):
    """List of answer strings ([] = none). None = lookup failed (no answer from both resolvers)."""
    def go():
        for url in DOH:
            try:
                r = requests.get(url, params={"name": name, "type": rtype}, timeout=TIMEOUT,
                                 headers={"accept": "application/dns-json", **UA})
                j = r.json()
                if j.get("Status") not in (0, 3):        # 0 ok, 3 NXDOMAIN
                    continue
                want = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}[rtype]
                return [a["data"].strip('"').rstrip(".") for a in j.get("Answer", []) if a.get("type") == want]
            except Exception:
                continue
        return None
    return _cached(("dns", name, rtype), go)


def asn_info(ip: str):
    """{'asn', 'prefix', 'country', 'as_name'} via Team Cymru's DNS service."""
    def go():
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if a.version == 4:
            q = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
        else:
            q = ".".join(reversed(a.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"
        t = dns(q, "TXT")
        if not t:
            return None
        parts = [p.strip() for p in t[0].split("|")]
        asn = parts[0].split()[0]
        info = {"asn": int(asn) if asn.isdigit() else None, "prefix": parts[1] if len(parts) > 1 else None,
                "country": parts[2] if len(parts) > 2 else None}
        n = dns(f"AS{asn}.asn.cymru.com", "TXT")
        if n:
            np_ = [p.strip() for p in n[0].split("|")]
            info["as_name"] = np_[-1] if np_ else None
        return info
    return _cached(("asn", ip), go)


# ---------- RDAP ----------

def _vcard(entity, field):
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item and item[0] == field:
            return item[3] if not isinstance(item[3], list) else " ".join(map(str, item[3]))
    return None


def _abuse_email(entities):
    for e in entities or []:
        if "abuse" in (e.get("roles") or []):
            m = _vcard(e, "email")
            if m:
                return m
        m = _abuse_email(e.get("entities"))
        if m:
            return m
    return None


def _date(s):
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def rdap_domain(registered: str):
    def go():
        try:
            r = requests.get(f"https://rdap.org/domain/{registered}", timeout=TIMEOUT + 4, headers=UA)
            if r.status_code == 404:
                return {"found": False}
            j = r.json()
        except Exception as ex:
            return {"found": None, "error": str(ex)[:120]}
        ev = {e.get("eventAction"): _date(e.get("eventDate", "")) for e in j.get("events", [])}
        reg = next((e for e in j.get("entities", []) if "registrar" in (e.get("roles") or [])), {})
        now = datetime.now(timezone.utc)
        created, expires = ev.get("registration"), ev.get("expiration")
        return {
            "found": True,
            "created": created.date().isoformat() if created else None,
            "age_days": (now - created).days if created else None,
            "expires": expires.date().isoformat() if expires else None,
            "registered_for_days": (expires - created).days if created and expires else None,
            "updated_days_ago": (now - ev["last changed"]).days if ev.get("last changed") else None,
            "registrar": _vcard(reg, "fn") if reg else None,
            "registrar_abuse_email": _abuse_email([reg]) or _abuse_email(j.get("entities")),
            "status": j.get("status", []),
            "nameservers": [n.get("ldhName", "").lower() for n in j.get("nameservers", [])],
        }
    return _cached(("rdap", registered), go)


def rdap_ip_abuse(ip: str):
    def go():
        try:
            j = requests.get(f"https://rdap.org/ip/{ip}", timeout=TIMEOUT + 4, headers=UA).json()
            return {"network": j.get("name"), "abuse_email": _abuse_email(j.get("entities")),
                    "country": j.get("country")}
        except Exception:
            return None
    return _cached(("rdapip", ip), go)


# ---------- Certificate (TLS handshake only) ----------

def certificate(host: str, ip: str):
    def go():
        if not is_public_ip(ip):
            return None
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip, 443), timeout=6) as s, ctx.wrap_socket(s, server_hostname=host) as t:
                der = t.getpeercert(binary_form=True)
        except Exception as ex:
            return {"https": False, "error": type(ex).__name__}
        try:   # decode with the standard library (no extra package)
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
                f.write(ssl.DER_cert_to_PEM_cert(der))
            c = ssl._ssl._test_decode_cert(f.name)
        except Exception:
            return {"https": True}
        issuer = " / ".join(v for part in c.get("issuer", ()) for k, v in part if k in ("organizationName", "commonName"))
        sans = [v for k, v in c.get("subjectAltName", ()) if k == "DNS"]
        nb = datetime.strptime(c["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if c.get("notBefore") else None
        na = datetime.strptime(c["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if c.get("notAfter") else None
        now = datetime.now(timezone.utc)
        return {"https": True, "issuer": issuer, "free_ca": any(x in issuer.lower() for x in FREE_CA),
                "issued_days_ago": (now - nb).days if nb else None,
                "valid_days": (na - nb).days if na and nb else None,
                "names_covered": len(sans), "wildcard": any(s.startswith("*.") for s in sans),
                "covers_host": any(host == s or (s.startswith("*.") and host.endswith(s[1:])) for s in sans)}
    return _cached(("cert", host, ip), go)


# ---------- all facts ----------

def facts(domain: str, tls: bool = True) -> dict:
    d = clean(domain)
    ext, registered = split_domain(d)
    # A tenant of a hosting platform (react-docs.vercel.app) is not a registration of its
    # own: the platform's age and wildcard certificate say nothing about the tenant.
    tenant = private_owner(d) != registered or any(registered == h or registered.endswith("." + h) for h in FREE_HOSTS)
    with ThreadPoolExecutor(6) as pool:
        fa = pool.submit(dns, d, "A")
        f6 = pool.submit(dns, d, "AAAA")
        fmx = pool.submit(dns, registered, "MX")
        fns = pool.submit(dns, registered, "NS")
        fcn = pool.submit(dns, d, "CNAME")
        frd = None if tenant else pool.submit(rdap_domain, registered)
        a, aaaa, mx, ns, cname, rd = (fa.result(), f6.result(), fmx.result(), fns.result(),
                                      fcn.result(), frd.result() if frd else {"found": None, "not_applicable": f"site on a hosting platform ({registered})"})
    ips = (a or []) + (aaaa or [])
    ips = [i for i in ips if _is_ip(i)]
    public = [i for i in ips if is_public_ip(i)]
    out = {"domain": d, "registered_domain": registered, "looked_up_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "dns": {"resolves": bool(ips), "a": a or [], "aaaa": aaaa or [], "mx": mx or [], "ns": ns or [],
                   "cname": cname or [], "lookup_failed": a is None and aaaa is None},
           "rdap": rd, "hosting": None, "certificate": None, "private_address": bool(ips) and not public,
           "platform_tenant": tenant}
    if public:
        ip = public[0]
        with ThreadPoolExecutor(3) as pool:
            fasn = pool.submit(asn_info, ip)
            fab = pool.submit(rdap_ip_abuse, ip)
            fct = pool.submit(certificate, d, ip) if tls else None
            h = fasn.result() or {}
            h.update({"ip": ip, **({"abuse": fab.result()} if fab.result() else {})})
            out["hosting"] = h
            out["certificate"] = fct.result() if fct else None
    return out


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ---------- turning facts into model inputs ----------

# No 'no registration record' sign: some registries (.ae) have no public RDAP, so a missing
# record is UNKNOWN, never a warning. Tenants of hosting platforms get neutral values.
FACT_NAMES = ["age_days_log", "age_known", "young_30d", "young_365d", "registered_1y", "has_mx",
              "cert_free_ca", "cert_new_7d", "cert_many_names", "no_https"]

# Plain-language reasons (used when a fact's learned effect is shown)
FACT_DESCRIBE = {
    "young_30d": "Domain registered in the last 30 days ({age} days ago)",
    "young_365d": "Domain registered less than a year ago ({age} days ago)",
    "age_days_log": "Domain age: {age} days",
    "age_known": "Registration date is public",
    "registered_1y": "Registered for one year only (typical of throw-away domains)",
    "has_mx": "Set up to receive e-mail (MX record)",
    "cert_free_ca": "Free automated certificate ({issuer})",
    "cert_new_7d": "Certificate issued in the last 7 days",
    "cert_many_names": "Certificate shared by many names ({n})",
    "no_https": "No working HTTPS",
}


def fact_vector(fx: dict) -> dict:
    """Numbers for the facts model. Missing values get neutral defaults."""
    import math
    rd = fx.get("rdap") or {}
    age = rd.get("age_days")
    cert = fx.get("certificate") or {}
    v = dict.fromkeys(FACT_NAMES, 0.0)
    v["age_days_log"] = math.log10(1 + age) if age is not None else 2.5       # ~1 year if unknown
    v["young_30d"] = float(age is not None and age <= 30)
    v["young_365d"] = float(age is not None and age <= 365)
    v["age_known"] = float(age is not None)
    rf = rd.get("registered_for_days")
    v["registered_1y"] = float(rf is not None and rf <= 400)
    v["has_mx"] = float(bool((fx.get("dns") or {}).get("mx")))
    if cert and not fx.get("platform_tenant"):
        v["cert_free_ca"] = float(bool(cert.get("free_ca")))
        v["cert_new_7d"] = float(cert.get("issued_days_ago") is not None and cert["issued_days_ago"] <= 7)
        v["cert_many_names"] = float((cert.get("names_covered") or 0) >= 20)
        v["no_https"] = float(cert.get("https") is False)
    return v
