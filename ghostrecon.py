from urllib.parse import urlparse
#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║                    👻 GHOST RECON v3.1                          ║
║              Enterprise OSINT Intelligence Framework             ║
║                         🔒 SECURE BY DESIGN                     ║
║                          Simone D'Agostino                      ║
╚══════════════════════════════════════════════════════════════════╝
"""

import json
import socket
import ssl
import re
import os
import sys
import time
import hashlib
import math
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from typing import Optional, Dict, List, Any, Tuple
import html as html_module
from dataclasses import dataclass

# Optional (phone intelligence)
try:
    import phonenumbers  # type: ignore
    from phonenumbers import carrier as pn_carrier  # type: ignore
    from phonenumbers import geocoder as pn_geocoder  # type: ignore
    from phonenumbers import number_type as pn_number_type  # type: ignore
except Exception:
    phonenumbers = None
    pn_carrier = None
    pn_geocoder = None
    pn_number_type = None


# ==================== CONFIGURAZIONE ====================

@dataclass
class Config:
    verify_ssl: bool = True
    aggressive_mode: bool = False
    redact_reports: bool = True
    timeout_default: int = 8
    timeout_aggressive: int = 20

    @classmethod
    def set_aggressive(cls, enabled: bool):
        old_mode = cls.aggressive_mode
        cls.aggressive_mode = enabled
        if enabled:
            print(f"\n  {C.BG_R}{C.BLD}⚠⚠⚠ AGGRESSIVE ENTERPRISE ENABLED ⚠⚠⚠{C.RST}")
            print(f"  {C.Y}Enterprise recon esteso attivo - Rispetta ToS!{C.RST}\n")
        else:
            print(f"\n  {C.G}✓ Safe mode restored{C.RST}\n")
        
        if old_mode != enabled and 'session_cache' in globals():
            session_cache.clear_all()
            print(f"  {C.CY}🔄 Cache resettata per cambio modalità{C.RST}\n")

    @classmethod
    def set_redact(cls, enabled: bool):
        cls.redact_reports = enabled
        status("🔒", f"Report redaction: {'ON' if enabled else 'OFF'}", C.CY)
    
    @classmethod
    def aggr_tag(cls) -> str:
        return "[AGGR ENTERPRISE]" if cls.aggressive_mode else "[SAFE]"


# ==================== COLORI ====================

class C:
    RST = "\033[0m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    R = "\033[91m"
    G = "\033[92m"
    Y = "\033[93m"
    B = "\033[94m"
    M = "\033[95m"
    CY = "\033[96m"
    W = "\033[97m"
    BG_R = "\033[41m"
    BG_G = "\033[42m"
    BG_B = "\033[44m"
    BG_M = "\033[45m"
    BG_Y = "\033[43m"


BANNER = f"""{C.CY}{C.BLD}
   ▄██████▄     ▄█    █▄     ▄██████▄     ▄████████     ███
  ███    ███   ███    ███   ███    ███   ███    ███ ▀█████████▄
  ███    █▀    ███    ███   ███    ███   ███    █▀     ▀███▀▀██
 ▄███         ▄███▄▄▄▄███▄▄ ███    ███   ███            ███   ▀
▀▀███ ████▄  ▀▀███▀▀▀▀███▀  ███    ███ ▀███████████     ███
  ███    ███   ███    ███   ███    ███          ███     ███
  ███    ███   ███    ███   ███    ███    ▄█    ███     ███
  ████████▀    ███    █▀     ▀██████▀   ▄████████▀    ▄████▀

  {C.M}██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝{C.RST}

  {C.DIM}Enterprise OSINT Framework v3.1{C.RST}
  {C.DIM}🔒 TLS Verified | 📊 Accurate Breach Intel{C.RST}
  {C.Y}⚠  Solo per scopi educativi e autorizzati{C.RST}
"""


# ==================== UTILITIES ====================

def box(title: str, content: list[str], color: str = C.CY) -> str:
    if not isinstance(title, str):
        title = str(title) if title is not None else ""
    if not isinstance(content, list):
        content = [str(content)] if content is not None else []
    
    try:
        max_content_len = 0
        for line in content:
            if isinstance(line, str):
                max_content_len = max(max_content_len, len(line))
            else:
                max_content_len = max(max_content_len, len(str(line)))
    except:
        max_content_len = 20
    
    width = max(len(title) + 4, max_content_len + 4, 60)
    
    lines = [
        f"{color}{'═' * width}",
        f"║  {C.BLD}{title}{C.RST}{color}{' ' * (width - len(title) - 4)}║",
        f"{'═' * width}{C.RST}",
    ]
    
    for line in content:
        line_str = str(line) if line is not None else ""
        padding = width - len(line_str) - 4
        lines.append(f"{color}║{C.RST}  {line_str}{' ' * max(padding, 0)}{color}║{C.RST}")
    
    lines.append(f"{color}{'═' * width}{C.RST}")
    return "\n".join(lines)


def status(icon: str, msg: str, color: str = C.G):
    icon = str(icon) if icon is not None else ""
    msg = str(msg) if msg is not None else ""
    print(f"  {color}{icon}{C.RST} {msg}")


def progress_bar(current: int, total: int, label: str = "", width: int = 30):
    try:
        current = int(current) if current is not None else 0
        total = int(total) if total is not None else 1
    except:
        current, total = 0, 1
    
    if total <= 0:
        total = 1
    
    pct = current / total if total else 0
    filled = int(width * pct)
    bar = f"{'█' * filled}{'░' * (width - filled)}"
    label = str(label) if label is not None else ""
    print(f"\r  {C.CY}⟫{C.RST} {bar} {pct*100:5.1f}% {C.DIM}{label}{C.RST}", end="", flush=True)
    if current >= total:
        print()


# ==================== DOMAIN VALIDATION ====================

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*"
    r"\.[a-z]{2,63}$",
    re.IGNORECASE
)

def normalize_domain(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"^https?://", "", s)
    s = s.split("/")[0]
    s = s.split(":")[0]
    s = s.strip(".")
    return s

def is_valid_domain(s: str) -> bool:
    s = normalize_domain(s)
    return bool(_DOMAIN_RE.match(s))


# ==================== SESSION CACHE ====================

class SessionCache:
    TTL = 3600  # seconds

    def __init__(self):
        self._store = {
            "safe": {"email": {}, "domain": {}, "ip": {}, "username": {}, "phone": {}},
            "aggr": {"email": {}, "domain": {}, "ip": {}, "username": {}, "phone": {}},
        }

    def _mode(self) -> str:
        return "aggr" if Config.aggressive_mode else "safe"

    def _bucket(self, cache_type: str) -> dict:
        return self._store[self._mode()].get(cache_type, {})

    def get(self, cache_type: str, key: str):
        if key is None:
            return None
        key_n = str(key).strip().lower()
        bucket = self._bucket(cache_type)
        entry = bucket.get(key_n)
        if not entry:
            return None
        ts = entry.get("ts", 0)
        if time.time() - ts > self.TTL:
            bucket.pop(key_n, None)
            return None
        return entry.get("data")

    def set(self, cache_type: str, key: str, value: dict):
        if key is None or not isinstance(value, dict):
            return
        key_n = str(key).strip().lower()
        bucket = self._bucket(cache_type)
        bucket[key_n] = {"data": value, "ts": time.time()}

    def clear_mode(self):
        self._store[self._mode()] = {"email": {}, "domain": {}, "ip": {}, "username": {}, "phone": {}}

    def clear_all(self):
        self._store["safe"] = {"email": {}, "domain": {}, "ip": {}, "username": {}, "phone": {}}
        self._store["aggr"] = {"email": {}, "domain": {}, "ip": {}, "username": {}, "phone": {}}

    # Backward-compatible helpers (used throughout the tool)
    def get_email(self, email: str):
        return self.get("email", email)

    def set_email(self, email: str, data: dict):
        self.set("email", email, data)

    def get_domain(self, domain: str):
        return self.get("domain", domain)

    def set_domain(self, domain: str, data: dict):
        self.set("domain", domain, data)

    def get_ip(self, ip: str):
        return self.get("ip", ip)

    def set_ip(self, ip: str, data: dict):
        self.set("ip", ip, data)

    def get_username(self, username: str):
        return self.get("username", username)

    def set_username(self, username: str, data: dict):
        self.set("username", username, data)

    def get_phone(self, phone: str):
        return self.get("phone", phone)

    def set_phone(self, phone: str, data: dict):
        self.set("phone", phone, data)



class Redactor:
    @staticmethod
    def email(email: str) -> str:
        if not isinstance(email, str):
            return str(email) if email is not None else ""
        if '@' not in email:
            return email
        try:
            local, domain = email.split('@', 1)
            if len(local) <= 2:
                return f"{'*' * len(local)}@{domain}"
            return f"{local[0]}{'*' * (len(local)-2)}{local[-1]}@{domain}"
        except:
            return email

    @staticmethod
    def phone(phone: str) -> str:
        if not isinstance(phone, str):
            return str(phone) if phone is not None else ""
        try:
            clean = re.sub(r'[^\d+]', '', phone)
            if len(clean) <= 4:
                return '*' * len(clean)
            if clean.startswith('+'):
                return clean[:3] + '*' * (len(clean)-5) + clean[-2:]
            return clean[:2] + '*' * (len(clean)-4) + clean[-2:]
        except:
            return phone

    @staticmethod
    def ip(ip: str) -> str:
        if not isinstance(ip, str):
            return str(ip) if ip is not None else ""
        if ip.count('.') == 3:
            parts = ip.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.*.*"
        return ip

    @staticmethod
    def dict(data: dict, redact: bool = True) -> dict:
        if not redact:
            return data if isinstance(data, dict) else {}
        
        if not isinstance(data, dict):
            return {}

        redacted = {}
        for key, value in data.items():
            key_str = str(key) if key is not None else ""
            
            if isinstance(value, dict):
                redacted[key] = Redactor.dict(value, redact)
            elif isinstance(value, list):
                redacted[key] = [Redactor.dict(v, redact) if isinstance(v, dict) else v for v in value]
            elif isinstance(value, str):
                if 'email' in key_str.lower() or key_str == 'email':
                    redacted[key] = Redactor.email(value)
                elif 'phone' in key_str.lower() or key_str == 'phone':
                    redacted[key] = Redactor.phone(value)
                elif 'ip' in key_str.lower() and value.count('.') == 3:
                    redacted[key] = Redactor.ip(value)
                else:
                    redacted[key] = value
            else:
                redacted[key] = value
        return redacted


# ==================== HTTP CLIENT ====================

class HTTPClient:
    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json, text/html, */*",
        "Accept-Language": "en-US,en;q=0.9",
    }

    @classmethod
    def _should_verify(cls, url: str, verify_ssl: Optional[bool] = None) -> bool:
        if verify_ssl is not None:
            return verify_ssl
        if isinstance(url, str) and url.startswith('http://'):
            status("⚠", f"HTTP connection to {url[:50]} - NO ENCRYPTION", C.Y)
            return False
        return Config.verify_ssl

    @classmethod
    def get(cls, url: str, headers: dict | None = None, timeout: int = None,
            verify_ssl: bool = None) -> dict:
        if not isinstance(url, str):
            return {"status": 0, "body": "", "headers": {}, "ok": False, "verified": False}
        
        hdrs = {**cls.DEFAULT_HEADERS, **(headers or {})}
        req = urllib.request.Request(url, headers=hdrs)

        if timeout is None:
            timeout = Config.timeout_aggressive if Config.aggressive_mode else Config.timeout_default

        ctx = ssl.create_default_context()
        verify = cls._should_verify(url, verify_ssl)

        if verify:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return {
                    "status": resp.status,
                    "body": body,
                    "headers": dict(resp.headers),
                    "ok": True,
                    "verified": verify,
                }
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            return {"status": e.code, "body": body, "headers": {}, "ok": False, "verified": verify}
        except urllib.error.URLError as e:
            return {"status": 0, "body": str(e.reason), "headers": {}, "ok": False, "verified": verify}
        except socket.timeout:
            return {"status": 0, "body": "Timeout", "headers": {}, "ok": False, "verified": verify}
        except Exception as e:
            return {"status": 0, "body": str(e), "headers": {}, "ok": False, "verified": verify}

    @classmethod
    def json_get(cls, url: str, **kwargs) -> dict | list | None:
        resp = cls.get(url, **kwargs)
        if resp["ok"] and isinstance(resp["body"], str):
            try:
                return json.loads(resp["body"])
            except json.JSONDecodeError:
                return None
        return None

    @classmethod
    def head(cls, url: str, timeout: int = None, verify_ssl: bool = None) -> dict:
        if not isinstance(url, str):
            return {"status": 0, "headers": {}, "ok": False}
        
        if timeout is None:
            timeout = Config.timeout_aggressive if Config.aggressive_mode else Config.timeout_default
        
        req = urllib.request.Request(url, method="HEAD", headers=cls.DEFAULT_HEADERS)

        ctx = ssl.create_default_context()
        verify = cls._should_verify(url, verify_ssl)

        if verify:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return {"status": resp.status, "headers": dict(resp.headers), "ok": True}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "headers": dict(e.headers) if e.headers else {}, "ok": False}
        except Exception:
            return {"status": 0, "headers": {}, "ok": False}

    @classmethod
    def post(cls, url: str, data: dict | str = None, headers: dict | None = None,
             timeout: int = None, verify_ssl: bool = None) -> dict:
        if not isinstance(url, str):
            return {"status": 0, "body": "", "headers": {}, "ok": False}
        
        if timeout is None:
            timeout = Config.timeout_aggressive if Config.aggressive_mode else Config.timeout_default
        
        hdrs = {**cls.DEFAULT_HEADERS, **(headers or {})}

        if isinstance(data, dict):
            data = urllib.parse.urlencode(data).encode()
        elif isinstance(data, str):
            data = data.encode()
        elif data is not None:
            data = str(data).encode()

        req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")

        ctx = ssl.create_default_context()
        verify = cls._should_verify(url, verify_ssl)

        if verify:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return {
                    "status": resp.status,
                    "body": body,
                    "headers": dict(resp.headers),
                    "ok": True,
                }
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            return {"status": e.code, "body": body, "headers": {}, "ok": False}
        except Exception as e:
            return {"status": 0, "body": str(e), "headers": {}, "ok": False}


http = HTTPClient()
session_cache = SessionCache()

# ==================== BREACH ENGINE ====================

def _http_get_json(url, timeout=6):
    if not isinstance(url, str):
        return None
    req = urllib.request.Request(url, headers={"User-Agent": "GhostRecon/3.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)
    except Exception:
        return None


def check_breach_xon(email):
    if not isinstance(email, str):
        return None, None
    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    data = _http_get_json(url, timeout=6)

    if data is None:
        return None, None
    if not isinstance(data, dict):
        return None, None

    breaches = data.get("breaches")
    meta = {}
    for k, v in data.items():
        if k != "breaches":
            meta[k] = v

    if breaches is None:
        return [], meta

    flat_breaches = []

    def flatten(item):
        if isinstance(item, list):
            for subitem in item:
                flatten(subitem)
        elif isinstance(item, dict):
            flat_breaches.append(item)
        elif isinstance(item, str):
            flat_breaches.append({
                "name": item,
                "breach_date": None,
                "description": f"Breach: {item}"
            })

    flatten(breaches)
    return flat_breaches, meta


def check_phone_breach_xon(phone_e164: str):
    meta = {
        "provider": "XposedOrNot", 
        "supported": False, 
        "note": "Public phone endpoint not available",
        "breach_check_supported": False
    }

    try:
        if not isinstance(phone_e164, str) or not phone_e164.strip():
            return [], {"provider": "XposedOrNot", "supported": False, "error": "empty phone", "breach_check_supported": False}
        return [], meta
    except Exception as e:
        meta["error"] = str(e)
        return [], meta


def rdap_domain_lookup(domain: str) -> dict:
    """
    RDAP primario + fallback WHOIS (porta 43) se RDAP non restituisce dati utili.
    Ritorna SEMPRE un dict normalizzato con:
      status: success|error
      domain, registrar, creation_date, updated_date, expiration_date, nameservers, dnssec, status_codes, source, raw
    """
    domain = (domain or "").strip().lower().strip(".")
    if not domain:
        return {"status": "error", "error": "empty domain", "domain": ""}

    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    rdap_candidates = []
    if tld == "it":
        rdap_candidates.append(f"https://rdap.nic.it/domain/{domain}")
    rdap_candidates.append(f"https://rdap.org/domain/{domain}")
    
    data = None
    for url in rdap_candidates:
        try:
            data = http.json_get(url, timeout=12)
            if isinstance(data, dict) and data:
                break
        except Exception:
            data = None
    # last tried url is in `url` if needed

    def _extract_rdap(d: dict) -> dict:
        events = d.get("events") or []
        nameservers = d.get("nameservers") or []
        ns = []
        for n in nameservers:
            if isinstance(n, dict) and n.get("ldhName"):
                ns.append(str(n["ldhName"]).rstrip("."))

        registrar = None
        entities = d.get("entities") or []
        for ent in entities:
            if not isinstance(ent, dict):
                continue
            roles = ent.get("roles") or []
            if "registrar" in roles:
                vcard = ent.get("vcardArray")
                if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
                    for item in vcard[1]:
                        if isinstance(item, list) and len(item) >= 4 and item[0] in ("fn", "org"):
                            registrar = str(item[3]).strip()
                            break
            if registrar:
                break

        created = updated = expires = None
        for ev in events:
            if not isinstance(ev, dict):
                continue
            action = ev.get("eventAction")
            date = ev.get("eventDate")
            if not date:
                continue
            if action == "registration":
                created = date
            elif action == "last changed":
                updated = date
            elif action == "expiration":
                expires = date

        dnssec = None
        sec = d.get("secureDNS")
        if isinstance(sec, dict):
            dnssec = sec.get("delegationSigned")

        status_codes = d.get("status")
        if isinstance(status_codes, str):
            status_codes = [status_codes]
        if not isinstance(status_codes, list):
            status_codes = []

        return {
            "status": "success",
            "domain": domain,
            "registrar": registrar,
            "creation_date": created,
            "updated_date": updated,
            "expiration_date": expires,
            "nameservers": ns,
            "dnssec": dnssec,
            "status_codes": status_codes,
            "source": "RDAP",
            "url": url,
            "raw": d,
            # backward-friendly aliases
            "created": created,
            "updated": updated,
            "expires": expires,
        }

    if isinstance(data, dict) and data:
        out = _extract_rdap(data)
        useful = bool(out.get("registrar") or out.get("creation_date") or out.get("expiration_date") or out.get("nameservers"))
        if useful:
            return out

    # Fallback WHOIS porta 43
    try:
        whois_raw = whois_port43(domain)
    except Exception as e:
        return {"status": "error", "error": f"whois_port43 failed: {e}", "domain": domain, "source": "WHOIS"}

    parsed = parse_whois_raw(whois_raw)
    return {
        "status": "success" if any(parsed.get(k) for k in ("registrar", "created", "expires", "nameservers")) else "error",
        "error": None if any(parsed.get(k) for k in ("registrar", "created", "expires", "nameservers")) else "no whois data",
        "domain": domain,
        "registrar": parsed.get("registrar"),
        "creation_date": parsed.get("created"),
        "updated_date": parsed.get("updated"),
        "expiration_date": parsed.get("expires"),
        "nameservers": parsed.get("nameservers") or [],
        "dnssec": parsed.get("dnssec"),
        "status_codes": [],
        "source": "WHOIS",
        "url": "whois://",
        "raw": whois_raw,
        # backward-friendly aliases
        "created": parsed.get("created"),
        "updated": parsed.get("updated"),
        "expires": parsed.get("expires"),
    }


def whois_port43(domain: str, timeout: int = 12) -> str:
    """Query WHOIS via porta 43 (IANA referral -> registry)."""
    import socket
    domain = domain.strip()
    if not domain:
        return ''

    def _query(server: str, q: str) -> str:
        data = b''
        with socket.create_connection((server, 43), timeout=timeout) as s:
            s.sendall((q + "\r\n").encode('utf-8', errors='ignore'))
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        return data.decode('utf-8', errors='replace')

    iana = _query('whois.iana.org', domain)
    refer = None
    for ln in iana.splitlines():
        if ln.lower().startswith('refer:'):
            refer = ln.split(':', 1)[1].strip()
            break
    if not refer:
        return iana

    try:
        return _query(refer, domain)
    except Exception:
        return iana


def parse_whois_raw(raw: str) -> dict:
    """Parsing leggero (best-effort) per output WHOIS porta 43."""
    out = {'registrar': None, 'created': None, 'updated': None, 'expires': None, 'nameservers': [], 'dnssec': None}
    if not raw:
        return out

    patterns = {
        'registrar': [r'^Registrar:\s*(.+)$', r'^Sponsoring Registrar:\s*(.+)$', r'^registrar:\s*(.+)$'],
        'created':   [r'^Creation Date:\s*(.+)$', r'^Created On:\s*(.+)$', r'^created:\s*(.+)$', r'^Registered On:\s*(.+)$'],
        'updated':   [r'^Updated Date:\s*(.+)$', r'^Last Updated On:\s*(.+)$', r'^changed:\s*(.+)$', r'^updated:\s*(.+)$'],
        'expires':   [r'^Registry Expiry Date:\s*(.+)$', r'^Expiration Date:\s*(.+)$', r'^Expire Date:\s*(.+)$', r'^expires:\s*(.+)$'],
        'dnssec':    [r'^DNSSEC:\s*(.+)$', r'^dnssec:\s*(.+)$'],
    }

    ns = set()
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith('%') or s.startswith('#'):
            continue
        m = re.match(r'^(Name Server|Nameserver|nserver|name-server):\s*(.+)$', s, flags=re.I)
        if m:
            v = m.group(2).strip().split()[0]
            if v:
                ns.add(v.rstrip('.'))
            continue
        for key, pats in patterns.items():
            if key != 'dnssec' and out.get(key):
                continue
            for pat in pats:
                mm = re.match(pat, s, flags=re.I)
                if mm:
                    out[key] = mm.group(1).strip()
                    break
    out['nameservers'] = sorted(ns)
    return out


def breach_risk_summary(breaches):
    years = []
    names = []

    if not isinstance(breaches, list):
        breaches = []

    for b in breaches:
        if isinstance(b, dict):
            n = b.get("name") or b.get("breach") or b.get("title")
            if n and isinstance(n, str):
                names.append(n)

            d = b.get("date") or b.get("breach_date") or b.get("added_date") or b.get("published")
            if d:
                try:
                    d_str = str(d)
                    if d_str and len(d_str) >= 4:
                        y = int(d_str[:4])
                        if 1990 <= y <= datetime.now().year + 1:
                            years.append(y)
                except:
                    pass
        else:
            names.append(str(b) if b is not None else "")

    count = len(breaches) if breaches is not None else 0
    uniq_years = sorted(set(years))
    last_year = max(uniq_years) if uniq_years else None

    if count == 0:
        score = 0
    elif count == 1:
        score = 35
    elif count <= 3:
        score = 55
    elif count <= 7:
        score = 75
    else:
        score = 90

    if last_year and last_year >= (datetime.now().year - 2):
        score = min(100, score + 10)

    if score >= 80:
        level = "HIGH"
    elif score >= 50:
        level = "MEDIUM"
    elif score >= 20:
        level = "LOW"
    else:
        level = "NONE"

    if uniq_years:
        timeline = f"{uniq_years[0]} → {uniq_years[-1]} ({len(uniq_years)} anni)"
    else:
        timeline = "N/A"

    sample = ", ".join(names[:3]) if names else "N/A"

    return {
        "count": count,
        "score": score,
        "level": level,
        "timeline": timeline,
        "sample": sample
    }


# ==================== MODULO 1 - CASE MANAGEMENT ====================

@classmethod
def get_bytes(cls, url: str, headers: dict | None = None, timeout: int = None,
              verify_ssl: bool = None) -> bytes | None:
    """Fetch raw bytes (best-effort)."""
    try:
        import urllib.request
        hdrs = dict(cls.DEFAULT_HEADERS)
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, headers=hdrs, method="GET")
        ctx = None
        if url.startswith("https://"):
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            if not cls._should_verify(url, verify_ssl):
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout or Config.timeout_default, context=ctx) as resp:
            return resp.read()
    except Exception:
        return None


class CaseManagement:
    def __init__(self):
        self.case_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.targets = {}
        self.notes = []
        self.evidence = []
        self.created_at = datetime.now()
        self.updated_at = datetime.now()
    
    def set_target(self, target_type: str, value: str):
        if not isinstance(target_type, str) or not isinstance(value, str):
            return
        self.targets[target_type] = value
        self.updated_at = datetime.now()
    
    def add_note(self, note: str):
        if isinstance(note, str) and note.strip():
            self.notes.append({
                "timestamp": datetime.now().isoformat(),
                "content": note.strip()
            })
            self.updated_at = datetime.now()
    
    def add_evidence(self, evidence_type: str, data: Any):
        if not isinstance(evidence_type, str):
            return
        self.evidence.append({
            "timestamp": datetime.now().isoformat(),
            "type": evidence_type,
            "data": data
        })
        self.updated_at = datetime.now()
    
    def get_summary(self) -> Dict:
        return {
            "case_id": self.case_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "targets": self.targets.copy(),
            "notes_count": len(self.notes),
            "evidence_count": len(self.evidence),
            "notes": self.notes.copy() if self.notes else []
        }
    
    def to_dict(self) -> Dict:
        return {
            "case_id": self.case_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "targets": self.targets.copy(),
            "notes": self.notes.copy(),
            "evidence": self.evidence.copy()
        }

# ==================== MODULO 2 - DOMAIN INTELLIGENCE ====================

def _dn_to_dict(dn) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not dn:
        return out
    try:
        for rdn in dn:
            if isinstance(rdn, (list, tuple)) and rdn:
                first = rdn[0]
                if isinstance(first, (list, tuple)) and len(first) == 2:
                    k, v = first
                    out[str(k)] = str(v)
    except Exception:
        pass
    return out


def calculate_tls_score(cert_info: Optional[Dict], headers: Optional[Dict]) -> int:
    score = 50
    try:
        if isinstance(cert_info, dict) and cert_info.get("verified") is True:
            tls_version = cert_info.get('tls_version')
            if isinstance(tls_version, str):
                if '1.3' in tls_version:
                    score += 20
                elif '1.2' in tls_version:
                    score += 10
                elif '1.1' in tls_version:
                    score += 5
                else:
                    score -= 10

            not_after = cert_info.get('not_after')
            if isinstance(not_after, str):
                try:
                    from datetime import datetime
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.now()).days

                    if days_left > 90:
                        score += 15
                    elif days_left > 30:
                        score += 10
                    elif days_left > 7:
                        score += 5
                    elif days_left < 0:
                        score -= 30
                    else:
                        score -= 10
                except:
                    pass

            issuer = cert_info.get('issuer', {})
            issuer_str = ""
            if isinstance(issuer, dict):
                issuer_str = " ".join([
                    str(issuer.get('organizationName', '')),
                    str(issuer.get('commonName', '')),
                ]).strip()

            trusted_issuers = ["let's encrypt", "digicert", "sectigo", "globalsign"]
            if issuer_str and any(ti in issuer_str.lower() for ti in trusted_issuers):
                score += 10
        else:
            score -= 20

        if isinstance(headers, dict):
            hsts = headers.get('Strict-Transport-Security') or headers.get('strict-transport-security')
            if hsts:
                score += 15

        return max(0, min(100, score))
    except Exception:
        return 50


def detect_cloudflare(headers: Optional[Dict], domain: str) -> Dict[str, Any]:
    result = {
        'is_cloudflare': False,
        'confidence': 'Low',
        'indicators': []
    }

    try:
        indicators = []

        if isinstance(headers, dict):
            server = headers.get('Server') or headers.get('server')
            if isinstance(server, str) and 'cloudflare' in server.lower():
                indicators.append(f"Server: {server}")
                result['is_cloudflare'] = True

            cf_ray = headers.get('CF-Ray') or headers.get('cf-ray')
            if cf_ray:
                indicators.append("CF-Ray present")
                result['is_cloudflare'] = True

            if headers.get('CF-Cache-Status') or headers.get('cf-cache-status'):
                indicators.append("CF-Cache-Status present")
                result['is_cloudflare'] = True

            if headers.get('CF-Request-ID') or headers.get('cf-request-id'):
                indicators.append("CF-Request-ID present")
                result['is_cloudflare'] = True

        try:
            ip = socket.gethostbyname(domain)
            if isinstance(ip, str):
                cloudflare_prefixes = ['104.16.', '104.17.', '104.18.', '104.19.',
                                       '172.64.', '173.245.', '198.41.', '162.158.']
                if any(ip.startswith(prefix) for prefix in cloudflare_prefixes):
                    indicators.append(f"IP in Cloudflare range: {ip}")
                    result['is_cloudflare'] = True
        except:
            pass

        result['indicators'] = indicators

        if indicators:
            if len(indicators) >= 3:
                result['confidence'] = 'High'
            elif len(indicators) >= 2:
                result['confidence'] = 'Medium'
            else:
                result['confidence'] = 'Low'
        else:
            result['indicators'] = ['No Cloudflare indicators found']

    except Exception as e:
        result['indicators'] = [f"Error in detection: {str(e)}"]

    return result

# ==================== DOMAIN RISK (ENTERPRISE) ====================

def compute_domain_risk_enterprise(results: dict) -> dict:
    """Enterprise domain risk (0-100) with coherent drivers and breakdown."""
    r = results if isinstance(results, dict) else {}
    breakdown = {"tls": 0, "headers": 0, "whois": 0, "ports": 0, "exposure": 0, "web": 0, "mitigations": 0}
    drivers = []

    # TLS (max +20)
    tls = r.get("tls_score", 0)
    try:
        tls = int(float(tls))
    except Exception:
        tls = 0
    if tls < 60:
        breakdown["tls"] = 20
        drivers.append(f"Weak TLS (tls_score={tls}) (+20)")
    elif tls < 75:
        breakdown["tls"] = 10
        drivers.append(f"Mid TLS (tls_score={tls}) (+10)")
    elif tls < 80:
        breakdown["tls"] = 5
        drivers.append(f"OK TLS (tls_score={tls}) (+5)")

    # Security headers (max +25)
    hs = r.get("headers_security", {})
    hscore = None
    if isinstance(hs, dict):
        hscore = hs.get("score", None)
    try:
        hscore_f = float(hscore) if hscore is not None else None
    except Exception:
        hscore_f = None

    if hscore_f is None:
        breakdown["headers"] = 10
        drivers.append("Headers score unavailable (+10)")
    else:
        if hscore_f < 30:
            breakdown["headers"] = 20
            drivers.append(f"Weak security headers (score={hscore_f:.1f}%) (+20)")
        elif hscore_f < 60:
            breakdown["headers"] = 10
            drivers.append(f"Medium security headers (score={hscore_f:.1f}%) (+10)")
        elif hscore_f < 75:
            breakdown["headers"] = 5
            drivers.append(f"OK security headers (score={hscore_f:.1f}%) (+5)")

    # WHOIS signals (max +25)
    whois_sig = r.get("whois_signals", {})
    ws = 0
    if isinstance(whois_sig, dict):
        ws = int(whois_sig.get("score", 0) or 0)
    if ws >= 25:
        breakdown["whois"] = 25
        drivers.append(f"Strong WHOIS risk signals (score={ws}) (+25)")
    elif ws >= 15:
        breakdown["whois"] = 15
        drivers.append(f"WHOIS risk signals (score={ws}) (+15)")
    elif ws >= 8:
        breakdown["whois"] = 8
        drivers.append(f"Minor WHOIS signals (score={ws}) (+8)")

    # Ports (max +20)
    ports = r.get("ports", [])
    total_ports = len(ports) if isinstance(ports, list) else 0
    verified_ports = 0
    nonstandard = 0
    admin_ports = 0
    if isinstance(ports, list):
        for p in ports:
            if not isinstance(p, dict):
                continue
            try:
                port = int(p.get("port", 0))
            except Exception:
                port = 0
            if p.get("verified"):
                verified_ports += 1
            if port not in (80, 443) and port != 0:
                nonstandard += 1
            if port in (22, 2222, 3389, 445, 5900, 3306, 5432, 6379, 9200, 27017):
                admin_ports += 1

    if total_ports > 0:
        if nonstandard == 0 and set([p.get("port") for p in ports if isinstance(p, dict)]) <= {80, 443}:
            breakdown["ports"] = 0
        else:
            pts = 6 + min(10, nonstandard * 4)
            if admin_ports:
                pts += min(8, 4 + admin_ports * 2)
            breakdown["ports"] = min(20, pts)
            drivers.append(f"Open ports (total={total_ports}, nonstandard={nonstandard}, admin={admin_ports}) (+{breakdown['ports']})")

    # Exposure (max +10) - URLScan is footprint, not breach
    exposure = r.get("domain_breaches", [])
    expo_n = len(exposure) if isinstance(exposure, list) else 0
    expo_pts = 0
    if expo_n:
        # Distinguish likely 'footprint' sources
        footprint = 0
        confirmed = 0
        for item in exposure:
            if not isinstance(item, dict):
                continue
            src = str(item.get("source", "")).lower()
            if "urlscan" in src:
                footprint += 1
            else:
                confirmed += 1
        expo_pts = min(10, confirmed * 10 + min(4, footprint * 2))
        if confirmed:
            drivers.append(f"Confirmed exposure signals (n={confirmed}) (+{min(10, confirmed*10)})")
        if footprint:
            drivers.append(f"Footprint signals (urlscan/etc n={footprint}) (+{min(4, footprint*2)})")
    breakdown["exposure"] = expo_pts

    # Web aggressive signals (max +10)
    web = r.get("web_info", {})
    if isinstance(web, dict):
        js_count = int(web.get("js_count", 0) or 0)
        ext_js = web.get("external_js", [])
        ext_js_n = len(ext_js) if isinstance(ext_js, list) else 0
        if js_count >= 25:
            breakdown["web"] += 5
            drivers.append(f"Heavy JS footprint (js_count={js_count}) (+5)")
        if ext_js_n >= 8:
            breakdown["web"] += 5
            drivers.append(f"Many external JS (external_js={ext_js_n}) (+5)")
        breakdown["web"] = min(10, breakdown["web"])

    # Mitigations (negative points)
    mitig = 0
    cf = r.get("cloudflare", {})
    if isinstance(cf, dict) and cf.get("is_cloudflare"):
        mitig -= 10
        drivers.append("Mitigation: Cloudflare detected (-10)")
    whois = r.get("whois", {})
    if isinstance(whois, dict) and whois.get("dnssec"):
        mitig -= 5
        drivers.append("Mitigation: DNSSEC enabled (-5)")
    breakdown["mitigations"] = mitig


    # Enterprise-only signals (added when aggressive suite ran)
    ent = r.get("enterprise", {}) if isinstance(r.get("enterprise", {}), dict) else {}
    ent_pts = 0
    if isinstance(ent, dict):
        # redirect anomalies
        ra = (ent.get("http_recon", {}) or {}).get("redirect_anomalies", []) if isinstance(ent.get("http_recon", {}), dict) else []
        if ra:
            add = min(10, 5 + len(ra) * 2)
            breakdown["web"] = min(25, breakdown.get("web", 0) + add)
            ent_pts += add
            drivers.append(f"Redirect anomalies (n={len(ra)}) (+{add})")

        # sensitive endpoints
        hits = (ent.get("endpoint_probe", {}) or {}).get("hits", []) if isinstance(ent.get("endpoint_probe", {}), dict) else []
        if hits:
            add = min(30, 12 + len(hits) * 4)
            breakdown["web"] = min(25, breakdown.get("web", 0) + min(10, add // 3))
            breakdown["ports"] = breakdown.get("ports", 0)  # keep
            # apply as exposure to keep buckets bounded
            breakdown["exposure"] = min(10, breakdown.get("exposure", 0) + min(10, add))
            ent_pts += add
            drivers.append(f"Sensitive endpoints exposed (n={len(hits)}) (+{add})")

        # js leaks
        js = ent.get("js_analysis", {}) if isinstance(ent.get("js_analysis", {}), dict) else {}
        js_add = 0
        if js.get("api_key_like"):
            js_add += 20
        if js.get("jwt_like"):
            js_add += 10
        if js.get("script_src_external", 0) >= 3:
            js_add += 5
        if js_add:
            breakdown["web"] = min(25, breakdown.get("web", 0) + min(10, js_add // 2))
            ent_pts += js_add
            drivers.append(f"Possible JS leak indicators (+{js_add})")

        # nonstandard admin port banners
        bans = (ent.get("banners", {}) or {}).get("items", []) if isinstance(ent.get("banners", {}), dict) else []
        if bans:
            add = min(15, 5 + len(bans) * 3)
            breakdown["ports"] = min(20, breakdown.get("ports", 0) + min(8, add))
            ent_pts += add
            drivers.append(f"Service banners on nonstandard ports (n={len(bans)}) (+{add})")

    # Soft cap enterprise extras so SAFE isn't penalized and AGGR stays bounded
    ent_pts = min(45, ent_pts)

    score = sum(v for v in breakdown.values() if isinstance(v, int))
    score = max(0, min(100, int(score)))

    if score >= 90:
        level = "CRITICAL"
    elif score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "NONE"

    return {"score": score, "level": level, "breakdown": breakdown, "drivers": drivers[:10]}




class DomainIntel:
    def __init__(self, domain: str):
        self.domain_raw = domain if isinstance(domain, str) else ""
        self.domain = normalize_domain(self.domain_raw)
        self.domain_valid = is_valid_domain(self.domain)

        self.results: dict = {
            "domain": self.domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "input_raw": self.domain_raw,
            "input_valid": self.domain_valid,
            "dns": {},
            "dns_ok": False,
            "whois": {},
            "whois_info": {},
            "ssl_cert": {},
            "technologies": [],
            "headers_security": {},
            "subdomains": [],
            "ports": [],
            "web_info": {},
            "domain_breaches": [],
            "port_sources": [],
            "censys_lookup": {},
            "tls_score": 0,
            "cloudflare": {},
        }

    def run_all(self):
        if not self.domain_raw or not self.domain_raw.strip():
            print(f"\n  {C.R}✗ Nessun dominio valido fornito{C.RST}")
            return self.results
        
        if not self.domain_valid:
            print(f"\n  {C.R}✗ Dominio non valido: '{self.domain_raw}'. Esempio: example.com{C.RST}")
            return self.results

        cached = session_cache.get_domain(self.domain)
        if cached:
            print(f"\n  {C.CY}📦 Usando risultati in cache per {self.domain}{C.RST}")
            self.results = cached
            self._print_results()
            return self.results

        print(f"\n{C.BLD}{C.CY}{'═'*60}")
        print(f"  🌐 DOMAIN INTELLIGENCE — {self.domain} {Config.aggr_tag()}")
        print(f"{'═'*60}{C.RST}\n")

        tasks = [
            ("DNS Resolution", self._dns_resolve),
            ("SSL Certificate", self._ssl_cert),
            ("HTTP Headers & Security", self._http_headers),
            ("Technology Fingerprint", self._tech_fingerprint),
            ("Subdomain Enumeration", self._subdomain_enum),
            ("Port Scan (Database Pubblici)", self._port_scan),
            ("WHOIS/RDAP Unified", self._whois_unified),
            ("Web Page Analysis", self._web_analysis),
            ("Domain Breach Check", self._domain_breach_check),
        ]

        for i, (name, func) in enumerate(tasks, 1):
            progress_bar(i - 1, len(tasks), name)
            try:
                func()
                status("✓", name, C.G)
            except Exception as e:
                status("✗", f"{name}: {str(e)[:80]}", C.R)
            progress_bar(i, len(tasks), name)

        self._calculate_tls_score()
        self._detect_cloudflare()
        self._run_enterprise_suite()
        self._favicon_hash()
        self._calc_domain_risk()
        session_cache.set_domain(self.domain, self.results)
        self._print_results()
        return self.results

    def _calculate_tls_score(self):
        cert_info = self.results.get("ssl_cert", {})
        headers = self.results.get("headers_security", {}).get("all_headers", {})
        self.results["tls_score"] = calculate_tls_score(cert_info, headers)

    def _detect_cloudflare(self):
        headers = self.results.get("headers_security", {}).get("all_headers", {})
        self.results["cloudflare"] = detect_cloudflare(headers, self.domain)


    def _whois_unified(self):
        """Single RDAP lookup + heuristic WHOIS signals."""
        # RDAP normalized
        rdap = rdap_domain_lookup(self.domain)
        if isinstance(rdap, dict) and rdap.get("status") == "success":
            self.results["whois"] = rdap
        else:
            self.results["whois"] = {"error": "RDAP lookup failed"}

        # Heuristic signals
        sig_score = 0
        reasons = []

        try:
            created = (self.results.get("whois") or {}).get("creation_date")
            if isinstance(created, str) and len(created) >= 4:
                year = int(created[:4])
                age = datetime.now(timezone.utc).year - year
                if age < 1:
                    sig_score += 25; reasons.append("Domain age < 1 year")
                elif age < 3:
                    sig_score += 15; reasons.append("Domain age < 3 years")
                elif age < 5:
                    sig_score += 6; reasons.append("Domain age < 5 years")
        except Exception:
            pass

        try:
            dnssec = (self.results.get("whois") or {}).get("dnssec")
            if not dnssec:
                sig_score += 5; reasons.append("DNSSEC disabled")
        except Exception:
            pass

        try:
            registrar = str((self.results.get("whois") or {}).get("registrar", "")).lower()
            cheap = ["namecheap", "internet.bs", "porkbun", "dynadot", "sav", "gandi", "hostinger"]
            if any(x in registrar for x in cheap):
                sig_score += 5; reasons.append("Low-cost registrar")
        except Exception:
            pass

        self.results["whois_signals"] = {"score": min(100, sig_score), "reasons": reasons[:8]}

    def _favicon_hash(self):
        """AGGR only: fetch favicon.ico bytes and hash SHA-256."""
        if not Config.aggressive_mode:
            return
        try:
            url = f"https://{self.domain}/favicon.ico"
            raw = http.get_bytes(url, timeout=10)
            if not raw:
                url = f"http://{self.domain}/favicon.ico"
                raw = http.get_bytes(url, timeout=10, verify_ssl=False)
            if raw:
                sha = hashlib.sha256(raw).hexdigest()
                self.results["favicon"] = {"url": url, "sha256": sha, "ok": True}
                status("✓", "Favicon hash computed (AGGR)", C.G)
            else:
                self.results["favicon"] = {"url": url, "ok": False}
        except Exception as e:
            self.results["favicon"] = {"ok": False, "error": str(e)[:120]}

    
    # -----------------------------
    # ENTERPRISE (AGGRESSIVE) RECON
    # -----------------------------
    def _enterprise_http_recon(self):
        if not Config.aggressive_mode:
            return
        base_variants = [
            f"https://{self.domain}",
            f"http://{self.domain}",
            f"https://www.{self.domain}",
            f"http://www.{self.domain}",
        ]
        recon = {"variants": [], "best": None, "redirect_anomalies": []}
        for u in base_variants:
            try:
                resp = http.get(u, timeout=12, allow_redirects=True, headers=http.DEFAULT_HEADERS)
                chain = []
                try:
                    # requests keeps history
                    for h in getattr(resp, "history", []) or []:
                        chain.append({"url": h.url, "status": getattr(h, "status_code", None)})
                except Exception:
                    pass
                chain.append({"url": getattr(resp, "url", u), "status": getattr(resp, "status_code", None)})

                final_url = getattr(resp, "url", u)
                status_code = getattr(resp, "status_code", None)
                host0 = urlparse(u).netloc.lower()
                hostf = urlparse(final_url).netloc.lower()
                scheme0 = urlparse(u).scheme.lower()
                schemef = urlparse(final_url).scheme.lower()
                downgrade = (scheme0 == "https" and schemef == "http")
                cross = (hostf and host0 and hostf != host0)

                item = {
                    "input": u,
                    "final_url": final_url,
                    "status": status_code,
                    "redirect_count": max(0, len(chain) - 1),
                    "downgrade": downgrade,
                    "cross_domain_redirect": cross,
                    "chain": chain,
                }
                recon["variants"].append(item)

                # pick best: prefer https final + 200/3xx with lowest redirects
                score = 0
                if schemef == "https": score += 3
                if status_code and int(status_code) < 400: score += 2
                score -= min(item["redirect_count"], 5) * 0.2
                item["_score"] = score
            except Exception:
                continue

        if recon["variants"]:
            best = sorted(recon["variants"], key=lambda x: x.get("_score", 0), reverse=True)[0]
            recon["best"] = {k: v for k, v in best.items() if k != "_score"}
            # anomalies
            if best.get("downgrade"):
                recon["redirect_anomalies"].append("HTTPS→HTTP downgrade detected")
            if best.get("cross_domain_redirect"):
                recon["redirect_anomalies"].append("Cross-domain redirect detected")
            if best.get("redirect_count", 0) >= 4:
                recon["redirect_anomalies"].append(f"Long redirect chain (count={best.get('redirect_count')})")

        self.results.setdefault("enterprise", {})["http_recon"] = recon

    def _enterprise_endpoint_probe(self):
        if not Config.aggressive_mode:
            return
        ent = self.results.setdefault("enterprise", {})
        base = None
        try:
            base = (ent.get("http_recon", {}) or {}).get("best", {}) or {}
            base = base.get("final_url") or None
        except Exception:
            base = None
        if not base:
            base = f"https://{self.domain}"
        base = base.rstrip("/")

        paths = [
            "/admin", "/login", "/dashboard", "/backup", "/.git", "/.env",
            "/api", "/graphql", "/staging", "/test"
        ]
        hits = []
        for path in paths:
            u = base + path
            try:
                resp = http.get(u, timeout=10, allow_redirects=False, headers=http.DEFAULT_HEADERS)
                sc = getattr(resp, "status_code", None)
                if sc in (200, 401, 403):
                    hits.append({"path": path, "status": sc, "url": u})
            except Exception:
                continue
        ent["endpoint_probe"] = {"base": base, "hits": hits, "count": len(hits)}

    def _enterprise_subdomain_expand(self):
        if not Config.aggressive_mode:
            return
        prefixes = ["dev", "test", "vpn", "mail", "portal", "api", "intranet", "old"]
        found = []
        for pfx in prefixes:
            sub = f"{pfx}.{self.domain}"
            try:
                socket.gethostbyname(sub)
                found.append(sub)
            except Exception:
                continue
        self.results.setdefault("enterprise", {})["subdomain_expand"] = {"found": found, "count": len(found)}

    def _enterprise_banner_grab(self):
        if not Config.aggressive_mode:
            return
        ports_info = self.results.get("open_ports", []) or []
        host = self.domain
        banners = []
        for p in ports_info:
            try:
                port = int(p.get("port") if isinstance(p, dict) else p)
            except Exception:
                continue
            if port in (80, 443):
                continue
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3.0)
                s.connect((host, port))
                try:
                    s.sendall(b"\r\n")
                except Exception:
                    pass
                try:
                    data = s.recv(128)
                except Exception:
                    data = b""
                s.close()
                banner = data.decode("utf-8", "ignore").strip()
                banners.append({"port": port, "banner": banner[:80]})
            except Exception:
                continue
        self.results.setdefault("enterprise", {})["banners"] = {"items": banners, "count": len(banners)}

    def _enterprise_js_analysis(self):
        if not Config.aggressive_mode:
            return
        ent = self.results.setdefault("enterprise", {})
        base = None
        try:
            base = (ent.get("http_recon", {}) or {}).get("best", {}) or {}
            base = base.get("final_url") or None
        except Exception:
            base = None
        if not base:
            base = f"https://{self.domain}"
        try:
            resp = http.get(base, timeout=12, allow_redirects=True, headers=http.DEFAULT_HEADERS)
            html = getattr(resp, "text", "") or ""
        except Exception:
            html = ""

        scripts_src = re.findall(r'<script[^>]+src=[\"\']([^\"\']+)[\"\']', html, flags=re.I)
        scripts_src = [s.strip() for s in scripts_src if s.strip()]
        # classify external
        external = 0
        for s in scripts_src:
            try:
                pu = urlparse(s)
                if pu.scheme in ("http", "https") and pu.netloc and self.domain not in pu.netloc:
                    external += 1
            except Exception:
                pass

        # endpoint patterns in HTML/JS urls
        endpoints = set(re.findall(r'(https?://[^\s\"\']+)', html))
        # common API-like relative paths
        rel_api = set(re.findall(r'["\'](/api/[^"\']+|/graphql[^"\']*)["\']', html))
        for rpath in rel_api:
            endpoints.add(rpath)

        # token patterns (very light heuristics)
        jwt_like = bool(re.search(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', html))
        api_key_like = bool(re.search(r'(api[_-]?key|token)\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']', html, flags=re.I))

        ent["js_analysis"] = {
            "script_src_total": len(scripts_src),
            "script_src_external": external,
            "endpoints_found": sorted(list(endpoints))[:40],
            "endpoints_count": len(endpoints),
            "jwt_like": jwt_like,
            "api_key_like": api_key_like,
        }

    def _run_enterprise_suite(self):
        if not Config.aggressive_mode:
            return
        self._enterprise_http_recon()
        self._enterprise_endpoint_probe()
        self._enterprise_subdomain_expand()
        self._enterprise_banner_grab()
        self._enterprise_js_analysis()

    def _calc_domain_risk(self):
        self.results["risk"] = compute_domain_risk_enterprise(self.results)

    def _dns_resolve(self):
        records = {}
        ok = False

        try:
            ips = socket.getaddrinfo(self.domain, None)
            ipv4 = list({addr[4][0] for addr in ips if addr[0] == socket.AF_INET})
            ipv6 = list({addr[4][0] for addr in ips if addr[0] == socket.AF_INET6})
            records["A"] = ipv4
            records["AAAA"] = ipv6
            ok = bool(ipv4 or ipv6)
        except socket.gaierror:
            records["A"] = []
            records["AAAA"] = []
            ok = False

        for rtype in ["MX", "TXT", "NS", "CNAME", "SOA"]:
            data = http.json_get(
                f"https://cloudflare-dns.com/dns-query?name={self.domain}&type={rtype}",
                headers={"Accept": "application/dns-json"}
            )
            if data and "Answer" in data and isinstance(data["Answer"], list):
                records[rtype] = [str(a.get("data", "")) for a in data["Answer"] if isinstance(a, dict)]
            else:
                records[rtype] = []

        self.results["dns"] = records
        self.results["dns_ok"] = ok

        if not ok:
            raise RuntimeError("impossibile risolvere il dominio (DNS)")

    def _ssl_cert(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        try:
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as s:
                s.settimeout(8)
                s.connect((self.domain, 443))
                cert = s.getpeercert()

                tls_version = s.version() if hasattr(s, 'version') else "Unknown"

                if isinstance(cert, dict) and cert:
                    subject = _dn_to_dict(cert.get("subject"))
                    issuer = _dn_to_dict(cert.get("issuer"))

                    self.results["ssl_cert"] = {
                        "subject": subject,
                        "issuer": issuer,
                        "serial": cert.get("serialNumber"),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "san": [
                            str(e[1]) for e in cert.get("subjectAltName", [])
                            if isinstance(e, tuple) and len(e) > 1
                        ],
                        "version": cert.get("version"),
                        "verified": True,
                        "tls_version": tls_version,
                    }
                else:
                    self.results["ssl_cert"] = {"verified": False, "error": "certificato non disponibile"}
                    raise RuntimeError("certificato non disponibile")
        except Exception as e:
            self.results["ssl_cert"] = {"error": str(e), "verified": False}
            raise

    def _http_headers(self):
        resp = http.get(f"https://{self.domain}", timeout=10, verify_ssl=True)
        if not resp.get("ok"):
            resp = http.get(f"http://{self.domain}", timeout=10, verify_ssl=False)

        hdrs = resp.get("headers", {})
        if not isinstance(hdrs, dict):
            hdrs = {}

        security_headers = [
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Frame-Options", "X-Content-Type-Options",
            "X-XSS-Protection", "Referrer-Policy",
            "Permissions-Policy", "Cross-Origin-Opener-Policy",
            "Cross-Origin-Resource-Policy",
        ]

        found = {}
        missing = []
        for sh in security_headers:
            val = hdrs.get(sh) or hdrs.get(sh.lower())
            if val:
                found[sh] = val
            else:
                missing.append(sh)

        score = len(found) / len(security_headers) * 100 if security_headers else 0

        self.results["headers_security"] = {
            "server": hdrs.get("Server") or hdrs.get("server", "N/A"),
            "powered_by": hdrs.get("X-Powered-By") or hdrs.get("x-powered-by", "N/A"),
            "present": found,
            "missing": missing,
            "score": round(score, 1),
            "all_headers": {k: str(v) for k, v in hdrs.items()},
            "tls_verified": resp.get("verified", False),
        }

        if not resp.get("ok"):
            raise RuntimeError("impossibile recuperare headers (HTTP/HTTPS)")

    def _tech_fingerprint(self):
        resp = http.get(f"https://{self.domain}", timeout=10)
        if not resp.get("ok"):
            resp = http.get(f"http://{self.domain}", timeout=10, verify_ssl=False)

        body = resp.get("body", "")
        hdrs = resp.get("headers", {})

        if not isinstance(body, str):
            body = ""
        if not isinstance(hdrs, dict):
            hdrs = {}

        techs = []

        signatures = {
            "WordPress": ["/wp-content/", "/wp-includes/", "wp-json"],
            "Joomla": ["/components/com_", "joomla!"],
            "Drupal": ["drupal.settings", "/sites/default/files"],
            "React": ["react.production.min", "__next_data__", "reactroot"],
            "Next.js": ["__next_data__", "_next/static"],
            "Vue.js": ["vue.min.js", "vue.runtime", "__vue__", "v-cloak"],
            "Angular": ["ng-version", "ng-app", "angular.min.js"],
            "jQuery": ["jquery.min.js", "jquery-"],
            "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
            "Tailwind CSS": ["tailwindcss"],
            "Laravel": ["laravel_session", "csrf-token"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "Flask": ["werkzeug"],
            "Express": ["X-Powered-By: Express"],
            "Cloudflare": ["cf-ray", "cloudflare"],
            "AWS": ["amazons3", "awselb", "x-amz-"],
            "Google Analytics": ["google-analytics.com", "gtag("],
            "Google Tag Manager": ["googletagmanager.com"],
            "Shopify": ["cdn.shopify.com", "shopify.theme"],
            "Wix": ["wix.com", "x-wix-"],
            "Squarespace": ["squarespace.com"],
            "ASP.NET": ["__viewstate", "asp.net"],
        }

        server = str(hdrs.get("Server") or hdrs.get("server") or "").lower()
        powered = str(hdrs.get("X-Powered-By") or hdrs.get("x-powered-by") or "").lower()

        if "nginx" in server:
            techs.append({"name": "Nginx", "category": "Web Server", "confidence": "high"})
        if "apache" in server:
            techs.append({"name": "Apache", "category": "Web Server", "confidence": "high"})
        if "cloudflare" in server:
            techs.append({"name": "Cloudflare", "category": "CDN", "confidence": "high"})
        if "php" in powered:
            techs.append({"name": "PHP", "category": "Language", "confidence": "high"})
        if "asp.net" in powered:
            techs.append({"name": "ASP.NET", "category": "Framework", "confidence": "high"})
        if "express" in powered:
            techs.append({"name": "Express.js", "category": "Framework", "confidence": "high"})

        body_lower = body.lower()
        for tech, sigs in signatures.items():
            for sig in sigs:
                if sig and isinstance(sig, str) and sig.lower() in body_lower:
                    if not any(isinstance(t, dict) and t.get("name") == tech for t in techs):
                        techs.append({"name": tech, "category": "Technology", "confidence": "medium"})
                    break

        self.results["technologies"] = techs

        if not resp.get("ok") and not techs:
            raise RuntimeError("impossibile fingerprint (pagina non raggiungibile)")

    def _subdomain_enum(self):
        subs = set()

        data = http.json_get(f"https://crt.sh/?q=%.{self.domain}&output=json", timeout=15)
        if data and isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict):
                    name = entry.get("name_value", "")
                    if isinstance(name, str):
                        for n in name.split("\n"):
                            n = n.strip().lower()
                            if n.endswith(self.domain) and "*" not in n:
                                subs.add(n)

        cert_info = self.results.get("ssl_cert", {})
        if isinstance(cert_info, dict):
            san_list = cert_info.get("san", [])
            if isinstance(san_list, list):
                for san in san_list:
                    if isinstance(san, str) and san.endswith(self.domain) and "*" not in san:
                        subs.add(san.lower())

        common = [
            "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
            "admin", "portal", "blog", "shop", "store", "api", "dev",
            "staging", "test", "beta", "cdn", "media", "static",
            "ns1", "ns2", "dns", "vpn", "remote", "git", "gitlab",
            "jenkins", "ci", "app", "mobile", "m", "docs", "wiki",
            "support", "help", "status", "monitor", "grafana",
            "prometheus", "kibana", "elastic", "db", "mysql", "redis",
            "mq", "rabbitmq", "kafka", "auth", "sso", "login",
        ]

        def check_sub(sub):
            if not isinstance(sub, str):
                return None
            fqdn = f"{sub}.{self.domain}"
            try:
                socket.getaddrinfo(fqdn, None, socket.AF_INET)
                return fqdn
            except socket.gaierror:
                return None

        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {pool.submit(check_sub, s): s for s in common}
            for f in as_completed(futures):
                result = f.result()
                if result:
                    subs.add(result)

        self.results["subdomains"] = sorted(list(subs)) if subs else []

    def _get_port_service(self, port: int) -> str:
        if not isinstance(port, (int, float)):
            return "unknown"
        port_int = int(port)
        port_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC",
            139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
            8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
            8888: "HTTP-Alt", 9090: "Web-Proxy", 9200: "Elasticsearch",
            27017: "MongoDB",
        }
        return port_services.get(port_int, "unknown")

    def _port_scan(self):
        open_ports = []
        sources = []

        try:
            ip = socket.gethostbyname(self.domain)
            if not isinstance(ip, str):
                raise RuntimeError("IP non valido")
        except socket.gaierror:
            status("○", "Port scan: impossibile risolvere IP", C.DIM)
            return

        status("📡", f"Port scan legale via database pubblici...", C.CY)

        try:
            shodan_data = http.json_get(f"https://internetdb.shodan.io/{ip}", timeout=10)
            if shodan_data and isinstance(shodan_data, dict) and "detail" not in shodan_data:
                ports = shodan_data.get("ports", [])
                if isinstance(ports, list):
                    for port in ports:
                        if isinstance(port, (int, str)):
                            port_int = int(port) if isinstance(port, str) else port
                            open_ports.append({
                                "port": port_int,
                                "service": self._get_port_service(port_int),
                                "state": "open",
                                "banner": "",
                                "source": "Shodan InternetDB",
                                "verified": True
                            })
                    sources.append("Shodan InternetDB")
                    status("✓", f"Shodan: {len(ports)} porte trovate", C.G)
                else:
                    status("○", "Shodan: Nessun dato disponibile", C.DIM)
        except Exception as e:
            status("○", f"Shodan: {str(e)[:30]}", C.DIM)

        try:
            urlscan_data = http.json_get(
                f"https://urlscan.io/api/v1/search/?q=ip:{ip}",
                timeout=10
            )
            if urlscan_data and isinstance(urlscan_data, dict) and urlscan_data.get("total", 0) > 0:
                results = urlscan_data.get("results", [])
                if isinstance(results, list):
                    for result in results[:10]:
                        if isinstance(result, dict):
                            page = result.get("page", {})
                            if isinstance(page, dict) and page.get("ip") == ip and page.get("port"):
                                port = page.get("port")
                                if isinstance(port, (int, str)):
                                    port_int = int(port) if isinstance(port, str) else port
                                    if not any(p["port"] == port_int for p in open_ports):
                                        open_ports.append({
                                            "port": port_int,
                                            "service": self._get_port_service(port_int),
                                            "state": "open",
                                            "banner": str(page.get("server", "")),
                                            "source": "URLScan.io",
                                            "verified": True,
                                            "url": str(result.get("task", {}).get("reportURL", ""))
                                        })
                    if results:
                        sources.append("URLScan.io")
                        status("✓", f"URLScan.io: porte trovate", C.G)
        except Exception:
            pass

        try:
            censys_url = f"https://search.censys.io/hosts/{ip}"
            resp = http.head(censys_url, timeout=8)
            if resp.get("ok"):
                self.results["censys_lookup"] = {
                    "url": censys_url,
                    "note": "Verifica manuale su Censys per porte dettagliate"
                }
                sources.append("Censys")
                status("🔍", "Censys: Ricerca disponibile", C.CY)
        except:
            pass

        if not open_ports:
            status("📡", "Nessuna porta da database, controllo servizi standard...", C.DIM)

            web_info = self.results.get("web_info", {})
            if isinstance(web_info, dict) and web_info.get("title", "N/A") != "N/A":
                for port in [80, 443]:
                    if not any(p["port"] == port for p in open_ports):
                        open_ports.append({
                            "port": port,
                            "service": self._get_port_service(port),
                            "state": "open (deduced)",
                            "banner": "Web server attivo",
                            "source": "Web Analysis",
                            "verified": False
                        })
                sources.append("Web Analysis")

            dns_info = self.results.get("dns", {})
            if isinstance(dns_info, dict) and dns_info.get("MX", []):
                for port in [25, 587, 993, 995]:
                    if not any(p["port"] == port for p in open_ports):
                        open_ports.append({
                            "port": port,
                            "service": self._get_port_service(port),
                            "state": "open (deduced from MX)",
                            "banner": "Mail server presente",
                            "source": "DNS MX Record",
                            "verified": False
                        })
                sources.append("DNS MX Record")

        try:
            self.results["ports"] = sorted(open_ports, key=lambda x: x.get("port", 0))
        except:
            self.results["ports"] = open_ports

        self.results["port_sources"] = list(set(sources)) if sources else []

        if open_ports:
            status("🔓", f"Trovate {len(open_ports)} porte da {len(set(sources))} fonti legali", C.G)
        else:
            status("○", "Nessuna porta rilevata da database pubblici", C.DIM)

    def _whois_lookup(self):
        data = http.json_get(f"https://rdap.org/domain/{self.domain}", timeout=10)
        if data and isinstance(data, dict):
            info = {
                "name": str(data.get("ldhName", "")),
                "status": data.get("status", []),
                "events": [],
                "nameservers": [],
                "entities": [],
            }

            events = data.get("events", [])
            if isinstance(events, list):
                for event in events:
                    if isinstance(event, dict):
                        info["events"].append({
                            "action": str(event.get("eventAction", "")),
                            "date": str(event.get("eventDate", "")),
                        })

            nameservers = data.get("nameservers", [])
            if isinstance(nameservers, list):
                for ns in nameservers:
                    if isinstance(ns, dict):
                        ns_name = ns.get("ldhName")
                        if ns_name:
                            info["nameservers"].append(str(ns_name))

            entities = data.get("entities", [])
            if isinstance(entities, list):
                for entity in entities:
                    if isinstance(entity, dict):
                        roles = entity.get("roles", [])
                        handle = str(entity.get("handle", ""))
                        vcard_info = {}

                        vcard_array = entity.get("vcardArray", [])
                        if isinstance(vcard_array, list) and len(vcard_array) > 1:
                            vcard_list = vcard_array[1]
                            if isinstance(vcard_list, list):
                                for vc in vcard_list:
                                    if isinstance(vc, list) and len(vc) >= 4:
                                        if vc[0] == "fn":
                                            vcard_info["name"] = str(vc[3])
                                        elif vc[0] == "email":
                                            vcard_info["email"] = str(vc[3])
                                        elif vc[0] == "org":
                                            vcard_info["org"] = str(vc[3])

                        info["entities"].append({
                            "roles": roles,
                            "handle": handle,
                            **vcard_info,
                        })

            self.results["whois_info"] = info
        else:
            self.results["whois_info"] = {"error": "RDAP lookup failed"}

    def _whois_rdap(self):
        result = rdap_domain_lookup(self.domain)
        if result and result.get("status") == "success":
            self.results["whois"] = result
            status("✓", f"RDAP: {result.get('registrar', 'N/A')}")

    def _web_analysis(self):
        resp = http.get(f"https://{self.domain}", timeout=10)
        if not resp.get("ok"):
            resp = http.get(f"http://{self.domain}", timeout=10, verify_ssl=False)

        body = resp.get("body", "")
        if not isinstance(body, str):
            body = ""

        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        title = title_match.group(1).strip() if title_match else "N/A"

        desc_match = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', body, re.IGNORECASE)
        description = desc_match.group(1).strip() if desc_match else "N/A"

        emails = list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)))

        links = re.findall(r'href=["\'](https?://[^"\']+)["\']', body, re.IGNORECASE)
        external_links = [l for l in links if self.domain not in l] if isinstance(links, list) else []

        social_patterns = {
            "Twitter/X": r'(?:twitter\.com|x\.com)/([a-zA-Z0-9_]+)',
            "Facebook": r'facebook\.com/([a-zA-Z0-9.]+)',
            "LinkedIn": r'linkedin\.com/(?:company|in)/([a-zA-Z0-9-]+)',
            "Instagram": r'instagram\.com/([a-zA-Z0-9_.]+)',
            "GitHub": r'github\.com/([a-zA-Z0-9-]+)',
            "YouTube": r'youtube\.com/(?:c/|channel/|@)([a-zA-Z0-9_-]+)',
        }

        social = {}
        for platform, pattern in social_patterns.items():
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                social[platform] = list(set(matches))

        robots = http.get(f"https://{self.domain}/robots.txt", timeout=5)
        robots_content = robots["body"][:2000] if robots.get("ok") and isinstance(robots.get("body"), str) else "Not found"

        sitemap = http.head(f"https://{self.domain}/sitemap.xml", timeout=5)

        self.results["web_info"] = {
            "title": title,
            "description": description,
            "emails_found": emails[:20] if emails else [],
            "external_links_count": len(external_links) if external_links else 0,
            "external_links_sample": external_links[:10] if external_links else [],
            "social_media": social,
            "robots_txt": robots_content[:500],
            "sitemap_exists": sitemap.get("ok", False),
            "page_size_kb": round(len(body) / 1024, 1) if body else 0,
        }

        if not resp.get("ok"):
            raise RuntimeError("pagina non raggiungibile (web analysis)")

    def _domain_breach_check(self):
        breaches = []

        try:
            urlscan_url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}"
            data = http.json_get(urlscan_url, timeout=10)
            if data and isinstance(data, dict) and data.get("total", 0) > 0:
                total = data.get("total", 0)
                results = data.get("results", [])
                malicious = 0

                if isinstance(results, list):
                    for r in results[:10]:
                        if isinstance(r, dict):
                            page = r.get("page", {})
                            if isinstance(page, dict) and page.get("status") in [400, 401, 403, 404, 500, 502, 503]:
                                malicious += 1

                breaches.append({
                    "source": "URLScan.io",
                    "confirmed": True,
                    "total_scans": total,
                    "malicious": malicious,
                    "details": f"{total} scansioni trovate"
                })
                status("⚠", f"URLScan.io: {total} scansioni trovate", C.Y)
        except Exception:
            pass

        try:
            ip = socket.gethostbyname(self.domain)
            if isinstance(ip, str):
                shodan_data = http.json_get(f"https://internetdb.shodan.io/{ip}")
                if shodan_data and isinstance(shodan_data, dict) and "detail" not in shodan_data:
                    vulns = shodan_data.get("vulns", [])
                    tags = shodan_data.get("tags", [])

                    if (isinstance(vulns, list) and vulns) or (isinstance(tags, list) and tags):
                        breaches.append({
                            "source": "Shodan InternetDB",
                            "confirmed": True,
                            "vulns": vulns[:10] if isinstance(vulns, list) else [],
                            "tags": tags[:5] if isinstance(tags, list) else [],
                            "details": f"{len(vulns) if isinstance(vulns, list) else 0} vulnerabilità note"
                        })
                        status("⚠", f"Shodan: {len(vulns) if isinstance(vulns, list) else 0} vulnerabilità!", C.R)
        except:
            pass

        if breaches:
            self.results["domain_breaches"] = breaches
            status("🔥", f"Trovati {len(breaches)} breach confermati per il dominio", C.R)

    def _print_results(self):
        r = self.results

        tls_score = r.get("tls_score", 0)
        cf_info = r.get("cloudflare", {})

        score_color = C.G if tls_score >= 70 else C.Y if tls_score >= 40 else C.R
        cf_status = f"{C.G}✓ Yes{C.RST}" if cf_info.get('is_cloudflare') else f"{C.R}✗ No{C.RST}"
        if not cf_info.get('is_cloudflare') and cf_info.get('confidence') == 'Low':
            cf_status = f"{C.Y}? Unknown{C.RST}"

        summary_lines = [
            f"TLS Score:   {score_color}{tls_score}/100{C.RST}",
            f"Cloudflare:  {cf_status} ({cf_info.get('confidence', 'Low')})",
        ]
        print(f"\n{box('🔒 TLS & CLOUDFLARE', summary_lines, C.CY)}")

        dns_lines = []
        dns_info = r.get("dns", {})
        if isinstance(dns_info, dict):
            for rtype, values in dns_info.items():
                if values and isinstance(values, list):
                    for v in values[:5]:
                        v_str = str(v) if v is not None else ""
                        dns_lines.append(f"{C.Y}{rtype:6}{C.RST} → {v_str}")
        if dns_lines:
            print(f"\n{box('📡 DNS Records', dns_lines)}")

        ssl_info = r.get("ssl_cert", {})
        if ssl_info and isinstance(ssl_info, dict) and "error" not in ssl_info:
            verified = ssl_info.get("verified", False)
            verified_str = f"{C.G}✓ Verified{C.RST}" if verified else f"{C.R}✗ Not Verified{C.RST}"

            subject = ssl_info.get("subject", {})
            issuer = ssl_info.get("issuer", {})

            subject_cn = "N/A"
            if isinstance(subject, dict):
                subject_cn = str(subject.get('commonName') or subject.get('organizationName') or "N/A")

            issuer_org = "N/A"
            if isinstance(issuer, dict):
                issuer_org = str(issuer.get('organizationName') or issuer.get('commonName') or "N/A")

            ssl_lines = [
                f"Subject:    {subject_cn}",
                f"Issuer:     {issuer_org}",
                f"Valid From: {ssl_info.get('not_before', 'N/A')}",
                f"Valid To:   {ssl_info.get('not_after', 'N/A')}",
                f"SANs:       {len(ssl_info.get('san', [])) if isinstance(ssl_info.get('san'), list) else 0} entries",
                f"TLS Vers:   {ssl_info.get('tls_version', 'N/A')}",
                f"Status:     {verified_str}",
            ]
            print(f"\n{box('🔒 SSL Certificate', ssl_lines, C.G)}")

        sec = r.get("headers_security", {})
        if sec and isinstance(sec, dict):
            score = sec.get("score", 0)
            score_color = C.G if score >= 70 else C.Y if score >= 40 else C.R
            tls_verified = sec.get("tls_verified", False)
            tls_str = f"{C.G}✓ TLS Verified{C.RST}" if tls_verified else f"{C.R}✗ TLS Not Verified{C.RST}"

            present_headers = sec.get("present", {})
            missing_headers = sec.get("missing", [])

            sec_lines = [
                f"Server:     {sec.get('server', 'N/A')}",
                f"Powered By: {sec.get('powered_by', 'N/A')}",
                f"TLS:        {tls_str}",
                f"Score:      {score_color}{score}%{C.RST}",
                "",
                f"{C.G}Present ({len(present_headers) if isinstance(present_headers, dict) else 0}):{C.RST}",
            ]

            if isinstance(present_headers, dict):
                for h in present_headers.keys():
                    sec_lines.append(f"  ✓ {h}")

            sec_lines.append(f"\n{C.R}Missing ({len(missing_headers) if isinstance(missing_headers, list) else 0}):{C.RST}")

            if isinstance(missing_headers, list):
                for h in missing_headers:
                    sec_lines.append(f"  ✗ {h}")

            print(f"\n{box('🛡️  Security Headers', sec_lines, C.M)}")

        techs = r.get("technologies", [])
        if techs and isinstance(techs, list):
            tech_lines = []
            for t in techs:
                if isinstance(t, dict):
                    conf_icon = "🟢" if t.get("confidence") == "high" else "🟡"
                    tech_lines.append(f"  {conf_icon} {t.get('name', 'Unknown'):20} [{t.get('category', 'Unknown')}]")
            if tech_lines:
                print(f"\n{box('🔧 Technologies Detected', tech_lines, C.B)}")

        subs = r.get("subdomains", [])
        if subs and isinstance(subs, list):
            sub_lines = [f"  • {s}" for s in subs[:30]]
            if len(subs) > 30:
                sub_lines.append(f"  ... and {len(subs)-30} more")
            sub_lines.insert(0, f"  Total: {C.BLD}{len(subs)}{C.RST} subdomains found")
            print(f"\n{box('🌐 Subdomains', sub_lines, C.CY)}")

        ports = r.get("ports", [])
        if ports and isinstance(ports, list):
            port_lines = []
            sources_used = r.get("port_sources", [])

            for p in ports:
                if isinstance(p, dict):
                    verified_icon = "✓" if p.get("verified", False) else "?"
                    verified_color = C.G if p.get("verified", False) else C.Y
                    source = p.get("source", "Unknown")
                    banner_str = f" | {p['banner'][:50]}" if p.get("banner") else ""
                    port_lines.append(
                        f"  {verified_color}{verified_icon}{C.RST}  {p.get('port', 0):>5}/tcp  "
                        f"{p.get('service', 'unknown'):15}  [{source}]{banner_str}"
                    )

            port_lines.append("")
            port_lines.append(f"  {C.DIM}📚 Fonti utilizzate: {', '.join(sources_used) if sources_used else 'Nessuna'}{C.RST}")

            if r.get("censys_lookup"):
                censys = r.get("censys_lookup")
                if isinstance(censys, dict):
                    port_lines.append(f"  {C.DIM}🔗 Censys: {censys.get('url', 'N/A')}{C.RST}")

            print(f"\n{box('🔌 Open Ports (Database Pubblici)', port_lines, C.Y)}")

        web = r.get("web_info", {})
        if web and isinstance(web, dict):
            emails_found = web.get('emails_found', [])
            if isinstance(emails_found, list):
                emails_redacted = [Redactor.email(e) for e in emails_found[:3]] if Config.redact_reports else emails_found[:3]
            else:
                emails_redacted = []

            web_lines = [
                f"Title:       {str(web.get('title', 'N/A'))[:60]}",
                f"Description: {str(web.get('description', 'N/A'))[:60]}",
                f"Page Size:   {web.get('page_size_kb', 0)} KB",
                f"Emails:      {', '.join(emails_redacted) or 'None found'}",
                f"Sitemap:     {'✓ Found' if web.get('sitemap_exists') else '✗ Not found'}",
            ]

            social = web.get("social_media", {})
            if social and isinstance(social, dict):
                web_lines.append(f"\n{C.BLD}Social Media:{C.RST}")
                for platform, handles in social.items():
                    if isinstance(handles, list):
                        web_lines.append(f"  {platform}: {', '.join(handles[:3])}")


            # AGGR extras (favicon + JS footprint)
            fav = r.get('favicon', {})
            if isinstance(fav, dict) and fav.get('ok') and fav.get('sha256'):
                web_lines.append(f"Favicon SHA256: {fav.get('sha256')}")
            if Config.aggressive_mode:
                try:
                    js_count = int(web.get('js_count', 0) or 0)
                except Exception:
                    js_count = 0
                ext_js = web.get('external_js', [])
                ext_js_n = len(ext_js) if isinstance(ext_js, list) else 0
                if js_count:
                    web_lines.append(f"JS files:    {js_count} (external: {ext_js_n})")

            print(f"\n{box('🌍 Web Analysis', web_lines, C.M)}")

        whois = r.get("whois", {})
        if whois and isinstance(whois, dict) and whois.get("status") == "success":
            whois_lines = []
            registrar = whois.get('registrar', 'N/A')
            created = whois.get('creation_date', 'N/A')
            expires = whois.get('expiration_date', 'N/A')
            updated = whois.get('updated_date', 'N/A')
            dnssec = whois.get('dnssec')

            # age (years)
            age_years = None
            try:
                if isinstance(created, str) and len(created) >= 4:
                    y = int(created[:4])
                    age_years = datetime.now(timezone.utc).year - y
            except Exception:
                age_years = None

            whois_lines.append(f"Registrar:    {registrar}")
            rc = whois.get("registrar_country")
            if rc:
                whois_lines.append(f"Country:      {rc}")
            whois_lines.append(f"Created:      {created}")
            if age_years is not None and age_years >= 0:
                whois_lines.append(f"Domain Age:   {age_years} years")
            whois_lines.append(f"Expires:      {expires}")
            whois_lines.append(f"Updated:      {updated}")
            whois_lines.append(f"DNSSEC:       {'✓ Yes' if dnssec else '✗ No'}")

            abuse = whois.get("abuse_email")
            if abuse:
                whois_lines.append(f"Abuse Email:  {abuse}")

            ns_list = whois.get('nameservers', []) or []
            ns_preview = ", ".join(ns_list[:3])
            whois_lines.append(f"Name servers: {ns_preview}")
            if len(ns_list) > 3:
                whois_lines[-1] += f" +{len(ns_list)-3} more"

            # WHOIS flags + mini risk
            sig = r.get("whois_signals", {}) if isinstance(r, dict) else {}
            ws = 0
            reasons = []
            if isinstance(sig, dict):
                ws = int(sig.get("score", 0) or 0)
                reasons = sig.get("reasons", []) or []

            # map to 0-25
            whois_points = max(0, min(25, ws))
            if whois_points >= 18:
                whois_level = "HIGH"
            elif whois_points >= 10:
                whois_level = "MEDIUM"
            elif whois_points > 0:
                whois_level = "LOW"
            else:
                whois_level = "NONE"

            whois_lines.append("")
            whois_lines.append(f"WHOIS Risk:   {whois_level} ({whois_points}/25)")
            if reasons:
                whois_lines.append("WHOIS Flags:")
                for rr in reasons[:5]:
                    whois_lines.append(f"  • {rr}")
            print(f"\n{box(f'📋 WHOIS / RDAP {Config.aggr_tag()}', whois_lines, C.M)}")

        breaches = r.get("domain_breaches", [])
        if breaches and isinstance(breaches, list):
            breach_lines = []
            for b in breaches:
                if isinstance(b, dict):
                    if b.get("source") == "URLScan.io":
                        breach_lines.append(f"  • {C.R}⚠{C.RST} {b.get('source')}: {b.get('details', '')}")
                    elif b.get("source") == "Shodan InternetDB":
                        vulns = b.get('vulns', [])
                        if isinstance(vulns, list):
                            vuln_str = f"{len(vulns)} vulnerabilità: {', '.join(vulns[:3])}" if vulns else "0 vulnerabilità"
                            breach_lines.append(f"  • {C.R}⚠{C.RST} {b.get('source')}: {vuln_str}")

            if breach_lines:
                print(f"\n{box('⚠️  DOMAIN EXPOSURE SIGNALS', breach_lines, C.R)}")



        # Enterprise Domain Risk
        try:
            rk = self.results.get("risk") or {}
            score = int(rk.get("score", 0) or 0)
            level = str(rk.get("level", "UNKNOWN"))
            bd = rk.get("breakdown", {}) if isinstance(rk.get("breakdown", {}), dict) else {}
            color = C.R if score >= 60 else C.Y if score >= 35 else C.G if score > 0 else C.DIM

            lines = [
                f"Risk Score:  {color}{score}/100{C.RST}",
                f"Risk Level:  {C.BLD}{level}{C.RST}",
                "",
                "Breakdown:",
                f"  • TLS:         {bd.get('tls', 0)}",
                f"  • Headers:     {bd.get('headers', 0)}",
                f"  • WHOIS:       {bd.get('whois', 0)}",
                f"  • Ports:       {bd.get('ports', 0)}",
                f"  • Exposure:    {bd.get('exposure', 0)}",
                f"  • Web:         {bd.get('web', 0)}",
                f"  • Mitigations: {bd.get('mitigations', 0)}",
            ]

            drivers = rk.get("drivers", [])
            if isinstance(drivers, list) and drivers:
                lines.append("")
                lines.append("Drivers:")
                for d in drivers[:6]:
                    lines.append(f"  • {d}")


            # Enterprise findings (AGGR)
            try:
                if Config.aggressive_mode:
                    ent = r.get("enterprise", {}) if isinstance(r.get("enterprise", {}), dict) else {}
                    if isinstance(ent, dict) and ent:
                        fl = []
                        hr = ent.get("http_recon", {}) if isinstance(ent.get("http_recon", {}), dict) else {}
                        ra = hr.get("redirect_anomalies", []) if isinstance(hr.get("redirect_anomalies", []), list) else []
                        if ra:
                            fl.append(f"Redirect anomalies: {len(ra)}")
                            for a in ra[:3]:
                                fl.append(f"  • {a}")
                        ep = ent.get("endpoint_probe", {}) if isinstance(ent.get("endpoint_probe", {}), dict) else {}
                        hits = ep.get("hits", []) if isinstance(ep.get("hits", []), list) else []
                        if hits:
                            fl.append(f"Sensitive endpoints: {len(hits)}")
                            for h in hits[:5]:
                                fl.append(f"  • {h.get('path')} ({h.get('status')})")
                        js = ent.get("js_analysis", {}) if isinstance(ent.get("js_analysis", {}), dict) else {}
                        if js:
                            fl.append(f"JS footprint: scripts={js.get('script_src_total',0)}, external={js.get('script_src_external',0)}")
                            if js.get("api_key_like"):
                                fl.append("  • Possible API key/token pattern")
                            if js.get("jwt_like"):
                                fl.append("  • Possible JWT-like token pattern")
                            if js.get("endpoints_count",0):
                                fl.append(f"  • Endpoints found: {js.get('endpoints_count')}")
                        bans = ent.get("banners", {}) if isinstance(ent.get("banners", {}), dict) else {}
                        items = bans.get("items", []) if isinstance(bans.get("items", []), list) else []
                        if items:
                            fl.append(f"Nonstandard banners: {len(items)}")
                            for it in items[:3]:
                                b = (it.get("banner") or "").strip()
                                fl.append(f"  • {it.get('port')}: {b[:50] if b else 'N/A'}")
                        subx = ent.get("subdomain_expand", {}) if isinstance(ent.get("subdomain_expand", {}), dict) else {}
                        found = subx.get("found", []) if isinstance(subx.get("found", []), list) else []
                        if found:
                            fl.append(f"Expanded subdomains: {len(found)}")
                            for s in found[:6]:
                                fl.append(f"  • {s}")
                        if fl:
                            print(f"\n{box('ENTERPRISE FINDINGS', fl, C.M)}")
            except Exception:
                pass

            print(f"\n{box('📊 DOMAIN RISK SCORE', lines, C.CY)}")
        except Exception:
            pass

# ==================== MODULO 3 - EMAIL OSINT ====================

class EmailOSINT:
    def __init__(self, email: str):
        self.email = email.strip().lower() if isinstance(email, str) else ""

        if "@" in self.email:
            parts = self.email.split("@", 1)
            self.local = parts[0]
            self.domain = parts[1]
        else:
            self.local = self.email
            self.domain = ""

        self.results = {
            "email": self.email,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "valid_format": False,
            "domain_info": {},
            "mx_records": [],
            "disposable": False,
            "breaches": [],
            "gravatar": {},
            "social_profiles": [],
            "breach_details": [],
            "breach_source": None,
            "breach_meta": {},
            "breach_summary": None,
            "presence": {
                "platforms": {},
                "confidence": "low",
                "web_mentions": 0,
                "evidence": {}
            },
            "exposure": {
                "confirmed": False,
                "source": None,
                "records": 0,
                "confidence": "low"
            }
        }

    def run_all(self):
        if not self.email or not self.email.strip():
            print(f"\n  {C.R}✗ Nessuna email valida fornita{C.RST}")
            return self.results

        cached = session_cache.get_email(self.email)
        if cached:
            print(f"\n  {C.CY}📦 Usando risultati in cache per {Redactor.email(self.email)}{C.RST}")
            self.results = cached
            self._print_results()
            return self.results

        print(f"\n{C.BLD}{C.M}{'═'*60}")
        email_display = Redactor.email(self.email) if Config.redact_reports else self.email
        print(f"  📧 EMAIL INTELLIGENCE — {email_display} {Config.aggr_tag()}")
        print(f"{'═'*60}{C.RST}\n")

        self._validate_format()

        if not self.results["valid_format"]:
            status("✗", "Input non è un indirizzo email valido. Esempio: nome@dominio.tld", C.R)
            self._print_results()
            return self.results

        self._check_mx()
        self._check_disposable()
        self._gravatar_lookup()
        self._breach_check_combined()
        self._social_enum()
        self._check_presence()
        self._update_exposure()

        session_cache.set_email(self.email, self.results)
        self._print_results()
        return self.results

    def _validate_format(self):
        pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,63}$'
        self.results["valid_format"] = bool(re.match(pattern, self.email))
        status("✓" if self.results["valid_format"] else "✗",
               f"Format validation: {'Valid' if self.results['valid_format'] else 'Invalid'}")

    def _check_mx(self):
        self.results["mx_records"] = []
        self.results["domain_info"] = self.results.get("domain_info", {})

        if not self.domain or "." not in self.domain:
            status("✗", "MX Records: dominio non valido", C.R)
            return

        resolvers = [
            ("Cloudflare", lambda: http.json_get(
                f"https://cloudflare-dns.com/dns-query?name={self.domain}&type=MX",
                headers={"Accept": "application/dns-json"},
                timeout=5
            )),
            ("GoogleDNS", lambda: http.json_get(
                f"https://dns.google/resolve?name={self.domain}&type=MX",
                timeout=5
            )),
            ("Quad9", lambda: http.json_get(
                f"https://dns.quad9.net:5053/dns-query?name={self.domain}&type=MX",
                headers={"Accept": "application/dns-json"},
                timeout=5
            )),
        ]

        def parse_mx_hosts(answer_list):
            hosts = []
            for a in answer_list or []:
                if not isinstance(a, dict):
                    continue
                data = str(a.get("data", "")).strip()
                parts = data.split()
                host = ""
                if len(parts) >= 2:
                    host = parts[1]
                elif len(parts) == 1:
                    host = parts[0]
                host = host.strip().rstrip(".").lower()
                if host:
                    hosts.append(host)
            return list(dict.fromkeys(hosts))

        mx_hosts = []
        used_resolver = None

        for name, fn in resolvers:
            try:
                data = fn()
                if data and isinstance(data, dict):
                    ans = data.get("Answer")
                    if isinstance(ans, list) and ans:
                        mx_hosts = parse_mx_hosts(ans)
                        if mx_hosts:
                            used_resolver = name
                            break
            except Exception:
                continue

        if not mx_hosts:
            hardcoded_mx = {
                "libero.it": ["mx.libero.it", "mx2.libero.it"],
                "tin.it": ["mx.libero.it", "mx2.libero.it"],
                "alice.it": ["mx.libero.it", "mx2.libero.it"],
                "virgilio.it": ["mx.virgilio.it", "mx2.virgilio.it"],
            }
            if self.domain in hardcoded_mx:
                mx_hosts = hardcoded_mx[self.domain]
                used_resolver = "hardcoded"
                status("⚠", f"MX Records: {len(mx_hosts)} found (hardcoded fallback)", C.Y)
            else:
                status("✗", "No MX records found (tutti i tentativi falliti)", C.R)
                return

        self.results["mx_records"] = mx_hosts

        provider = "Unknown"

        if any("google.com" in h or "aspmx.l.google.com" in h for h in mx_hosts):
            provider = "Google"
        elif any("outlook.com" in h or "protection.outlook.com" in h for h in mx_hosts):
            provider = "Microsoft"
        elif any("libero.it" in h for h in mx_hosts):
            provider = "Libero/Italiaonline"
        elif any("yahoo.com" in h or "yahoodns.net" in h for h in mx_hosts):
            provider = "Yahoo"
        elif any("icloud.com" in h or "mail.icloud.com" in h for h in mx_hosts):
            provider = "Apple iCloud"

        self.results["domain_info"]["mx_provider"] = provider
        self.results["domain_info"]["mx_resolver_used"] = used_resolver

        status("✓", f"MX Records: {len(mx_hosts)} found (resolver={used_resolver}, provider={provider})", C.G)

    def _check_disposable(self):
        disposable_domains = {
            "tempmail.com", "throwaway.email", "guerrillamail.com",
            "mailinator.com", "10minutemail.com", "trashmail.com",
            "yopmail.com", "temp-mail.org", "guerrillamail.info",
            "sharklasers.com", "grr.la", "guerrillamailblock.com",
            "tempail.com", "dispostable.com", "maildrop.cc",
            "fakeinbox.com", "mailnesia.com", "mailcatch.com",
        }
        self.results["disposable"] = self.domain in disposable_domains
        if self.results["disposable"]:
            status("⚠", "Disposable email detected!", C.Y)
        else:
            status("✓", "Not a known disposable email")

    def _gravatar_lookup(self):
        email_hash = hashlib.md5(self.email.encode()).hexdigest()
        profile_url = f"https://gravatar.com/{email_hash}.json"
        data = http.json_get(profile_url)

        if data and isinstance(data, dict) and "entry" in data:
            entry_list = data["entry"]
            if isinstance(entry_list, list) and len(entry_list) > 0:
                entry = entry_list[0]
                if isinstance(entry, dict):
                    accounts = entry.get("accounts", [])
                    accounts_list = []
                    if isinstance(accounts, list):
                        for a in accounts:
                            if isinstance(a, dict):
                                accounts_list.append({
                                    "name": str(a.get("shortname", "")),
                                    "url": str(a.get("url", ""))
                                })

                    self.results["gravatar"] = {
                        "exists": True,
                        "display_name": str(entry.get("displayName", "")),
                        "profile_url": str(entry.get("profileUrl", "")),
                        "avatar_url": f"https://gravatar.com/avatar/{email_hash}",
                        "about": str(entry.get("aboutMe", "")),
                        "location": str(entry.get("currentLocation", "")),
                        "accounts": accounts_list,
                    }
                    status("✓", f"Gravatar profile found: {entry.get('displayName', 'N/A')}", C.G)
                    return

        self.results["gravatar"] = {"exists": False}
        status("○", "No Gravatar profile", C.DIM)

    def _breach_check_combined(self):
        print("  📡 Breach Check (XposedOrNot public DB) in corso...")
        breaches_xon, meta_xon = check_breach_xon(self.email)

        self.results["breach_source"] = "XposedOrNot"
        self.results["breaches"] = breaches_xon
        self.results["breach_meta"] = meta_xon or {}

        if breaches_xon is None:
            print("  ○ Breach check non disponibile (timeout/errore fonte)")
            self.results["breach_summary"] = None
        else:
            summary = breach_risk_summary(breaches_xon)
            self.results["breach_summary"] = summary

            if summary["count"] == 0:
                print("  ✅ Nessun breach trovato in alcun database pubblico")
                print("  ℹ Nota: il controllo si basa su database pubblici/statici e può avere ritardi di aggiornamento.")
                print("     Per verifica ufficiale consultare Have I Been Pwned (HIBP).")
            else:
                print(f"  🔥 Trovati {summary['count']} breach")
                print(f"  ⚠ Risk: {summary['level']}  | Score: {summary['score']}/100")
                print(f"  🗓 Timeline: {summary['timeline']}")

        other_breaches = []

        try:
            resp = http.get(
                f"https://emailrep.io/{self.email}",
                headers={"User-Agent": "GhostRecon/3.0", "Accept": "application/json"},
                timeout=10
            )
            if resp["ok"]:
                data = json.loads(resp["body"])
                if isinstance(data, dict):
                    details = data.get("details", {})
                    if isinstance(details, dict) and details.get("breaches", False):
                        breach_count = details.get("breach_count", 0)
                        other_breaches.append({
                            "source": "EmailRep.io",
                            "breach_name": "Multiple Breaches",
                            "records": breach_count,
                            "details": f"{breach_count} breach trovati",
                            "confirmed": True,
                            "reliable": True
                        })
                        status("⚠", f"⚠️ EmailRep.io: {breach_count} breach confermati!", C.R)
        except:
            pass

        try:
            email_hash = hashlib.sha256(self.email.encode()).hexdigest()
            ff_url = f"https://monitor.firefox.com/breach-stats?emailHash={email_hash}"
            resp = http.get(ff_url, timeout=10)
            if resp["ok"]:
                data = json.loads(resp["body"])
                if isinstance(data, dict) and data.get("breached", False):
                    breach_count = data.get("breachCount", 1)
                    breaches_found = data.get("breaches", [])
                    if isinstance(breaches_found, list):
                        for b in breaches_found[:5]:
                            if isinstance(b, dict):
                                other_breaches.append({
                                    "source": "Firefox Monitor",
                                    "breach_name": str(b.get("Name", "Unknown")),
                                    "date": str(b.get("BreachDate", "")),
                                    "details": f"Trovato in: {b.get('Name', 'Unknown breach')}",
                                    "confirmed": True,
                                    "reliable": True
                                })
                    status("⚠", f"⚠️ Firefox Monitor: {breach_count} breach!", C.R)
        except:
            pass

        if Config.aggressive_mode:
            try:
                leak_data = http.post(
                    "https://leak-lookup.com/api/search",
                    data=f"key=&type=email_address&query={self.email}",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=Config.timeout_aggressive
                )
                if leak_data["ok"]:
                    data = json.loads(leak_data["body"])
                    if isinstance(data, dict) and data.get("error") == "false" and data.get("message"):
                        message = data.get("message")
                        if isinstance(message, dict):
                            for breach_name, records in message.items():
                                if records:
                                    record_count = len(records) if isinstance(records, list) else 1
                                    other_breaches.append({
                                        "source": "Leak-Lookup",
                                        "breach_name": str(breach_name),
                                        "records": record_count,
                                        "details": f"Database: {breach_name} ({record_count} records)",
                                        "confirmed": True,
                                        "reliable": True
                                    })
                                    status("⚠", f"⚠️ Leak-Lookup: {breach_name}", C.R)
            except:
                pass

            try:
                snushbase_url = f"https://public.snusbase.com/?search={self.email}&type=email"
                resp = http.get(snushbase_url, timeout=Config.timeout_aggressive)
                if resp["ok"] and "no results" not in resp.get("body", "").lower():
                    body = resp.get("body", "")
                    if isinstance(body, str) and "found" in body.lower():
                        other_breaches.append({
                            "source": "Snusbase",
                            "breach_name": "Public Database",
                            "details": "Email presente in database pubblico",
                            "confirmed": True,
                            "reliable": False
                        })
                        status("⚠", f"⚠️ Snusbase: Email presente!", C.R)
            except:
                pass

            try:
                lc_url = f"https://leakcheck.net/api?key=&type=email&query={self.email}"
                resp = http.get(lc_url, timeout=Config.timeout_aggressive)
                if resp["ok"]:
                    data = json.loads(resp["body"])
                    if isinstance(data, dict) and data.get("success") and data.get("found", 0) > 0:
                        result = data.get("result", [])
                        if isinstance(result, list):
                            for breach in result[:5]:
                                if isinstance(breach, dict):
                                    other_breaches.append({
                                        "source": "LeakCheck",
                                        "breach_name": str(breach.get("name", "Unknown")),
                                        "date": str(breach.get("date", "")),
                                        "details": f"Database: {breach.get('name', 'Unknown')}",
                                        "confirmed": True,
                                        "reliable": True
                                    })
                            status("⚠", f"⚠️ LeakCheck: {data.get('found', 0)} leak!", C.R)
            except:
                pass

        self.results["breach_details"] = other_breaches
        if other_breaches:
            self.results["exposure"]["confirmed"] = True
            self.results["exposure"]["source"] = other_breaches[0]["source"] if other_breaches else "Multiple"
            self.results["exposure"]["records"] = len(other_breaches)
            self.results["exposure"]["confidence"] = "high"
            status("🔥", f"TROVATI {len(other_breaches)} BREACH IN FONTI AGGIUNTIVE!", C.BG_R)

    def _social_enum(self):
        profiles = []
        try:
            data = http.json_get(f"https://api.github.com/search/users?q={self.email}+in:email")
            if data and isinstance(data, dict) and data.get("total_count", 0) > 0:
                items = data.get("items", [])
                if isinstance(items, list):
                    for user in items[:3]:
                        if isinstance(user, dict):
                            profiles.append({
                                "platform": "GitHub",
                                "username": str(user.get("login", "")),
                                "url": str(user.get("html_url", "")),
                            })
                    status("✓", f"Found {len(profiles)} GitHub profile(s)")
        except:
            pass
        self.results["social_profiles"] = profiles

    def _check_presence(self):
        status("🔍", "Verifica presenza su piattaforme...", C.CY)

        presence = self.results.get("presence", {})
        if not isinstance(presence, dict):
            presence = {}

        platforms = {}
        evidence = {}
        web_mentions = 0

        try:
            import urllib.parse
            url = f"https://urlscan.io/api/v1/search/?q={urllib.parse.quote(self.email)}"
            data = http.json_get(url, timeout=8)

            if data and isinstance(data, dict):
                web_mentions = data.get("total", 0)
                web_mentions = int(web_mentions) if isinstance(web_mentions, (int, float, str)) and str(web_mentions).isdigit() else 0

                results = data.get("results", [])
                domains = []

                if isinstance(results, list):
                    for result in results[:5]:
                        if isinstance(result, dict):
                            page = result.get("page", {})
                            if isinstance(page, dict):
                                domain = page.get("domain")
                                if domain and isinstance(domain, str):
                                    domains.append(domain)

                evidence["web_mentions"] = web_mentions
                evidence["top_domains"] = domains[:5]

                if web_mentions > 0:
                    platforms["web"] = "signal"
                    status("✓", f"Trovate {web_mentions} menzioni pubbliche", C.G)
                else:
                    platforms["web"] = "unknown"
                    status("○", "Nessuna menzione pubblica trovata", C.DIM)
        except:
            platforms["web"] = "unknown"
            evidence["web_mentions"] = 0
            evidence["top_domains"] = []

        total_signals = sum(1 for v in platforms.values() if v == "signal")
        if total_signals >= 2:
            confidence = "high"
        elif total_signals == 1:
            confidence = "medium"
        else:
            confidence = "low"

        presence["platforms"] = platforms
        presence["confidence"] = confidence
        presence["web_mentions"] = web_mentions
        presence["evidence"] = evidence

        self.results["presence"] = presence

    def _update_exposure(self):
        exposure = self.results.get("exposure", {})
        if not isinstance(exposure, dict):
            exposure = {}

        if self.results.get("breach_details") and len(self.results["breach_details"]) > 0:
            exposure["confirmed"] = True
            exposure["source"] = "Multiple Sources"
            exposure["records"] = len(self.results["breach_details"])
            exposure["confidence"] = "high"

        elif self.results.get("breach_summary") and self.results["breach_summary"].get("count", 0) > 0:
            exposure["confirmed"] = True
            exposure["source"] = self.results.get("breach_source", "XposedOrNot")
            exposure["records"] = self.results["breach_summary"].get("count", 0)
            exposure["confidence"] = "medium"

        self.results["exposure"] = exposure

    def _print_results(self):
        email_display = Redactor.email(self.email) if Config.redact_reports else self.email

        mx_provider = None
        mx_resolver = None
        domain_info = self.results.get("domain_info", {})
        if isinstance(domain_info, dict):
            mx_provider = domain_info.get("mx_provider")
            mx_resolver = domain_info.get("mx_resolver_used")

        lines = [
            f"Email:       {email_display}",
            f"Valid:       {'✓ Yes' if self.results['valid_format'] else '✗ No'}",
            f"Domain:      {self.domain or 'N/A'}",
            f"Disposable:  {'⚠ Yes!' if self.results['disposable'] else '✓ No'}",
            f"MX Records:  {len(self.results['mx_records'])}",
        ]

        if self.results["valid_format"]:
            if mx_provider or mx_resolver:
                lines.append(f"MX Provider: {mx_provider or 'Unknown'}")
                lines.append(f"MX Resolver: {mx_resolver or 'N/A'}")

        grav = self.results.get("gravatar", {})
        if isinstance(grav, dict) and grav.get("exists"):
            lines.extend([
                "",
                f"{C.BLD}Gravatar Profile:{C.RST}",
                f"  Name:     {grav.get('display_name', 'N/A')}",
                f"  Location: {grav.get('location', 'N/A')}",
                f"  URL:      {grav.get('profile_url', '')}",
            ])

        profiles = self.results.get("social_profiles", [])
        if profiles and isinstance(profiles, list):
            lines.append(f"\n{C.BLD}Social Profiles:{C.RST}")
            for p in profiles:
                if isinstance(p, dict):
                    lines.append(f"  [{p.get('platform', 'Unknown')}] {p.get('username', '')} — {p.get('url', '')}")

        breaches = self.results.get("breaches")
        summary = self.results.get("breach_summary")
        source = self.results.get("breach_source", "N/A")

        if not self.results["valid_format"]:
            lines.append(f"\n{C.R}✗ Inserisci una email valida (es. nome@dominio.tld){C.RST}")

        elif breaches is None:
            lines.append(f"\n{C.Y}○ BREACH CHECK: NON DISPONIBILE{C.RST}")
            lines.append(f"  Fonte: {source}")

        elif summary and summary.get("count", 0) == 0:
            lines.append(f"\n{C.BLD}{C.G}✅ NESSUN BREACH TROVATO{C.RST}")
            lines.append(f"  Fonte: {source}")
            lines.append(f"  {C.DIM}Nota: check basato su DB pubblici/statici; possibile ritardo aggiornamenti.{C.RST}")

        else:
            cnt = summary.get("count", 0) if summary else (len(breaches) if isinstance(breaches, list) else 0)
            lines.append(f"\n{C.BLD}{C.BG_R}⚠️⚠️⚠️  BREACH TROVATI ⚠️⚠️⚠️{C.RST}")
            lines.append(f"  {C.R}TOTALE: {cnt} breach{C.RST}")

            if summary:
                lines.append(f"  Risk: {summary.get('level', 'NONE')}  | Score: {summary.get('score', 0)}/100")
                lines.append(f"  Timeline: {summary.get('timeline', 'N/A')}")
                sample = summary.get('sample', 'N/A')
                lines.append(f"  Esempi: {sample}")

            lines.append(f"  Fonte: {source}")

        other_breaches = self.results.get("breach_details", [])
        if other_breaches and isinstance(other_breaches, list):
            lines.append(f"\n{C.BLD}{C.Y}🔍 Breach rilevati da fonti aggiuntive:{C.RST}")

            by_source = {}
            for b in other_breaches:
                if isinstance(b, dict):
                    src = b.get('source', 'Unknown')
                    by_source.setdefault(src, []).append(b)

            for source_name, breach_list in by_source.items():
                lines.append(f"  {C.Y}📁 {source_name}:{C.RST}")
                for b in breach_list[:3]:
                    if isinstance(b, dict):
                        bn = b.get("breach_name") or b.get("details", "Compromesso")
                        rec = b.get("records")
                        if isinstance(rec, int):
                            lines.append(f"    • {C.R}⚠{C.RST} {bn} ({rec} records)")
                        else:
                            lines.append(f"    • {C.R}⚠{C.RST} {bn}")
                if len(breach_list) > 3:
                    lines.append(f"    • ... e {len(breach_list)-3} altri")

        presence = self.results.get("presence", {})
        if isinstance(presence, dict):
            web_mentions = presence.get("web_mentions", 0)
            confidence = presence.get("confidence", "low")

            if isinstance(web_mentions, int) and web_mentions > 0:
                lines.append(f"\n{C.BLD}{C.CY}🌐 PRESENCE SIGNAL:{C.RST}")
                lines.append(f"  Menzioni web: {web_mentions}")
                lines.append(f"  Confidence: {confidence.upper()}")

                evidence = presence.get("evidence", {})
                if isinstance(evidence, dict):
                    domains = evidence.get("top_domains", [])
                    if domains:
                        lines.append(f"  Domini: {', '.join(domains[:3])}")

        exposure = self.results.get("exposure", {})
        if isinstance(exposure, dict) and exposure.get("confirmed"):
            lines.append(f"\n{C.BLD}{C.R}🔐 BREACH EXPOSURE CONFIRMED:{C.RST}")
            lines.append(f"  Fonte: {exposure.get('source', 'Unknown')}")
            lines.append(f"  Record: {exposure.get('records', 0)}")
            lines.append(f"  Confidence: {exposure.get('confidence', 'low').upper()}")

        print(f"\n{box(f'📧 EMAIL INTELLIGENCE REPORT {Config.aggr_tag()}', lines, C.M)}")

        if self.results["valid_format"] and breaches is not None and summary and summary.get("count", 0) > 0:
            self._draw_breach_timeline(breaches, summary)

    def _draw_breach_timeline(self, breaches, summary):
        if not breaches or not isinstance(breaches, list):
            return

        years = []
        for b in breaches:
            if isinstance(b, dict):
                d = b.get('date') or b.get('breach_date') or b.get('added_date') or b.get('published')
                if d:
                    try:
                        d_str = str(d)
                        if d_str and len(d_str) >= 4:
                            y = int(d_str[:4])
                            if 1990 <= y <= datetime.now().year + 1:
                                years.append(y)
                    except:
                        pass

        if not years:
            return

        from collections import Counter
        year_counts = Counter(years)
        min_year = min(year_counts.keys())
        max_year = max(year_counts.keys())

        print()
        if min_year == max_year:
            print(f"  {C.CY}📅 Breach concentrati nel {min_year}{C.RST}")
            bar_len = min(30, year_counts[min_year] * 2)
            bar = "█" * bar_len
            print(f"  {C.R}{bar}{C.RST}")
            print(f"  {C.DIM}{year_counts[min_year]} breach in questo anno{C.RST}")
        else:
            print(f"  {C.CY}📅 Cronologia breach per anno:{C.RST}")
            print(f"  {C.DIM}anno : numero breach{C.RST}")
            max_count = max(year_counts.values())
            scale = 25
            for year in range(min_year, max_year + 1):
                count = year_counts.get(year, 0)
                if count == 0:
                    continue
                bar_len = int((count / max_count) * scale) if max_count > 0 else 0
                bar = "█" * bar_len
                year_str = f"{year} :"
                if year >= datetime.now().year - 1:
                    color = C.R
                elif year >= datetime.now().year - 3:
                    color = C.Y
                else:
                    color = C.G
                print(f"  {year_str:<7} {color}{bar:<25}{C.RST} {count}")
        print()


# ==================== MODULO 4 - PHONE BREACH CHECK ====================

class PhoneBreachCheck:
    def __init__(self, phone: str, default_country: str = "IT"):
        self.phone_raw = phone.strip() if isinstance(phone, str) else ""
        self.default_country = default_country

        self.results = {
            "phone_raw": self.phone_raw,
            "phone_e164": None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "valid_format": False,
            "country": None,
            "country_name": None,
            "carrier": None,
            "line_type": None,
            "voip_detected": False,
            "footprint_links": [],
            "breaches": [],
            "breach_source": None,
            "breach_summary": None,
            "breach_check_supported": False,
            "notes": [],
            "reputation": {"label": "UNKNOWN", "score": 0, "source": None, "signals": []},
            "reputation_links": [],
        }

    def run_all(self):
        if not self.phone_raw or not self.phone_raw.strip():
            print(f"\n  {C.R}✗ Nessun numero valido fornito{C.RST}")
            return self.results

        cached = session_cache.get_phone(self.phone_raw)
        if cached:
            print(f"\n  {C.CY}📦 Usando risultati in cache per {self._mask_phone(self.phone_raw)}{C.RST}")
            self.results = cached
            self._print_results()
            return self.results

        print(f"\n{C.BLD}{C.Y}{'═'*60}")
        print(f"  📱 PHONE BREACH CHECK — {self._mask_phone(self.phone_raw)} {Config.aggr_tag()}")
        print(f"{'═'*60}{C.RST}\n")

        self._validate_and_normalize()

        if not self.results["valid_format"]:
            status("✗", "Input non è un numero valido. Esempi: +393331234567 oppure 3331234567", C.R)
            self._print_results()
            return self.results

        self._breach_check_phone()

        session_cache.set_phone(self.phone_raw, self.results)
        self._print_results()
        return self.results


    def _validate_and_normalize(self):
        raw = self.phone_raw
        cleaned = re.sub(r"[^\d+]", "", raw)

        # Basic sanity checks (always)
        if cleaned.count("+") > 1 or ("+" in cleaned and not cleaned.startswith("+")):
            self.results["valid_format"] = False
            self.results["notes"].append("Formato non valido: '+' in posizione errata.")
            return

        digits = re.sub(r"\D", "", cleaned)

        if len(digits) < 7 or len(digits) > 15:
            self.results["valid_format"] = False
            self.results["notes"].append("Lunghezza numero non valida (atteso 7..15 cifre).")
            return

        # Phone intelligence (preferred)
        if phonenumbers is not None:
            try:
                if cleaned.startswith("+"):
                    num = phonenumbers.parse(cleaned, None)
                else:
                    num = phonenumbers.parse(cleaned, self.default_country)

                if not phonenumbers.is_valid_number(num):
                    self.results["valid_format"] = False
                    self.results["notes"].append("Numero non valido secondo libphonenumber.")
                    return

                e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
                region = phonenumbers.region_code_for_number(num)

                country_name = None
                try:
                    country_name = pn_geocoder.description_for_number(num, "en") if pn_geocoder else None
                except Exception:
                    country_name = None

                carrier_name = None
                try:
                    carrier_name = pn_carrier.name_for_number(num, "en") if pn_carrier else None
                except Exception:
                    carrier_name = None

                ltype = "UNKNOWN"
                voip = False
                try:
                    nt = phonenumbers.number_type(num)
                    if pn_number_type and nt == pn_number_type.VOIP:
                        ltype = "VOIP"
                        voip = True
                    elif pn_number_type and nt == pn_number_type.MOBILE:
                        ltype = "MOBILE"
                    elif pn_number_type and nt == pn_number_type.FIXED_LINE:
                        ltype = "FIXED_LINE"
                    elif pn_number_type and nt == pn_number_type.FIXED_LINE_OR_MOBILE:
                        ltype = "FIXED_OR_MOBILE"
                    elif pn_number_type and nt == pn_number_type.TOLL_FREE:
                        ltype = "TOLL_FREE"
                    elif pn_number_type and nt == pn_number_type.PREMIUM_RATE:
                        ltype = "PREMIUM_RATE"
                except Exception:
                    ltype = "UNKNOWN"
                    voip = False

                self.results["phone_e164"] = e164
                self.results["country"] = region or self.default_country
                self.results["country_name"] = country_name
                self.results["carrier"] = carrier_name
                self.results["line_type"] = ltype
                self.results["voip_detected"] = bool(voip)
                self.results["valid_format"] = True
                self.results["footprint_links"] = self._public_footprint_links(e164)

                # Reputation (best-effort, OSINT heuristic)
                self.results["reputation_links"] = self._build_reputation_links(e164)
                self.results["reputation"] = self._phone_reputation_heuristic(e164)

                status("✓", f"Format validation: Valid ({self._mask_phone(e164)})", C.G)
                status("✓", f"Country detection: {self.results['country']} ({country_name or 'N/A'})", C.G)
                status("✓", f"Carrier detection: {carrier_name or 'N/A'}", C.G)
                status("✓", f"VoIP detection: {'YES' if voip else 'NO'}", C.G)
                status("✓", f"Public footprint search: {len(self.results['footprint_links'])} query links ready", C.G)
                return

            except Exception:
                self.results["notes"].append("phonenumbers parse failed; fallback to basic normalization.")

        # Fallback (no phonenumbers or parse error)
        if cleaned.startswith("+"):
            e164 = "+" + digits
            country = self._guess_country_from_e164(e164)
        else:
            e164 = "+39" + digits
            country = self.default_country

        self.results["phone_e164"] = e164
        self.results["country"] = country
        self.results["valid_format"] = True
        self.results["footprint_links"] = self._public_footprint_links(e164)

        status("✓", f"Format validation: Valid ({self._mask_phone(e164)})", C.G)
        status("✓", f"Country detection: {country}", C.G)
        if phonenumbers is None:
            status("○", "Carrier detection: N/A (phonenumbers not installed)", C.Y)
            status("○", "VoIP detection: N/A (phonenumbers not installed)", C.Y)
        status("✓", f"Public footprint search: {len(self.results['footprint_links'])} query links ready", C.G)

    def _public_footprint_links(self, e164: str) -> list:
        q = (e164 or "").strip()
        if not q:
            return []
        q_plain = urllib.parse.quote(q)
        q_leak = urllib.parse.quote(f"{q} leak")
        q_paste = urllib.parse.quote(f"{q} site:pastebin.com OR site:paste.ee OR site:ghostbin.com")
        q_forums = urllib.parse.quote(f"{q} forum OR channel OR group")
        return [
            f"https://www.google.com/search?q={q_plain}",
            f"https://www.google.com/search?q={q_leak}",
            f"https://www.google.com/search?q={q_paste}",
            f"https://www.google.com/search?q={q_forums}",
            f"https://www.bing.com/search?q={q_plain}",
            f"https://duckduckgo.com/?q={q_plain}",
        ]

    def _guess_country_from_e164(self, e164: str) -> str:
        if e164.startswith("+39"):
            return "IT"
        if e164.startswith("+1"):
            return "US/CA"
        if e164.startswith("+44"):
            return "UK"
        if e164.startswith("+33"):
            return "FR"
        if e164.startswith("+49"):
            return "DE"
        if e164.startswith("+34"):
            return "ES"
        return "Unknown"

    def _breach_check_phone(self):
        self.results["breach_source"] = "XposedOrNot"
        status("📡", "Breach Check (XposedOrNot public DB) in corso...", C.CY)

        breaches, meta = check_phone_breach_xon(self.results["phone_e164"])
        self.results["breaches"] = breaches if breaches else []
        self.results["breach_meta"] = meta or {}
        self.results["breach_check_supported"] = meta.get("breach_check_supported", False) if isinstance(meta, dict) else False

        if not self.results["breach_check_supported"]:
            status("○", "Phone breach check: not supported (public endpoint not available)", C.Y)
            self.results["breach_summary"] = {"count": 0, "level": "UNKNOWN", "score": 0, "supported": False}
            return

        count = len(self.results["breaches"]) if isinstance(self.results["breaches"], list) else 0
        level = "NONE"
        score = 0
        if count >= 10:
            level, score = "HIGH", 90
        elif count >= 3:
            level, score = "MEDIUM", 70
        elif count >= 1:
            level, score = "LOW", 45

        self.results["breach_summary"] = {"count": count, "level": level, "score": score, "supported": True}

        if count == 0:
            status("✓", "Nessun breach trovato (DB pubblici)", C.G)
        else:
            status("🔥", f"Trovati {count} breach — Risk: {level} | Score: {score}/100", C.R)


    def _build_reputation_links(self, e164: str) -> List[str]:
        digits = re.sub(r"[^0-9+]", "", e164)
        digits_no_plus = digits.replace("+", "")
        return [
            f"https://www.tellows.it/num/{digits}",
            f"https://www.chi-chiama.it/numero/{digits_no_plus}",
            f"https://www.google.com/search?q={urllib.parse.quote(digits)}+spam+truffa",
        ]

    def _phone_reputation_heuristic(self, e164: str) -> Dict[str, Any]:
        """Best-effort phone reputation without API keys.
        Tries a lightweight fetch (tellows). If it fails, returns UNKNOWN.
        """
        rep = {"label": "UNKNOWN", "score": 0, "source": None, "signals": []}
        url = f"https://www.tellows.it/num/{re.sub(r'[^0-9+]', '', e164)}"
        try:
            r = self.session.get(url, timeout=6, allow_redirects=True)
            if r.status_code == 200 and r.text:
                t = r.text.lower()
                rep["source"] = "tellows"
                bad_kw = ["truffa", "spam", "call center", "telemarketing", "scam", "fraud", "molest"]
                hits = [k for k in bad_kw if k in t]
                if hits:
                    rep["signals"] = hits[:6]
                    rep["label"] = "SUSPICIOUS"
                    rep["score"] = min(95, 60 + len(hits) * 7)
                else:
                    rep["label"] = "POSSIBLE_REPORTS"
                    rep["score"] = 35
        except Exception:
            pass
        return rep

    def _print_results(self):
        r = self.results

        phone_disp = self._mask_phone(r.get("phone_e164") or r.get("phone_raw") or "")
        lines = [
            f"Phone:       {phone_disp}",
            f"Valid:       {'✓ Yes' if r.get('valid_format') else '✗ No'}",
            f"Country:     {r.get('country') or 'N/A'}" + (f" ({r.get('country_name')})" if r.get('country_name') else ""),
            f"Carrier:     {r.get('carrier') or 'N/A'}",
            f"Line Type:   {r.get('line_type') or 'N/A'}",
            f"VoIP:        {'✓ Yes' if r.get('voip_detected') else '○ No'}",
            f"Footprint:   {len(r.get('footprint_links') or [])} query links",
        ]

        # Invalid format path
        if not r.get("valid_format"):
            notes = r.get("notes", [])
            if isinstance(notes, list) and notes:
                lines.append("")
                lines.append("Errors:")
                for n in notes[:5]:
                    lines.append(f"  • {n}")
            else:
                lines.append("")
                lines.append("Errors:")
                lines.append("  • Inserisci un numero valido. Esempi: +393331234567 oppure 3331234567")

            links = r.get("footprint_links") or []
            if isinstance(links, list) and links:
                lines.append("")
                lines.append("Footprint Links:")
                for u in links[:6]:
                    lines.append(f"  • {u}")

            rep_links = r.get("reputation_links") or []
            if rep_links:
                lines.append("")
                lines.append("Reputation Links:")
                for u in rep_links[:3]:
                    lines.append(f"  • {u}")

            print(f"\n{box(f'📱 PHONE BREACH CHECK REPORT {Config.aggr_tag()}', lines, C.Y)}")
            return

        # Valid format path
        if not r.get("breach_check_supported", True):
            lines.append("")
            lines.append(f"{C.Y}Breach Check: NOT SUPPORTED (public endpoint not available){C.RST}")
        else:
            summary = r.get("breach_summary") or {}
            lines.extend([
                f"Breach Source: {r.get('breach_source') or 'N/A'}",
                f"Breaches:      {summary.get('count', 0)}",
                f"Risk:          {summary.get('level', 'N/A')}  | Score: {summary.get('score', 0)}/100",
            ])

            breaches = r.get("breaches", [])
            if isinstance(breaches, list) and breaches:
                lines.append("")
                lines.append("Examples:")
                for b in breaches[:5]:
                    if isinstance(b, dict):
                        name = b.get("name") or b.get("breach") or b.get("title") or "Unknown"
                        date = b.get("date") or b.get("breach_date") or b.get("published") or "N/A"
                        lines.append(f"  • {name} ({str(date)[:10]})")
                    else:
                        lines.append(f"  • {str(b)[:80]}")

        links = r.get("footprint_links") or []
        if isinstance(links, list) and links:
            lines.append("")
            lines.append("Footprint Links:")
            for u in links[:6]:
                lines.append(f"  • {u}")

        print(f"\n{box(f'📱 PHONE BREACH CHECK REPORT {Config.aggr_tag()}', lines, C.Y)}")

    def _mask_phone(self, s: str) -> str:
        if not isinstance(s, str) or not s:
            return "N/A"
        digits = re.sub(r"\D", "", s)
        if len(digits) <= 6:
            return s
        return s[:3] + "*" * (len(s) - 6) + s[-3:]




# ==================== MODULO 5 - USERNAME HUNTER ====================

class UsernameHunter:
    PLATFORMS_DIRECT = {
        "GitHub": "https://github.com/{}",
        "Instagram": "https://www.instagram.com/{}/",
        "Twitter/X": "https://twitter.com/{}",
        "Facebook": "https://www.facebook.com/{}",
        "LinkedIn": "https://www.linkedin.com/in/{}",
        "Reddit": "https://www.reddit.com/user/{}",
        "TikTok": "https://www.tiktok.com/@{}",
        "Snapchat": "https://www.snapchat.com/add/{}",
        "Pinterest": "https://www.pinterest.com/{}/",
        "Tumblr": "https://{}.tumblr.com",
        "YouTube": "https://www.youtube.com/@{}",
        "Twitch": "https://www.twitch.tv/{}",
        "Discord": "https://discord.com/users/{}",
        "Telegram": "https://t.me/{}",
        "WhatsApp": "https://wa.me/{}",
        "Signal": "https://signal.me/#u/{}",
        "GitLab": "https://gitlab.com/{}",
        "Bitbucket": "https://bitbucket.org/{}/",
        "StackOverflow": "https://stackoverflow.com/users/{}",
        "HackerNews": "https://news.ycombinator.com/user?id={}",
        "Dev.to": "https://dev.to/{}",
        "Medium": "https://medium.com/@{}",
        "Keybase": "https://keybase.io/{}",
        "Replit": "https://replit.com/@{}",
        "CodePen": "https://codepen.io/{}",
        "GeeksforGeeks": "https://auth.geeksforgeeks.org/user/{}/profile",
        "Steam": "https://steamcommunity.com/id/{}",
        "Epic Games": "https://www.epicgames.com/@{}",
        "Xbox": "https://account.xbox.com/it-it/profile?gamertag={}",
        "PlayStation": "https://my.playstation.com/profile/{}",
        "Minecraft": "https://namemc.com/profile/{}",
        "Roblox": "https://www.roblox.com/user.aspx?username={}",
        "Fortnite": "https://fortnitetracker.com/profile/all/{}",
        "Apex Legends": "https://apex.tracker.gg/apex/profile/origin/{}/overview",
        "HWG": "https://www.hwupgrade.it/forum/member.php?username={}",
        "Tom's Hardware": "https://forum.tomsguide.it/members/?username={}",
        "ForumFree": "https://member.forumfree.it/?user={}",
        "Androidiani": "https://www.androidiani.com/forum/members/{}.html",
        "Moto.it": "https://www.moto.it/forum/member.php?username={}",
        "Quora": "https://www.quora.com/profile/{}",
        "ProductHunt": "https://www.producthunt.com/@{}",
        "Behance": "https://www.behance.net/{}",
        "Dribbble": "https://dribbble.com/{}",
        "Flickr": "https://www.flickr.com/people/{}",
        "Vimeo": "https://vimeo.com/{}",
        "SoundCloud": "https://soundcloud.com/{}",
        "Spotify": "https://open.spotify.com/user/{}",
        "Last.fm": "https://www.last.fm/user/{}",
        "Mixcloud": "https://www.mixcloud.com/{}/",
        "Xing": "https://www.xing.com/profile/{}",
        "AngelList": "https://angel.co/u/{}",
        "Upwork": "https://www.upwork.com/freelancers/~{}",
        "Fiverr": "https://www.fiverr.com/{}",
        "Freelancer": "https://www.freelancer.com/u/{}",
        "Tinder": "https://tinder.com/@{}",
        "Bumble": "https://bumble.com/it/profile/{}",
        "Grindr": "https://www.grindr.com/profile/{}",
        "Wikipedia": "https://en.wikipedia.org/wiki/User:{}",
        "Patreon": "https://www.patreon.com/{}",
        "Kickstarter": "https://www.kickstarter.com/profile/{}",
        "Etsy": "https://www.etsy.com/people/{}",
        "eBay": "https://www.ebay.com/usr/{}",
        "Amazon": "https://www.amazon.com/gp/profile/{}",
        "Wish": "https://www.wish.com/{}",
        "Aliexpress": "https://feedback.aliexpress.com/display/evaluationDetail.htm?memberId={}",
    }
    
    PLATFORMS_API = {
        "GitHub": {
            "url": "https://api.github.com/users/{}",
            "check": lambda d: isinstance(d, dict) and d.get("id") is not None,
            "fields": ["login", "name", "bio", "public_repos", "followers", "location", "blog", "twitter_username", "created_at"]
        },
        "Reddit": {
            "url": "https://www.reddit.com/user/{}/about.json",
            "check": lambda d: isinstance(d, dict) and d.get("data", {}).get("id") is not None,
            "fields": ["name", "total_karma", "created_utc", "is_gold", "link_karma", "comment_karma"]
        },
        "Instagram": {
            "url": "https://www.instagram.com/{}/?__a=1",
            "check": lambda d: isinstance(d, dict) and d.get("graphql", {}).get("user", {}).get("id") is not None,
            "fields": ["full_name", "biography", "edge_followed_by", "edge_follow", "is_private", "is_verified"]
        },
    }
    
    def __init__(self, username: str):
        self.username = username.strip().lower() if isinstance(username, str) else ""
        self.results = {
            "username": self.username,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "found_profiles": [],
            "not_found": [],
            "breaches": [],
            "summary": None,
            "stats": {
                "total_checked": 0,
                "found": 0,
                "not_found": 0,
                "error": 0
            }
        }

    def hunt(self):
        if not self.username:
            print(f"\n  {C.R}✗ Nessun username valido fornito{C.RST}")
            return self.results
            
        print(f"\n{C.BLD}{C.Y}{'═'*60}")
        print(f"  🎯 USERNAME HUNTER — {self.username} {Config.aggr_tag()}")
        print(f"{'═'*60}{C.RST}\n")
        
        status("🔍", f"Controllo {len(self.PLATFORMS_DIRECT)} piattaforme...", C.CY)
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(self._check_platform, name, url): name 
                for name, url in self.PLATFORMS_DIRECT.items()
            }
            
            for i, future in enumerate(as_completed(futures), 1):
                platform = futures[future]
                try:
                    result = future.result()
                    if i % 10 == 0:
                        progress_bar(i, len(self.PLATFORMS_DIRECT), f"Checking {platform[:15]}...")
                except Exception as e:
                    self.results["stats"]["error"] += 1
        
        progress_bar(len(self.PLATFORMS_DIRECT), len(self.PLATFORMS_DIRECT), "Completato!")
        
        self._check_breaches()
        self._generate_summary()
        self._print_results()
        
        return self.results
    
    def _check_platform(self, name: str, url_template: str) -> dict:
        self.results["stats"]["total_checked"] += 1
        
        url = url_template.format(self.username)
        
        result = {
            "platform": name,
            "url": url,
            "checked": datetime.now().isoformat()
        }
        
        try:
            if name in ["Instagram", "TikTok", "Snapchat"]:
                resp = http.head(url, timeout=5)
            else:
                resp = http.get(url, timeout=5)
            
            if resp["ok"] and resp["status"] == 200:
                body = resp.get("body", "")
                body_lower = body.lower() if isinstance(body, str) else ""
                
                false_positives = [
                    "not found", "user not found", "profile not found",
                    "page not found", "doesn't exist", "no user",
                    "non trovato", "utente non esistente", "pagina non trovata"
                ]
                
                is_false_positive = any(fp in body_lower for fp in false_positives)
                
                if not is_false_positive or len(body_lower) < 200:
                    result["found"] = True
                    result["status"] = "found"
                    result["method"] = "direct"
                    self.results["found_profiles"].append(result)
                    self.results["stats"]["found"] += 1
                    return result
        except:
            pass
        
        self.results["not_found"].append({
            "platform": name,
            "url": url,
            "status": "not_found"
        })
        self.results["stats"]["not_found"] += 1
        return {"platform": name, "found": False}
    
    def _check_breaches(self):
        status("🔥", f"Controllo breach per username '{self.username}'...", C.Y)
        
        if Config.aggressive_mode:
            try:
                data = http.post(
                    "https://leak-lookup.com/api/search",
                    data={
                        "key": "",
                        "type": "username",
                        "query": self.username
                    },
                    timeout=Config.timeout_aggressive
                )
                
                if data["ok"]:
                    result = json.loads(data["body"])
                    if isinstance(result, dict) and result.get("error") == "false" and result.get("message"):
                        message = result.get("message")
                        if isinstance(message, dict):
                            for breach_name, records in message.items():
                                if records:
                                    record_count = len(records) if isinstance(records, list) else 1
                                    self.results["breaches"].append({
                                        "source": "Leak-Lookup",
                                        "breach_name": str(breach_name),
                                        "records": record_count,
                                        "confirmed": True
                                    })
                            
                            if self.results["breaches"]:
                                status("🔥", f"⚠️ Trovato in {len(self.results['breaches'])} breach!", C.R)
            except:
                pass
            
            try:
                url = f"https://psbdmp.ws/api/search/{self.username}"
                data = http.json_get(url, timeout=Config.timeout_aggressive)
                if data and isinstance(data, dict) and data.get("count", 0) > 0:
                    self.results["breaches"].append({
                        "source": "PSBDMP (Pastebin)",
                        "breach_name": "Pastebin Dumps",
                        "count": data.get("count", 0),
                        "url": f"https://psbdmp.ws/search/{self.username}",
                        "confirmed": True
                    })
                    status("⚠", f"Trovato in {data.get('count', 0)} pastebin dumps", C.Y)
            except:
                pass
    
    def _generate_summary(self):
        found_count = self.results["stats"]["found"]
        total = self.results["stats"]["total_checked"]
        
        if found_count == 0:
            level = "NESSUNO"
        elif found_count < 5:
            level = "BASSO"
        elif found_count < 15:
            level = "MEDIO"
        else:
            level = "ALTO"
        
        self.results["summary"] = {
            "found_count": found_count,
            "total_checked": total,
            "coverage": f"{found_count}/{total}",
            "exposure_level": level,
            "breach_count": len(self.results["breaches"])
        }
    
    def _print_results(self):
        stats = self.results["stats"]
        summary = self.results["summary"]
        
        lines = [
            f"Username:    {self.username}",
            f"",
            f"{C.BLD}📊 STATISTICHE:{C.RST}",
            f"  Piattaforme controllate: {stats['total_checked']}",
            f"  Profili trovati:          {C.G}{stats['found']}{C.RST}",
            f"  Non trovati:              {stats['not_found']}",
            f"  Errori:                   {stats['error']}",
            f"  Copertura:                {summary['coverage']}",
            f"  Livello esposizione:      {summary['exposure_level']}",
        ]
        
        if self.results["found_profiles"]:
            lines.extend([
                f"",
                f"{C.BLD}{C.G}✅ PROFILI TROVATI ({len(self.results['found_profiles'])}):{C.RST}"
            ])
            
            social = []
            dev = []
            gaming = []
            forums = []
            other = []
            
            for p in self.results["found_profiles"]:
                if isinstance(p, dict):
                    name = p.get("platform", "")
                    if name in ["GitHub", "GitLab", "Bitbucket", "StackOverflow", "Dev.to", "Medium", "Keybase", "CodePen"]:
                        dev.append(p)
                    elif name in ["Steam", "Epic Games", "Xbox", "PlayStation", "Minecraft", "Roblox", "Twitch"]:
                        gaming.append(p)
                    elif name in ["HWG", "Tom's Hardware", "ForumFree", "Androidiani", "Moto.it", "Reddit", "Quora"]:
                        forums.append(p)
                    elif name in ["Facebook", "Instagram", "Twitter/X", "LinkedIn", "TikTok", "Snapchat"]:
                        social.append(p)
                    else:
                        other.append(p)
            
            categories = [
                ("📱 Social", social, C.M),
                ("💻 Developer", dev, C.CY),
                ("🎮 Gaming", gaming, C.G),
                ("🗣️ Forum", forums, C.Y),
                ("📦 Altro", other, C.DIM)
            ]
            
            for cat_name, cat_list, color in categories:
                if cat_list:
                    lines.append(f"  {color}{cat_name}:{C.RST}")
                    for p in sorted(cat_list, key=lambda x: x.get("platform", ""))[:5]:
                        if isinstance(p, dict):
                            lines.append(f"    • {p.get('platform', '')}: {p.get('url', '')}")
                    if len(cat_list) > 5:
                        lines.append(f"    • ... e {len(cat_list)-5} altri")
        
        if self.results["breaches"]:
            lines.extend([
                f"",
                f"{C.BLD}{C.R}🔥 BREACH TROVATI ({len(self.results['breaches'])}):{C.RST}"
            ])
            for b in self.results["breaches"][:5]:
                if isinstance(b, dict):
                    if b.get("source") == "PSBDMP (Pastebin)":
                        lines.append(f"  • {C.R}⚠{C.RST} {b.get('source')}: {b.get('count', 0)} dumps")
                    else:
                        lines.append(f"  • {C.R}⚠{C.RST} {b.get('source')}: {b.get('breach_name')}")
            if len(self.results["breaches"]) > 5:
                lines.append(f"  • ... e {len(self.results['breaches'])-5} altri")
        
        if stats['found'] > 0:
            lines.extend([
                f"",
                f"{C.BLD}{C.Y}💡 RACCOMANDAZIONI:{C.RST}",
                f"  • Usa username diversi per ogni piattaforma",
                f"  • Evita di usare lo stesso username per account sensibili",
                f"  • Controlla le impostazioni privacy sui profili trovati"
            ])
            
            if self.results["breaches"]:
                lines.append(f"  • {C.R}⚠  Cambia password OVUNQUE usi questo username{C.RST}")
        
        print(f"\n{box(f'🎯 USERNAME HUNTER REPORT {Config.aggr_tag()}', lines, C.Y)}")
        
        if stats['found'] > 0:
            print(f"\n  {C.CY}💡 Per approfondire un profilo, usa i moduli:{C.RST}")
            print(f"  {C.G}• Email OSINT{C.RST} se trovi email nei profili")
            print(f"  {C.G}• Phone Breach Check{C.RST} se trovi numeri")
            print(f"  {C.G}• Domain Intel{C.RST} se trovi domini personali")


# ==================== MODULO 6 - IP INTELLIGENCE ====================

class IPIntel:
    def __init__(self, ip: str):
        self.ip = ip.strip() if isinstance(ip, str) else ""
        self.results = {}

    def run_all(self):
        if not self.ip:
            print(f"\n  {C.R}✗ Nessun IP valido fornito{C.RST}")
            return self.results

        print(f"\n{C.BLD}{C.R}{'═'*60}")
        print(f"  📍 IP INTELLIGENCE — {Redactor.ip(self.ip) if Config.redact_reports else self.ip} {Config.aggr_tag()}")
        print(f"{'═'*60}{C.RST}\n")

        self._geolocate()
        self._asn_info()
        self._threat_check()
        self._reputation_check()
        self._reverse_dns()
        self._print_results()
        return self.results

    def _geolocate(self):
        data = http.json_get(
            f"http://ip-api.com/json/{self.ip}?fields=66846719",
            verify_ssl=False
        )

        if data and isinstance(data, dict) and data.get("status") == "success":
            self.results["geo"] = {
                "country": str(data.get("country", "")),
                "country_code": str(data.get("countryCode", "")),
                "region": str(data.get("regionName", "")),
                "city": str(data.get("city", "")),
                "zip": str(data.get("zip", "")),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "timezone": str(data.get("timezone", "")),
                "isp": str(data.get("isp", "")),
                "org": str(data.get("org", "")),
                "as": str(data.get("as", "")),
                "asname": str(data.get("asname", "")),
                "mobile": bool(data.get("mobile", False)),
                "proxy": bool(data.get("proxy", False)),
                "hosting": bool(data.get("hosting", False)),
            }
            status("✓", f"Location: {data.get('city')}, {data.get('country')}")
        else:
            status("✗", "Geolocation failed", C.R)

    def _asn_info(self):
        data = http.json_get(f"https://ipinfo.io/{self.ip}/json")
        if data and isinstance(data, dict):
            self.results["ipinfo"] = {
                "hostname": str(data.get("hostname", "N/A")),
                "org": str(data.get("org", "N/A")),
                "city": str(data.get("city", "")),
                "region": str(data.get("region", "")),
                "country": str(data.get("country", "")),
                "loc": str(data.get("loc", "")),
            }
            status("✓", f"Org (ipinfo): {data.get('org', 'N/A')}")

    def _threat_check(self):
        shodan_data = http.json_get(f"https://internetdb.shodan.io/{self.ip}")
        if shodan_data and isinstance(shodan_data, dict) and "detail" not in shodan_data:
            self.results["shodan"] = {
                "ports": shodan_data.get("ports", []) if isinstance(shodan_data.get("ports"), list) else [],
                "hostnames": shodan_data.get("hostnames", []) if isinstance(shodan_data.get("hostnames"), list) else [],
                "cpes": shodan_data.get("cpes", []) if isinstance(shodan_data.get("cpes"), list) else [],
                "vulns": shodan_data.get("vulns", []) if isinstance(shodan_data.get("vulns"), list) else [],
                "tags": shodan_data.get("tags", []) if isinstance(shodan_data.get("tags"), list) else [],
            }
            n_vulns = len(self.results["shodan"]["vulns"])
            if n_vulns > 0:
                status("⚠", f"Shodan: {n_vulns} vulnerabilities known!", C.R)
            else:
                status("✓", f"Shodan: {len(self.results['shodan']['ports'])} open ports")
        else:
            status("○", "Shodan InternetDB: No data", C.DIM)

    def _reputation_check(self):
        status("🔍", "Verifica reputazione su blacklist...", C.CY)

        reputation = {
            "blacklisted": False,
            "lists": [],
            "hits": [],
            "reasons": [],
            "score": 100,
            "level": "UNKNOWN",
            "sources_checked": [],
        }

        geo = self.results.get("geo", {})
        if not isinstance(geo, dict):
            geo = {}

        is_hosting = bool(geo.get("hosting", False))
        is_proxy   = bool(geo.get("proxy", False))
        is_mobile  = bool(geo.get("mobile", False))

        org = str(geo.get("org") or geo.get("isp") or geo.get("as") or "").lower()
        consumer_hint = any(k in org for k in [
            "telecom", "tim", "vodafone", "wind", "fastweb", "eolo", "tiscali",
            "telefonica", "orange", "deutsche telekom", "bt", "comcast", "verizon",
            "dsl", "broadband", "fibra", "adsl"
        ])
        is_consumer = is_mobile or consumer_hint or (not is_hosting and not is_proxy)

        dnsbl_lists = [
            {"name": "zen.spamhaus.org",          "weight": 0,  "type": "spamhaus_zen"},
            {"name": "cbl.abuseat.org",           "weight": 25, "type": "cbl"},
            {"name": "bl.spamcop.net",            "weight": 12, "type": "spamcop"},
            {"name": "dnsbl.sorbs.net",           "weight": 8,  "type": "sorbs"},
            {"name": "b.barracudacentral.org",    "weight": 10, "type": "barracuda"},
        ]

        spamhaus_map = {
            "127.0.0.2":  ("SBL", 30, "Spamhaus SBL (spam sources)"),
            "127.0.0.3":  ("CSS", 10, "Spamhaus CSS (compromised/abused)"),
            "127.0.0.4":  ("XBL", 25, "Spamhaus XBL (exploited/botnet)"),
            "127.0.0.10": ("PBL", 8,  "Spamhaus PBL (policy: IP consumer/dynamic)"),
            "127.0.0.11": ("PBL", 8,  "Spamhaus PBL (policy: IP consumer/dynamic)"),
        }

        verify_urls = {
            "zen.spamhaus.org":       lambda ip: f"https://check.spamhaus.org/listed/?searchterm={ip}",
            "cbl.abuseat.org":        lambda ip: f"http://cbl.abuseat.org/lookup.cgi?ip={ip}",
            "bl.spamcop.net":         lambda ip: f"https://www.spamcop.net/bl.shtml?ip={ip}",
            "dnsbl.sorbs.net":        lambda ip: f"https://www.sorbs.net/lookup.shtml?ip={ip}",
            "b.barracudacentral.org": lambda ip: f"https://www.barracudacentral.org/lookups/lookup-reputation?ip_address={ip}",
        }

        def _verify_url(dnsbl_name: str) -> str:
            fn = verify_urls.get(dnsbl_name)
            return fn(self.ip) if fn else f"https://www.google.com/search?q={dnsbl_name}+{self.ip}"


        try:
            ip_parts = str(self.ip).split(".")
            if len(ip_parts) != 4:
                self.results["reputation"] = reputation
                status("○", "Reputation: IP non IPv4 / formato non supportato", C.DIM)
                return

            reversed_ip = ".".join(reversed(ip_parts))

            try:
                socket.setdefaulttimeout(2.5)
            except:
                pass

            for item in dnsbl_lists:
                dnsbl = item["name"]
                reputation["sources_checked"].append(dnsbl)
                query = f"{reversed_ip}.{dnsbl}"

                try:
                    ans = socket.gethostbyname(query)
                    if not ans:
                        continue

                    if item.get("type") == "spamhaus_zen":
                        code = ans.strip()
                        list_type, weight, descr = spamhaus_map.get(
                            code, ("ZEN", 15, f"Spamhaus ZEN (code {code})")
                        )

                        if list_type == "PBL" and is_consumer:
                            weight = 5
                            descr = "Spamhaus PBL (policy: IP consumer/dynamic) — segnale debole"
                        elif list_type == "PBL" and not is_consumer:
                            weight = 15
                            descr = "Spamhaus PBL su IP non-consumer — attenzione (config/hosting?)"

                        if weight > 0:
                            reputation["score"] = max(0, reputation["score"] - weight)

                        reputation["blacklisted"] = True
                        reputation["lists"].append(dnsbl)
                        reputation["hits"].append({
                            "dnsbl": dnsbl,
                            "answer": code,
                            "type": list_type,
                            "weight": weight,
                            "description": descr,
                        })
                        reputation["reasons"].append(descr)

                        status("⚠", f"IP listato: {dnsbl} → {list_type} ({code})", C.R if weight >= 20 else C.Y)
                        continue

                    weight = int(item.get("weight", 10))
                    if is_consumer and item.get("type") in ("sorbs", "spamcop"):
                        weight = max(3, weight // 2)

                    reputation["score"] = max(0, reputation["score"] - weight)
                    reputation["blacklisted"] = True
                    reputation["lists"].append(dnsbl)
                    reputation["hits"].append({
                        "dnsbl": dnsbl,
                        "answer": ans.strip(),
                        "type": item.get("type", "generic"),
                        "weight": weight,
                        "description": f"DNSBL hit: {dnsbl}",
                    })
                    reputation["reasons"].append(f"DNSBL hit: {dnsbl}")

                    status("⚠", f"IP in blacklist: {dnsbl}", C.R if weight >= 20 else C.Y)
                    print(f"      ↳ Verify: {_verify_url(dnsbl)}")

                except socket.gaierror:
                    pass
                except Exception:
                    pass

        except Exception:
            pass

        reputation["score"] = max(0, min(100, int(reputation.get("score", 100))))

        if reputation["score"] >= 80:
            rep_level, rep_color = "GOOD", C.G
        elif reputation["score"] >= 50:
            rep_level, rep_color = "FAIR", C.Y
        else:
            rep_level, rep_color = "POOR", C.R

        reputation["level"] = rep_level
        self.results["reputation"] = reputation

        if not reputation["blacklisted"]:
            status("✓", f"IP non presente in blacklist (score: {reputation['score']}/100)", C.G)
        else:
            status("⚠", f"Reputazione: {rep_level} | Score: {reputation['score']}/100", rep_color)

    def _reverse_dns(self):
        try:
            hostname = socket.gethostbyaddr(self.ip)
            self.results["reverse_dns"] = hostname[0]
            status("✓", f"Reverse DNS: {hostname[0]}")
        except (socket.herror, socket.gaierror):
            self.results["reverse_dns"] = "N/A"
            status("○", "No reverse DNS", C.DIM)
        except Exception:
            self.results["reverse_dns"] = "N/A"
            status("○", "No reverse DNS", C.DIM)

    def _print_results(self):
        geo = self.results.get("geo", {})
        if not isinstance(geo, dict):
            geo = {}

        ipinfo = self.results.get("ipinfo", {})
        if not isinstance(ipinfo, dict):
            ipinfo = {}

        lines = [
            f"IP:         {Redactor.ip(self.ip) if Config.redact_reports else self.ip}",
            f"Reverse DNS:{self.results.get('reverse_dns', 'N/A')}",
            "",
            f"{C.BLD}Geolocation:{C.RST}",
            f"  Country:  {geo.get('country', 'N/A')} ({geo.get('country_code', '')})",
            f"  Region:   {geo.get('region', 'N/A')}",
            f"  City:     {geo.get('city', 'N/A')}",
            f"  Coords:   {geo.get('lat', 'N/A')}, {geo.get('lon', 'N/A')}",
            f"  Timezone: {geo.get('timezone', 'N/A')}",
            "",
            f"{C.BLD}Network:{C.RST}",
            f"  ISP:      {geo.get('isp', 'N/A')}",
            f"  Org:      {geo.get('org', 'N/A')}",
            f"  ASN:      {geo.get('as', 'N/A')}",
        ]

        if ipinfo.get("org") and ipinfo.get("org") != geo.get("org"):
            lines.append(f"  Org (ipinfo): {ipinfo.get('org', 'N/A')}")

        lines.extend([
            f"  Mobile:   {'Yes' if geo.get('mobile') else 'No'}",
            f"  Proxy:    {'⚠ Yes' if geo.get('proxy') else 'No'}",
            f"  Hosting:  {'Yes' if geo.get('hosting') else 'No'}",
        ])

        rep = self.results.get("reputation", {})
        if isinstance(rep, dict):
            score = rep.get("score", 100)
            level = rep.get("level", "GOOD")
            blacklisted = rep.get("blacklisted", False)

            if blacklisted:
                rep_color = C.R
            elif score >= 80:
                rep_color = C.G
            elif score >= 50:
                rep_color = C.Y
            else:
                rep_color = C.R

            lines.extend([
                "",
                f"{C.BLD}Reputation:{C.RST}",
                f"  Score:     {rep_color}{score}/100 ({level}){C.RST}",
                f"  Blacklist: {'⚠ Yes' if blacklisted else '✓ No'}",
            ])

            if blacklisted and rep.get("lists"):
                lines.append(f"  Lists:     {', '.join(rep['lists'][:3])}")

        shodan = self.results.get("shodan", {})
        if isinstance(shodan, dict):
            lines.extend([
                "",
                f"{C.BLD}Shodan InternetDB:{C.RST}",
                f"  Ports:    {', '.join(map(str, shodan.get('ports', [])))}",
                f"  Hosts:    {', '.join(shodan.get('hostnames', [])[:5])}",
            ])
            vulns = shodan.get("vulns", [])
            if vulns:
                lines.append(f"  {C.R}Vulns:    {', '.join(vulns[:10])}{C.RST}")

        if geo.get("lat") and geo.get("lon") and not Config.redact_reports:
            maps_url = f"https://www.google.com/maps?q={geo['lat']},{geo['lon']}"
            lines.append(f"\n  🗺️  {maps_url}")

        print(f"\n{box(f'📍 IP Intelligence Report {Config.aggr_tag()}', lines, C.R)}")


# ==================== MODULO 7 - DATA LEAK RECON ====================

class DataLeakRecon:
    def __init__(self, targets: List[str], deep: bool = False):
        self.targets = targets if isinstance(targets, list) else []
        self.deep = bool(deep)
        self.results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "targets": [],
            "summary": {}
        }

    def _normalize_target(self, t: str) -> str:
        if not isinstance(t, str):
            return ""
        t = t.strip()
        t = t.strip(",;.")
        t = re.sub(r"\s+", " ", t)
        return t

    def run(self):
        print(f"\n{C.BLD}{C.R}{'═'*60}")
        print(f"  🔍 DATA LEAK RECON {Config.aggr_tag()}")
        print(f"{'═'*60}{C.RST}\n")

        norm_targets = []
        for t in self.targets:
            nt = self._normalize_target(t)
            if nt:
                norm_targets.append(nt)

        if not norm_targets:
            status("⚠", "Nessun target specificato", C.Y)
            return self.results

        leak_hits = 0
        exposure_signals = 0

        for target in norm_targets:
            print(f"\n  {C.Y}Target: {target}{C.RST}")

            target_result = {
                "target": target,
                "type": self._detect_type(target),
                "findings": [],
                "sources_checked": []
            }

                        # URLScan.io — meaningful mainly for domains (web exposure / scans)
            if target_result.get("type") == "domain":
                try:
                    import urllib.parse
                    q = urllib.parse.quote(target)
                    url = f"https://urlscan.io/api/v1/search/?q={q}"
                    data = http.json_get(url, timeout=8)

                    target_result["sources_checked"].append("URLScan.io")

                    if data and isinstance(data, dict):
                        count = data.get("total", 0)
                        try:
                            count = int(count)
                        except Exception:
                            count = 0

                        if count > 0:
                            target_result["findings"].append({
                                "source": "URLScan.io",
                                "category": "exposure",
                                "type": "web_mention",
                                "count": count,
                                "url": f"https://urlscan.io/search/#{target}"
                            })
                            status("⚠", f"Trovate {count} menzioni web (exposure)", C.Y)
                            exposure_signals += 1

                            # Aggressive: include a few concrete result URLs (verify)
                            if aggressive_mode:
                                try:
                                    res = data.get("results") or []
                                    examples = []
                                    for r in res[:5]:
                                        rid = r.get("_id") or r.get("task", {}).get("uuid")
                                        if not rid:
                                            continue
                                        # Public UI URL (more user-friendly than API)
                                        examples.append(f"https://urlscan.io/result/{rid}/")
                                    if examples:
                                        target_result["findings"].append({
                                            "source": "URLScan.io (examples)",
                                            "category": "signal",
                                            "type": "links",
                                            "count": len(examples),
                                            "links": examples
                                        })
                                except Exception:
                                    pass
                except Exception:
                    pass


            try:
                url = f"https://psbdmp.ws/api/search/{target}"
                data = http.json_get(url, timeout=5)

                target_result["sources_checked"].append("PSBDMP")

                if data and isinstance(data, dict):
                    count = data.get("count", 0)
                    try:
                        count = int(count)
                    except:
                        count = 0

                    if count > 0:
                        target_result["findings"].append({
                            "source": "PSBDMP (Pastebin)",
                            "category": "leak",
                            "type": "paste_dump",
                            "count": count,
                            "url": f"https://psbdmp.ws/search/{target}"
                        })
                        status("🔥", f"Trovati {count} paste/dump (leak-like)!", C.R)
                        leak_hits += count

                        # Aggressive: include a few paste references (metadata-only) for verification
                        # NOTE: we do NOT download paste contents; we only link to public index pages.
                        try:
                            if Config.aggressive_mode and isinstance(data.get("data"), list):
                                examples = []
                                for item in data.get("data", [])[:5]:
                                    if isinstance(item, dict):
                                        pid = item.get("id") or item.get("paste_id") or item.get("key")
                                        if isinstance(pid, str) and pid:
                                            examples.append(f"https://psbdmp.ws/api/paste/{pid}")
                                if examples:
                                    target_result["findings"].append({
                                        "source": "PSBDMP (examples)",
                                        "category": "signal",
                                        "type": "paste_refs",
                                        "count": len(examples),
                                        "links": [{"engine": "psbdmp", "url": u} for u in examples],
                                    })
                        except Exception:
                            pass

            except:
                pass

            # Mozilla Observatory (security posture - NOT a leak source)
            if target_result.get("type") == "domain":
                try:
                    target_result["sources_checked"].append("Mozilla Observatory")
                    # Always provide a verify link
                    target_result["findings"].append({
                        "source": "Mozilla Observatory",
                        "category": "signal",
                        "type": "link",
                        "count": 1,
                        "links": [{"label": "Observatory analyze", "url": f"https://observatory.mozilla.org/analyze/{target}"}]
                    })
                    # In aggressive mode, try to pull cached score (no rescan) to enrich the report
                    if Config.aggressive_mode:
                        api = f"https://http-observatory.security.mozilla.org/api/v1/analyze?host={target}&rescan=false"
                        data = http.json_get(api, timeout=8)
                        if isinstance(data, dict):
                            score = data.get("score")
                            grade = data.get("grade")
                            state = data.get("state")
                            if score is not None or grade:
                                target_result["findings"].append({
                                    "source": "Mozilla Observatory (cached)",
                                    "category": "signal",
                                    "type": "score",
                                    "count": 1,
                                    "details": {"score": score, "grade": grade, "state": state},
                                    "links": [{"label": "API analyze (cached)", "url": api}]
                                })
                except Exception:
                    pass


            # -----------------------------
            # DEEP SOURCES (no keys) - only when deep=True
            # -----------------------------
            if self.deep:
                try:
                    import urllib.parse
                except Exception:
                    urllib = None
                # Guardrail: in aggressive mode, avoid deep code-search on very generic / broad queries
                # (keeps noise down and reduces misuse potential)
                if Config.aggressive_mode:
                    if re.search(r"\s", target) or len(target) < 4:
                        target_result["sources_checked"].append("Deep sources skipped (generic)")
                        # still provide passive dork links below
                        deep_skip = True
                    else:
                        deep_skip = False
                else:
                    deep_skip = False
                # 1) searchcode.com public API (code leaks / snippets)
                try:
                    if deep_skip:
                        raise Exception('skip')
                    q = urllib.parse.quote(target)
                    sc_url = f"https://searchcode.com/api/result/{q}/"
                    data = http.json_get(sc_url, timeout=10)
                    target_result["sources_checked"].append("Searchcode")
                    if data and isinstance(data, dict):
                        cnt = int(data.get("total", 0) or 0)
                        if cnt > 0:
                            target_result["findings"].append({
                                "source": "Searchcode",
                                "category": "exposure",
                                "type": "code_mention",
                                "count": cnt,
                                "url": f"https://searchcode.com/?q={q}"
                            })
                            status("⚠", f"Searchcode: {cnt} risultati (code exposure)", C.Y)
                            exposure_signals += 1

                        # Aggressive: include a few concrete result URLs for quick verification (no content scraping)
                        try:
                            if Config.aggressive_mode and isinstance(data.get("results"), list):
                                examples = []
                                for r in data.get("results", [])[:5]:
                                    if isinstance(r, dict):
                                        u = r.get("result") or r.get("page") or r.get("task", {}).get("url")
                                        # 'result' is usually a urlscan result JSON URL; keep it proof-friendly
                                        if isinstance(u, str) and u.startswith("http"):
                                            examples.append(u)
                                if examples:
                                    target_result["findings"].append({
                                        "source": "URLScan.io (examples)",
                                        "category": "signal",
                                        "type": "result_links",
                                        "count": len(examples),
                                        "links": [{"engine": "urlscan", "url": u} for u in examples],
                                    })
                        except Exception:
                            pass

                except Exception:
                    pass

                # 2) GitHub code search (rate-limited, best-effort)
                try:
                    if deep_skip:
                        raise Exception('skip')
                    q = urllib.parse.quote(target)
                    gh_url = f"https://api.github.com/search/code?q={q}"
                    data = http.json_get(gh_url, timeout=10, headers={**http.DEFAULT_HEADERS, "User-Agent": "GhostRecon/3.1"})
                    target_result["sources_checked"].append("GitHub Search")
                    if data and isinstance(data, dict):
                        cnt = int(data.get("total_count", 0) or 0)
                        # keep it bounded: GitHub can return huge totals
                        if cnt > 0:
                            show = min(cnt, 1000)
                            target_result["findings"].append({
                                "source": "GitHub Search",
                                "category": "exposure",
                                "type": "code_mention",
                                "count": show,
                                "url": f"https://github.com/search?q={q}&type=code"
                            })
                            status("⚠", f"GitHub code mentions: {show} (cap)", C.Y)
                            exposure_signals += 1

                        # Aggressive: include a few concrete result URLs for quick verification (no content scraping)
                        try:
                            if Config.aggressive_mode and isinstance(data.get("results"), list):
                                examples = []
                                for r in data.get("results", [])[:5]:
                                    if isinstance(r, dict):
                                        u = r.get("result") or r.get("page") or r.get("task", {}).get("url")
                                        # 'result' is usually a urlscan result JSON URL; keep it proof-friendly
                                        if isinstance(u, str) and u.startswith("http"):
                                            examples.append(u)
                                if examples:
                                    target_result["findings"].append({
                                        "source": "URLScan.io (examples)",
                                        "category": "signal",
                                        "type": "result_links",
                                        "count": len(examples),
                                        "links": [{"engine": "urlscan", "url": u} for u in examples],
                                    })
                        except Exception:
                            pass

                except Exception:
                    pass

                # 3) Passive dork links (Pastebin-like, Ghostbin, Paste.ee) - no scanning, just links
                try:
                    # Paste/dork links (verification-only). We never fetch paste content here.
                    base_sites = "site:pastebin.com OR site:paste.ee OR site:ghostbin.com OR site:hastebin.com"
                    # Basic query (always)
                    basic_query = f'"{target}" {base_sites}'
                    basic_q = urllib.parse.quote(basic_query)

                    dorks = [
                        ("Google (basic)", f"https://www.google.com/search?q={basic_q}"),
                        ("Bing (basic)", f"https://www.bing.com/search?q={basic_q}"),
                        ("DuckDuckGo (basic)", f"https://duckduckgo.com/?q={basic_q}"),
                    ]

                    # Aggressive: add a password/stealer-oriented query pack for the SAME target (still verification-only)
                    if Config.aggressive_mode:
                        kw_pack = "(password OR pass OR pwd OR creds OR credential OR combo OR stealer OR infostealer OR log)"
                        aggr_query = f'"{target}" {kw_pack} {base_sites}'
                        aggr_q = urllib.parse.quote(aggr_query)
                        dorks.extend([
                            ("Google (aggr+keywords)", f"https://www.google.com/search?q={aggr_q}"),
                            ("Bing (aggr+keywords)", f"https://www.bing.com/search?q={aggr_q}"),
                            ("DuckDuckGo (aggr+keywords)", f"https://duckduckgo.com/?q={aggr_q}"),
                        ])

                    target_result["findings"].append({
                        "source": "Paste/Dork Links",
                        "category": "signal",
                        "type": "links",
                        "count": len(dorks),
                        "links": [{"engine": n, "url": u} for n, u in dorks]
                    })
                except Exception:
                    pass


            self.results["targets"].append(target_result)

        self.results["summary"] = {
            "total_targets": len(norm_targets),
            "leak_hits": leak_hits,
            "exposure_signals": exposure_signals,
            "timestamp": datetime.now().isoformat()
        }

        self.results["hits"] = leak_hits
        self.results["signals"] = exposure_signals

        self._print_results()
        return self.results

    def _detect_type(self, target: str) -> str:
        if not isinstance(target, str):
            return "unknown"
        if '@' in target:
            return "email"
        elif re.match(r'^[\d\.]+$', target) and target.count('.') == 3:
            return "ip"
        elif re.match(r'^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$', target):
            return "domain"
        elif re.match(r'^\+?[\d\s\-\(\)]{8,}$', target):
            return "phone"
        else:
            return "username"

    def _print_results(self):
        summary = self.results.get("summary", {})

        leak_hits = summary.get("leak_hits", 0)
        exposure = summary.get("exposure_signals", 0)

        leak_color = C.R if leak_hits > 0 else C.G
        exp_color = C.Y if exposure > 0 else C.DIM

        lines = [
            f"Targets analizzati:   {summary.get('total_targets', 0)}",
            f"Leak-like hits:       {leak_color}{leak_hits}{C.RST}",
            f"Exposure signals:     {exp_color}{exposure}{C.RST}",
            "",
            f"{C.BLD}Dettaglio per target:{C.RST}"
        ]

        for t in self.results.get("targets", []):
            if not isinstance(t, dict):
                continue

            target_name = t.get("target", "Unknown")
            target_type = t.get("type", "unknown")
            findings = t.get("findings", [])

            lines.append(f"  {C.Y}{target_name}{C.RST} ({target_type})")

            if findings and isinstance(findings, list):
                for f in findings:
                    if not isinstance(f, dict):
                        continue
                    src = f.get("source", "Unknown")
                    cnt = f.get("count", 0)
                    cat = f.get("category", "signal")
                    icon = "🔥" if cat == "leak" else "🌐"
                    lines.append(f"    {icon} {src}: {cnt} risultati ({cat})")
            else:
                lines.append(f"    {C.G}✓ Nessun segnale trovato{C.RST}")

        if leak_hits > 0:
            box_color = C.R
        elif exposure > 0:
            box_color = C.Y
        else:
            box_color = C.G

        print(f"\n{box('🔍 DATA LEAK RECON REPORT', lines, box_color)}")



# ==================== MODULO 8 - LEAK INTELLIGENCE (STRICT ENTERPRISE) ====================

class LeakIntelligenceEngine:
    """
    STRICT ENTERPRISE MODE (NO KEY, NO SCRAPING):
    - Accetta SOLO email valide o domini validi (FQDN).
    - Rifiuta keyword generiche / username / handle (@name) per ridurre rumore e falsi positivi.
    - Fornisce link verificabili (pivot OSINT) tramite i findings di DataLeakRecon (deep=True).
    """

    EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
    DOMAIN_REGEX = re.compile(
        r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
        r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
    )

    def __init__(self, targets: List[str]):
        self.targets_raw = targets if isinstance(targets, list) else []
        self.targets_valid: List[str] = []
        self.targets_rejected: List[str] = []
        self._filter_targets()

    def _is_email(self, s: str) -> bool:
        return bool(self.EMAIL_REGEX.match(s.strip()))

    def _is_domain(self, s: str) -> bool:
        ss = s.strip().lower()
        if ss.startswith("http://") or ss.startswith("https://"):
            try:
                ss = urlparse(ss).netloc
            except Exception:
                pass
        # reject things like "@libero.it:" or "@name"
        if ss.startswith("@") or ":" in ss or " " in ss:
            return False
        return bool(self.DOMAIN_REGEX.match(ss))

    def _filter_targets(self):
        for t in self.targets_raw:
            if not isinstance(t, str):
                continue
            s = t.strip()
            if not s:
                continue
            if self._is_email(s) or self._is_domain(s):
                self.targets_valid.append(s)
            else:
                self.targets_rejected.append(s)

    def _score_from_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        leak_cnt = 0
        exposure_cnt = 0
        signal_cnt = 0
        sources = set()
        links: List[str] = []
        link_seen = set()
        drivers: List[str] = []

        for f in findings or []:
            if not isinstance(f, dict):
                continue
            src = str(f.get("source", "Unknown"))
            sources.add(src)

            # Collect verification links (proof-ready)
            try:
                u = f.get("url")
                # Normalize URLScan API links to human-friendly result page (works without API/GUID validation)
                if isinstance(u, str) and "urlscan.io/api/v1/result/" in u:
                    try:
                        _uuid = u.split("/api/v1/result/")[-1].strip("/ ")
                        u = f"https://urlscan.io/result/{_uuid}/"
                    except Exception:
                        pass
                if isinstance(u, str) and u.startswith("http") and u not in link_seen:
                    links.append(u)
                    link_seen.add(u)
            except Exception:
                pass
            try:
                lks = f.get("links")
                if isinstance(lks, list):
                    for item in lks:
                        if isinstance(item, dict):
                            uu = item.get("url")
                            if isinstance(uu, str) and "urlscan.io/api/v1/result/" in uu:
                                try:
                                    _uuid = uu.split("/api/v1/result/")[-1].strip("/ ")
                                    uu = f"https://urlscan.io/result/{_uuid}/"
                                except Exception:
                                    pass
                            if isinstance(uu, str) and uu.startswith("http") and uu not in link_seen:
                                links.append(uu)
                                link_seen.add(uu)
            except Exception:
                pass

            cat = str(f.get("category", "signal"))
            cnt = f.get("count", 0) or 0
            try:
                cnt_i = int(cnt)
            except Exception:
                cnt_i = 0

            if cat == "leak":
                leak_cnt += cnt_i
                if cnt_i > 0:
                    drivers.append(f"🔥 {src}: {cnt_i} leak-like hits")
            elif cat == "exposure":
                exposure_cnt += max(1, cnt_i) if cnt_i > 0 else 0
                if cnt_i > 0:
                    drivers.append(f"🌐 {src}: {cnt_i} exposure mentions")
            else:
                signal_cnt += max(1, cnt_i) if cnt_i > 0 else 0
                if cnt_i > 0:
                    drivers.append(f"🔎 {src}: {cnt_i} signals")

        # Score model (bounded, conservative + noise-aware)
        # NOTE: exposure counts can be huge for popular domains (e.g., repubblica.it) and do NOT imply a leak.
        # We therefore apply a log-scale to exposure to avoid inflated scores from mere popularity.
        score = 0
        score += min(60, leak_cnt * 20)

        # log10 scale: 0->0, 2->~1.1, 10->2, 100->3, 1000->4 ...
        exp_points = int(2 * math.log10(exposure_cnt + 1))  # capped: exposure != leak (popularity/noise)
        sig_points = int(3 * math.log10(signal_cnt + 1))    # softer than linear

        score += min(10, exp_points)
        score += min(15, sig_points)
        score = max(0, min(100, score))

        if score >= 70:
            conf = "HIGH"
        elif score >= 40:
            conf = "MED"
        else:
            conf = "LOW"

        return {
            "score": score,
            "confidence": conf,
            "leak_cnt": leak_cnt,
            "exposure_cnt": exposure_cnt,
            "signal_cnt": signal_cnt,
            "sources": sorted(list(sources))[:10],
            "links": links[:10],
            "drivers": drivers[:6],
        }

    def run(self) -> Dict[str, Any]:
        print(f"\n{C.BLD}{C.R}{'═'*60}")
        print(f"  🧠 LEAK INTELLIGENCE ENGINE (STRICT) {Config.aggr_tag()}")
        print(f"{'═'*60}{C.RST}\n")

        if self.targets_rejected:
            print(f"  {C.Y}⚠ Targets rifiutati (solo email o domini ammessi):{C.RST}")
            for r in self.targets_rejected[:10]:
                print(f"    • {r}")
            if len(self.targets_rejected) > 10:
                print(f"    • ... +{len(self.targets_rejected)-10} altri")
            print("")

        if not self.targets_valid:
            report = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "mode": "AGGRESSIVE" if Config.aggressive_mode else "SAFE",
                "targets": [],
                "summary": {
                    "total_targets": 0,
                    "max_score": 0,
                    "top_target": None,
                },
                "sha256": hashlib.sha256(b"{}").hexdigest()
            }
            lines = [
                "Nessun target valido.",
                "Modalità Enterprise STRICT: inserisci solo email complete o domini (es. esempio.com)."
            ]
            print(f"\n{box('🧠 LEAK INTELLIGENCE REPORT', lines, C.Y)}")
            return report

        recon = DataLeakRecon(self.targets_valid, deep=True)
        raw = recon.run()

        intel_targets = []
        max_score = 0
        top = None

        for t in raw.get("targets", []) if isinstance(raw, dict) else []:
            if not isinstance(t, dict):
                continue
            target = t.get("target", "")
            ttype = t.get("type", "unknown")
            findings = t.get("findings", []) if isinstance(t.get("findings", []), list) else []

            scored = self._score_from_findings(findings)

            s = scored["score"]
            if s >= 70:
                level = "HIGH"
            elif s >= 40:
                level = "MEDIUM"
            elif s >= 15:
                level = "LOW"
            else:
                level = "NONE"

            entry = {
                "target": target,
                "type": ttype,
                "leak_score": s,
                "risk_level": level,
                "confidence": scored["confidence"],
                "counts": {
                    "leak_like_hits": scored["leak_cnt"],
                    "exposure_mentions": scored["exposure_cnt"],
                    "signals": scored["signal_cnt"],
                },
                "drivers": scored["drivers"],
                "sources": scored["sources"],
                "links": scored.get("links", []),
                "findings": findings,  # raw findings for evidence
            }
            intel_targets.append(entry)

            if s > max_score:
                max_score = s
                top = entry

        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mode": "AGGRESSIVE" if Config.aggressive_mode else "SAFE",
            "targets": intel_targets,
            "summary": {
                "total_targets": len(intel_targets),
                "max_score": max_score,
                "top_target": {"target": top.get("target"), "risk_level": top.get("risk_level"), "score": top.get("leak_score")} if isinstance(top, dict) else None,
            }
        }

        try:
            payload = json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8")
            report["sha256"] = hashlib.sha256(payload).hexdigest()
        except Exception:
            report["sha256"] = None

        self._print_report(report)
        return report

    def _print_report(self, report: Dict[str, Any]):
        lines = []
        summ = report.get("summary", {}) if isinstance(report, dict) else {}
        lines.append(f"Targets analizzati:   {summ.get('total_targets', 0)}")
        lines.append(f"Max Leak Score:      {summ.get('max_score', 0)}/100")
        top = summ.get("top_target")
        if isinstance(top, dict) and top.get("target"):
            lines.append(f"Top target:          {top.get('target')} ({top.get('risk_level')}, {top.get('score')}/100)")
        lines.append("")
        lines.append(f"{C.BLD}Dettaglio per target:{C.RST}")

        for t in report.get("targets", []) if isinstance(report, dict) else []:
            if not isinstance(t, dict):
                continue
            name = t.get("target")
            ttype = t.get("type")
            score = t.get("leak_score", 0)
            level = t.get("risk_level", "NONE")
            conf = t.get("confidence", "LOW")

            color = C.R if score >= 70 else (C.Y if score >= 40 else (C.G if score >= 15 else C.DIM))
            lines.append(f"  {C.Y}{name}{C.RST} ({ttype})")
            lines.append(f"    Score: {color}{score}/100{C.RST} | Level: {color}{level}{C.RST} | Confidence: {conf}")
            counts = t.get("counts", {})
            if isinstance(counts, dict):
                lines.append(f"    Counts: leak={counts.get('leak_like_hits',0)}, exposure={counts.get('exposure_mentions',0)}, signals={counts.get('signals',0)}")
            drivers = t.get("drivers", [])
            if drivers:
                for d in drivers[:3]:
                    lines.append(f"    - {d}")
            links = t.get("links", [])
            if isinstance(links, list) and len(links) > 0:
                lines.append(f"    {C.BLD}🔗 Links (verify):{C.RST}")
                for u in links[:8]:
                    if isinstance(u, str) and u.startswith("http"):
                        lines.append(f"      • {u}")

        sha = report.get("sha256")
        if sha:
            lines.append("")
            lines.append(f"SHA-256 report: {sha}")

        lines.append("")
        lines.append(f"{C.BLD}Next steps (safe):{C.RST}")
        lines.append("  • Se score ≥ 40: verifica asset, forzare reset credenziali, MFA, monitoraggio.")
        lines.append("  • Usa target specifici (email completa o dominio) per ridurre rumore.")
        lines.append("  • Usa modulo Evidence per congelare report/hashes su caso autorizzato.")

        box_color = C.R if summ.get("max_score", 0) >= 70 else (C.Y if summ.get("max_score", 0) >= 40 else C.G)
        print(f"\n{box('🧠 LEAK INTELLIGENCE REPORT', lines, box_color)}")
class IncidentIntelEngine:
    """
    📰 INCIDENT INTELLIGENCE (MODE)
    Obiettivo: generare pivot OSINT *mirati* per verificare incidenti (ransomware/leak/breach),
    riducendo falsi positivi dovuti a siti che parlano spesso di ransomware (es. portali cyber).

    ⚠ Nota:
    - Questa sezione NON "conferma" incidenti: genera query e link per verifica manuale.
    - Per evitare risultati fuorvianti, le query "incident" escludono il sito target ( -site:target ).
    """

    # Fonti “pivot” (lookup manuale)
    RANSOMWARE_TRACKERS = [
        # tracker / aggregator
        ("ransomware.live", "site:ransomware.live"),
        ("ransomlook.io", "site:ransomlook.io"),
        ("ransomwatch", "site:ransomwatch.telemetry.ltd"),  # spesso usato come mirror/dominio variabile
    ]

    # Siti “news cyber” dove filtrare a dovere (solo se serve)
    CYBER_NEWS_SITES = [
        "bleepingcomputer.com",
        "therecord.media",
        "securityweek.com",
        "helpnetsecurity.com",
        "thehackernews.com",
        "wired.it",
        "corriere.it",
        "repubblica.it",
        "ansa.it",
    ]

    # Keyword italiane + inglesi (incidenti)
    INCIDENT_KW = [
        "ransomware", "data breach", "breach", "leak site", "extortion", "stolen data",
        "compromised", "intrusion", "hack", "attacco informatico", "attacco ransomware",
        "esfiltrazione", "furto dati", "violazione dati", "data leak",
    ]

    def __init__(self, aggressive_mode: bool = False):
        self.aggressive_mode = aggressive_mode

    @staticmethod
    def _is_email(s: str) -> bool:
        s = (s or "").strip()
        # reject things like "@domain.tld" without local-part
        if s.startswith("@"):
            return False
        return bool(re.match(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$", s))

    @staticmethod
    def _is_domain(s: str) -> bool:
        s = (s or "").strip().lower()
        if "://" in s or "/" in s:
            return False
        if "@" in s:
            return False
        # basic domain pattern (no wildcards)
        return bool(re.match(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", s))

    @staticmethod
    def _quote(s: str) -> str:
        # use quotes for exact match in engines
        return f"\"{s}\""

    def _mk_search(self, engine: str, q: str) -> str:
        q_enc = urllib.parse.quote(q, safe="")
        if engine == "google":
            return f"https://www.google.com/search?q={q_enc}"
        if engine == "bing":
            return f"https://www.bing.com/search?q={q_enc}"
        return f"https://duckduckgo.com/?q={q_enc}"

    def _incident_queries(self, target: str) -> list[str]:
        """
        Query “seria”: cerca articoli/menzioni che parlano di *incidenti che riguardano il target*.
        Regola chiave anti-fuorviante: esclude il sito target dai risultati.
        """
        t = target.strip().lower()
        tq = self._quote(target) if self._is_domain(t) else self._quote(target)

        # Escludi risultati ospitati sul dominio target (se target è dominio)
        exclude = f" -site:{t}" if self._is_domain(t) else ""

        # Query compatte ma forti
        q1 = f'{tq} (ransomware OR "data breach" OR breach OR "leak site" OR extortion OR "stolen data"){exclude}'
        q2 = f'{tq} ("attacco informatico" OR "attacco ransomware" OR "furto dati" OR "violazione dati" OR esfiltrazione){exclude}'
        q3 = f'{tq} (infostealer OR stealer OR credentials OR password OR "credential theft"){exclude}'
        return [q1, q2, q3]

    def _focused_news_queries(self, target: str) -> list[str]:
        """
        Query su siti specifici (news/cyber) – *sempre* con -site:target per non prendere articoli del target stesso.
        """
        t = target.strip().lower()
        exclude = f" -site:{t}" if self._is_domain(t) else ""
        tq = self._quote(target)

        # Niente lista infinita: scegliamo 5-6 siti max per tenere rumore basso
        sites = self.CYBER_NEWS_SITES[:6] if not self.aggressive_mode else self.CYBER_NEWS_SITES

        qs = []
        for s in sites:
            qs.append(f'site:{s} {tq} (ransomware OR breach OR "data breach" OR leak OR extortion OR "furto dati"){exclude}')
        return qs

    def _tracker_queries(self, target: str) -> list[str]:
        tq = self._quote(target)
        qs = []
        for _, siteq in self.RANSOMWARE_TRACKERS:
            qs.append(f'{siteq} {tq}')
        return qs

    def _code_leak_queries(self, target: str) -> list[str]:
        tq = self._quote(target)
        return [
            f'site:github.com {tq} (password OR passwd OR pwd OR creds OR "api key" OR secret OR leak OR stealer)',
            f'site:pastebin.com {tq}',
        ]

    def run(self, targets: list[str]) -> dict:
        """
        Stampa pivot e restituisce struttura dati, senza eseguire scraping.
        """
        out = {"targets": []}

        header_mode = "AGGR ENTERPRISE" if self.aggressive_mode else "SAFE"
        print("═" * 60)
        print(f"  📰 INCIDENT INTEL (MODE) [{header_mode}]")
        print("═" * 60)

        for raw in targets:
            t = (raw or "").strip()
            if not t:
                continue

            # accetta email o dominio (in linea con modalità STRICT)
            if not (self._is_email(t) or self._is_domain(t)):
                print(f"\n  ⚠ Target ignorato (solo email o dominio): {t}")
                continue

            # per email: usa sia email completa che dominio come pivot
            pivots = [t]
            if self._is_email(t):
                dom = t.split("@", 1)[-1].lower()
                if dom and dom not in pivots:
                    pivots.append(dom)

            target_block = {"input": t, "pivots": []}
            print(f"\n  Target: {t}")
            print("  🔗 Links (verify):")

            for pivot in pivots:
                pivot_block = {"pivot": pivot, "links": {"incident": [], "news": [], "trackers": [], "code_leaks": []}}

                # 1) query incident “serie”
                for q in self._incident_queries(pivot):
                    for eng in ("google", "bing", "ddg"):
                        url = self._mk_search(eng, q)
                        pivot_block["links"]["incident"].append(url)

                # 2) query su siti cyber/news (riduce rumore rispetto a query generiche)
                for q in self._focused_news_queries(pivot):
                    # basta google: sulle query site: è spesso sufficiente e riduce output
                    url = self._mk_search("google", q)
                    pivot_block["links"]["news"].append(url)

                # 3) tracker ransomware
                for q in self._tracker_queries(pivot):
                    url = self._mk_search("google", q)
                    pivot_block["links"]["trackers"].append(url)

                # 4) code/paste leak pivots
                for q in self._code_leak_queries(pivot):
                    for eng in ("google", "bing"):
                        url = self._mk_search(eng, q)
                        pivot_block["links"]["code_leaks"].append(url)

                # stampa: compatto (no pareti infinite)
                def _print_group(title: str, urls: list[str], maxn: int):
                    if not urls:
                        return
                    print(f"    • {title}:")
                    for u in urls[:maxn]:
                        print(f"      - {u}")
                    if len(urls) > maxn:
                        print(f"      - ... (+{len(urls)-maxn})")

                max_inc = 6 if not self.aggressive_mode else 12
                max_news = 4 if not self.aggressive_mode else 8
                max_trk = 3 if not self.aggressive_mode else 6
                max_code = 4 if not self.aggressive_mode else 8

                _print_group(f"Incident mentions (exclude target site)", pivot_block["links"]["incident"], max_inc)
                _print_group(f"Cyber/news sites", pivot_block["links"]["news"], max_news)
                _print_group(f"Ransomware trackers", pivot_block["links"]["trackers"], max_trk)
                _print_group(f"Code/Paste leaks", pivot_block["links"]["code_leaks"], max_code)

                target_block["pivots"].append(pivot_block)

            out["targets"].append(target_block)

        # hash report (for evidence)
        try:
            h = hashlib.sha256(json.dumps(out, sort_keys=True).encode("utf-8")).hexdigest()
            out["sha256"] = h
        except Exception:
            out["sha256"] = None
        return out


class EvidenceCollector:
    def __init__(self):
        self.evidence = []
        self.case = None
    
    def set_case(self, case: CaseManagement):
        if isinstance(case, CaseManagement):
            self.case = case
    
    def add_evidence(self, evidence_type: str, data: Any, source: str = "", tags: List[str] = None):
        evidence_item = {
            "timestamp": datetime.now().isoformat(),
            "type": evidence_type,
            "data": data,
            "source": source,
            "tags": tags if isinstance(tags, list) else []
        }
        
        self.evidence.append(evidence_item)
        
        if self.case:
            self.case.add_evidence(evidence_type, data)
    
    def get_summary(self) -> Dict:
        types_count = {}
        for ev in self.evidence:
            ev_type = ev.get("type", "unknown")
            types_count[ev_type] = types_count.get(ev_type, 0) + 1
        
        return {
            "total": len(self.evidence),
            "types": types_count,
            "last_updated": datetime.now().isoformat()
        }
    
    def export(self, format: str = "json") -> str:
        if format == "json":
            return json.dumps(self.evidence, indent=2, default=str)
        elif format == "text":
            lines = ["EVIDENCE COLLECTION", "="*50]
            for ev in self.evidence:
                lines.append(f"\n[{ev.get('timestamp', 'N/A')}] {ev.get('type', 'Unknown')}")
                lines.append(f"Source: {ev.get('source', 'N/A')}")
                lines.append(f"Data: {json.dumps(ev.get('data', {}), default=str)[:200]}")
            return "\n".join(lines)
        else:
            return ""


# ==================== MODULO 10 - PASSWORD BREACH CHECK ====================


# ==================== MODULO 10 - PASSWORD BREACH CHECK ====================

class PasswordBreachCheck:
    @staticmethod
    def check_password(password: str):
        if not isinstance(password, str):
            return {"error": "Invalid password", "type": "password"}
            
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        print(f"\n{C.BLD}{C.Y}{'═'*60}")
        print(f"  🔐 PASSWORD BREACH CHECK {Config.aggr_tag()}")
        print(f"{'═'*60}{C.RST}\n")

        status("🔑", f"Password hash: {sha1[:10]}...{sha1[-6:]}")
        status("📡", f"Querying HIBP range {prefix}...")

        try:
            resp = http.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10)

            if resp["ok"] and isinstance(resp["body"], str):
                found = False
                for line in resp["body"].splitlines():
                    if line.startswith(suffix):
                        parts = line.split(':')
                        count = int(parts[1]) if len(parts) > 1 else 0
                        found = True
                        print(f"\n  {C.BG_R}{C.BLD}⚠️  PASSWORD COMPROMESSA ⚠️{C.RST}")
                        print(f"\n  {C.R}Password trovata in {count:,} breach!{C.RST}")
                        print(f"  {C.DIM}Non usare mai questa password.{C.RST}")
                        print(f"  {C.Y}Fonte: Have I Been Pwned (HIBP){C.RST}")

                        return {
                            "breached": True,
                            "count": count,
                            "hash": sha1,
                            "source": "HIBP",
                            "type": "password",
                            "message": f"Password appears {count:,} times"
                        }

                if not found:
                    print(f"\n  {C.BG_G}{C.BLD}✅ PASSWORD SICURA ✅{C.RST}")
                    print(f"\n  {C.G}Password non trovata in alcun breach.{C.RST}")
                    print(f"  {C.DIM}Fonte: Have I Been Pwned (HIBP){C.RST}")

                    return {
                        "breached": False,
                        "hash": sha1,
                        "source": "HIBP",
                        "type": "password",
                        "message": "Password not found"
                    }
            else:
                status("✗", "HIBP check failed", C.R)
                return {"error": "HIBP check failed", "type": "password"}
        except Exception as e:
            status("✗", f"Errore HIBP: {str(e)}", C.R)
            return {"error": str(e), "type": "password"}

    @staticmethod
    def check_hash(hash_value: str):
        if not isinstance(hash_value, str):
            return {"error": "Invalid hash", "type": "hash"}
            
        hash_value = hash_value.upper().strip()

        print(f"\n{C.BLD}{C.Y}{'═'*60}")
        print(f"  🔐 HASH BREACH CHECK {Config.aggr_tag()}")
        print(f"{'═'*60}{C.RST}\n")

        if not re.match(r'^[A-F0-9]{40}$', hash_value):
            status("✗", f"Formato hash non valido: {hash_value[:20]}", C.R)
            print(f"\n  {C.Y}Formato SHA1 valido: 40 caratteri esadecimali (0-9, A-F){C.RST}")
            print(f"  {C.DIM}Esempio: 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8{C.RST}")
            return {
                "error": "Invalid hash format",
                "type": "hash",
                "valid_format": False
            }

        prefix = hash_value[:5]
        suffix = hash_value[5:]

        status("🔑", f"Hash: {hash_value[:10]}...{hash_value[-6:]}")
        status("📡", f"Querying HIBP range {prefix}...")

        try:
            resp = http.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10)

            if resp["ok"] and isinstance(resp["body"], str):
                found = False
                for line in resp["body"].splitlines():
                    if line.startswith(suffix):
                        parts = line.split(':')
                        count = int(parts[1]) if len(parts) > 1 else 0
                        found = True
                        print(f"\n  {C.BG_R}{C.BLD}⚠️  HASH COMPROMESSO ⚠️{C.RST}")
                        print(f"\n  {C.R}Hash presente in {count:,} breach!{C.RST}")
                        print(f"  {C.Y}Fonte: Have I Been Pwned (HIBP){C.RST}")

                        return {
                            "breached": True,
                            "count": count,
                            "hash": hash_value,
                            "source": "HIBP",
                            "type": "hash",
                            "message": f"Hash appears {count:,} times"
                        }

                if not found:
                    print(f"\n  {C.BG_G}{C.BLD}✅ HASH NON TROVATO ✅{C.RST}")
                    print(f"\n  {C.G}Hash non presente nei database HIBP.{C.RST}")
                    print(f"  {C.DIM}Fonte: Have I Been Pwned (HIBP){C.RST}")

                    return {
                        "breached": False,
                        "hash": hash_value,
                        "source": "HIBP",
                        "type": "hash",
                        "message": "Hash not found"
                    }
            else:
                status("✗", "HIBP check failed", C.R)
                return {"error": "HIBP check failed", "type": "hash"}
        except Exception as e:
            status("✗", f"Errore HIBP: {str(e)}", C.R)
            return {"error": str(e), "type": "hash"}


# ==================== MODULO 11 - MY IP ====================

class MyIP:
    def __init__(self):
        self.results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "public_ip": None,
            "ip_info": None
        }

    def detect(self):
        status("🌍", "Rilevamento IP pubblico...", C.CY)

        try:
            data = http.json_get("https://api.ipify.org?format=json", timeout=5)

            if not (data and isinstance(data, dict)):
                status("✗", "Impossibile rilevare IP pubblico", C.R)
                return self.results

            my_ip = data.get("ip")
            if not (my_ip and isinstance(my_ip, str)):
                status("✗", "Formato IP non valido", C.R)
                return self.results

            my_ip = my_ip.strip()

            try:
                import ipaddress
                ipaddress.ip_address(my_ip)
            except Exception:
                status("✗", f"Formato IP non valido: {my_ip}", C.R)
                return self.results

            self.results["public_ip"] = my_ip
            print(f"\n  {C.G}Il tuo IP pubblico: {C.BLD}{my_ip}{C.RST}")

            ask = input(f"\n  {C.Y}Eseguire IP Intelligence? (y/n){C.RST} ⟫ ").strip().lower()

            if ask in ("y", "yes", "s", "si"):
                intel = IPIntel(my_ip)
                ip_results = intel.run_all()
                self.results["ip_info"] = ip_results if isinstance(ip_results, dict) else {"error": "IPIntel returned non-dict"}
            else:
                status("○", "Analisi IP saltata", C.DIM)

            return self.results

        except Exception as e:
            status("✗", f"Errore rilevamento IP: {str(e)}", C.R)
            return self.results


# ==================== WHOIS RAPIDO ====================

def whois_quick_lookup(app_instance, domain: str):
    """WHOIS lookup rapido con RDAP - funzione helper"""
    print(f"\n{C.BLD}{C.M}{'═'*60}")
    print(f"  🔍 WHOIS RAPIDO (RDAP) {Config.aggr_tag()}")
    print(f"{'═'*60}{C.RST}\n")
    
    if not domain:
        status("✗", "Nessun dominio inserito", C.R)
        return
    
    import re
    domain = re.sub(r'^https?://', '', domain.lower())
    domain = domain.split('/')[0]
    domain = domain.split(':')[0]
    
    if not re.match(r'^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$', domain):
        status("✗", f"Dominio non valido: {domain}", C.R)
        return
    
    status("🔄", f"Ricerca WHOIS per {domain}...", C.CY)
    
    result = rdap_domain_lookup(domain)
    
    if result.get("status") != "success":
        status("✗", f"RDAP lookup fallito: {result.get('error', 'Errore sconosciuto')}", C.R)
        return
    
    lines = [
        f"Domain:      {result.get('domain', domain)}",
        f"Registrar:   {result.get('registrar', 'N/A')}",
        f"Created:     {result.get('creation_date', 'N/A')}",
        f"Expires:     {result.get('expiration_date', 'N/A')}",
        f"Updated:     {result.get('updated_date', 'N/A')}",
        f"DNSSEC:      {'✓ Yes' if result.get('dnssec') else '✗ No'}",
        f"Status:      {', '.join(result.get('status_codes', [])[:3])}",
        "",
        f"Name Servers:"
    ]
    
    ns_list = result.get('nameservers', [])
    if ns_list:
        for ns in ns_list[:5]:
            lines.append(f"  • {ns}")
        if len(ns_list) > 5:
            lines.append(f"  ... e {len(ns_list)-5} altri")
    else:
        lines.append("  • Nessun nameserver trovato")
    
    print(f"\n{box(f'🔍 WHOIS RDAP {Config.aggr_tag()}', lines, C.M)}")
    
    session_id = f"whois_{domain}_{datetime.now().strftime('%H%M%S')}"
    app_instance.session_results[session_id] = {
        "type": "whois",
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "data": result
    }
    status("💾", f"Risultato salvato in sessione [ID: {session_id}]", C.G)
    
    app_instance.case.set_target("domain", domain)
    app_instance.evidence.add_evidence("whois_lookup", 
                                       {"domain": domain, "registrar": result.get('registrar')},
                                       source="WhoisQuick")


# ==================== REPORT GENERATOR ====================

class ReportGenerator:
    @staticmethod
    def save_json(data: dict, filename: str = None, redact: bool = None):
        if redact is None:
            redact = Config.redact_reports

        if not isinstance(data, dict):
            data = {"error": "Invalid data"}

        if not filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            mode = "redacted" if redact else "full"
            filename = f"ghost_recon_{mode}_{ts}.json"

        output_data = Redactor.dict(data, redact) if redact else data

        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False, default=str)
            status("💾", f"JSON report saved: {filename}", C.G)
            if redact:
                status("🔒", "PII redacted - GDPR compliant", C.CY)
        except Exception as e:
            status("✗", f"Error saving JSON: {str(e)}", C.R)

        return filename

    @staticmethod
    def save_html(data: dict, filename: str = None, redact: bool = None):
        if redact is None:
            redact = Config.redact_reports

        if not isinstance(data, dict):
            data = {"error": "Invalid data"}

        if not filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            mode = "redacted" if redact else "full"
            filename = f"ghost_recon_{mode}_{ts}.html"

        output_data = Redactor.dict(data, redact) if redact else data

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>👻 Ghost Recon - OSINT Report {'(Redacted)' if redact else ''}</title>
<style>
  :root {{
    --bg: #0a0a1a;
    --card: #12122a;
    --border: #1e1e3e;
    --text: #e0e0e0;
    --accent: #00d4ff;
    --green: #00ff88;
    --red: #ff4444;
    --yellow: #ffaa00;
    --purple: #aa44ff;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 2rem;
  }}
  .container {{ max-width: 1400px; margin: 0 auto; }}
  .header {{
    text-align: center;
    padding: 2rem;
    background: linear-gradient(135deg, #0a0a2e, #1a0a3e);
    border: 1px solid var(--border);
    border-radius: 12px;
    margin-bottom: 2rem;
  }}
  .header h1 {{ color: var(--accent); }}
  .breach {{ 
    background: rgba(255,68,68,0.1);
    border-left: 4px solid var(--red);
    padding: 1rem;
    margin: 0.5rem 0;
  }}
  .source {{ color: var(--yellow); font-weight: bold; }}
  pre {{
    background: #080818;
    padding: 1rem;
    border-radius: 8px;
    overflow-x: auto;
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>👻 Ghost Recon v3.1</h1>
    <p>Enterprise OSINT Framework - {'Redacted Report' if redact else 'Full Report'}</p>
    <p style="color: #666;">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    { '<p style="color: #00ff88;">🔒 PII Redacted - GDPR Compliant</p>' if redact else '' }
  </div>

  <pre>{html_module.escape(json.dumps(output_data, indent=2, default=str, ensure_ascii=False))}</pre>

  <div style="text-align: center; padding: 2rem; color: #444;">
    <p>Ghost Recon Enterprise v3.1 — Educational purposes only</p>
    <p>TLS Verified | Breach Intelligence | PII Protection</p>
  </div>
</div>
</body>
</html>"""

        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(html_content)
            status("💾", f"HTML report saved: {filename}", C.G)
        except Exception as e:
            status("✗", f"Error saving HTML: {str(e)}", C.R)

        return filename

    @staticmethod
    def save_encrypted(data: dict, password: str, filename: str = None):
        if not isinstance(data, dict):
            data = {"error": "Invalid data"}
            
        if not isinstance(password, str) or not password:
            status("✗", "Password non valida", C.R)
            return None
            
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import hashes, padding
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.backends import default_backend
            import secrets
        except ImportError as e:
            status("❌", f"Errore import cryptography: {e}", C.R)
            status("💡", "Installa con: pip install cryptography", C.Y)
            return None

        if not filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ghost_recon_encrypted_{ts}.ghost"

        json_data = json.dumps(data, indent=2, default=str, ensure_ascii=False).encode('utf-8')
        
        salt = secrets.token_bytes(16)
        iv = secrets.token_bytes(12)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(json_data) + padder.finalize()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        tag = encryptor.tag
        
        encrypted_package = salt + iv + tag + ciphertext
        
        try:
            with open(filename, 'wb') as f:
                f.write(encrypted_package)
        except Exception as e:
            status("✗", f"Errore salvataggio file: {str(e)}", C.R)
            return None
        
        info_filename = filename + ".info"
        try:
            with open(info_filename, 'w', encoding='utf-8') as f:
                f.write(f"""╔════════════════════════════════════════════════════════════╗
║           👻 GHOST RECON - REPORT CIFRATO              ║
╚════════════════════════════════════════════════════════════╝

File: {filename}
Algoritmo: AES-256-GCM
KDF: PBKDF2-HMAC-SHA256 (100,000 iterazioni)
Salt: 16 byte
IV: 12 byte
Tag: 16 byte (autenticazione)

PER DECIFRARE:

python ghostrecon.py --decrypt {filename} "tua_password"
""")
        except:
            pass
        
        status("🔐", f"Report cifrato AES-256-GCM salvato: {filename}", C.M)
        status("ℹ️", f"Istruzioni decifratura: {info_filename}", C.CY)
        return filename

    @staticmethod
    def decrypt_report(filename: str, password: str):
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import hashes, padding
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.backends import default_backend
        except ImportError as e:
            print(f"❌ Errore import cryptography: {e}")
            print("   Installa con: pip install cryptography")
            return None
        
        try:
            with open(filename, 'rb') as f:
                data = f.read()
            
            if len(data) < 44:
                print("❌ File corrotto o non valido")
                return None
                
            salt = data[:16]
            iv = data[16:28]
            tag = data[28:44]
            ciphertext = data[44:]
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode('utf-8'))
            
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            json_data = unpadder.update(padded) + unpadder.finalize()
            
            return json.loads(json_data.decode('utf-8'))
            
        except Exception as e:
            print(f"❌ Errore decifratura: {e}")
            print("   Password errata o file danneggiato")
            return None


# ==================== MAIN GHOST RECON APP ====================

class GhostRecon:
    def __init__(self):
        self.session_results = {}
        self.aggressive_mode = bool(getattr(Config, 'aggressive_mode', False))
        self.session_start = datetime.now()
        self.case = CaseManagement()
        self.evidence = EvidenceCollector()
        self.evidence.set_case(self.case)
        self.reporter = ReportGenerator

    def run(self):
        os.system("cls" if os.name == "nt" else "clear")
        print(BANNER)

        print(f"  {C.CY}🔒 Security Status:{C.RST}")
        print(f"  {C.G}✓{C.RST} TLS Verification: {C.G}ENABLED{C.RST} (default)")
        print(f"  {C.G}✓{C.RST} PII Redaction: {C.G}{'ENABLED' if Config.redact_reports else 'DISABLED'}{C.RST}")
        print(f"  {C.Y}⚠{C.RST} Aggressive Mode: {C.Y}{'ENABLED' if Config.aggressive_mode else 'DISABLED'}{C.RST}")
        
        try:
            import cryptography
            crypto_status = f"{C.G}✓ INSTALLED{C.RST}"
        except ImportError:
            crypto_status = f"{C.R}✗ NOT INSTALLED{C.RST} (pip install cryptography)"
        print()

        while True:
            self._show_menu()
            choice = input(f"\n  {C.CY}ghost{C.W}@{C.M}recon{C.RST} ⟫ ").strip()

            if choice == "1":
                self._case_management_menu()

            elif choice == "2":
                domain = input(f"  {C.Y}Domain{C.RST} ⟫ ").strip()
                if domain:
                    self.case.set_target("domain", domain)
                    intel = DomainIntel(domain)
                    results = intel.run_all()
                    self.session_results[f"domain_{domain}"] = results
                    
                    if results.get("tls_score", 0) < 50:
                        self.evidence.add_evidence("weak_tls", 
                                                  {"domain": domain, "score": results.get("tls_score")},
                                                  source="DomainIntel")
                    if results.get("domain_breaches"):
                        self.evidence.add_evidence("domain_breach", 
                                                  {"domain": domain, "breaches": results.get("domain_breaches")},
                                                  source="DomainIntel")

            elif choice == "3":
                email = input(f"  {C.Y}Email{C.RST} ⟫ ").strip()
                if email:
                    self.case.set_target("email", email)
                    osint = EmailOSINT(email)
                    results = osint.run_all()
                    self.session_results[f"email_{email}"] = results
                    
                    if results.get("exposure", {}).get("confirmed"):
                        self.evidence.add_evidence("email_breach", 
                                                  {"email": email, "summary": results.get("breach_summary")},
                                                  source="EmailOSINT")
                    if results.get("presence", {}).get("web_mentions", 0) > 0:
                        self.evidence.add_evidence("web_presence", 
                                                  {"email": email, "mentions": results.get("presence", {}).get("web_mentions")},
                                                  source="EmailOSINT")

            elif choice == "4":
                phone = input(f"  {C.Y}Phone (+country code){C.RST} ⟫ ").strip()
                if phone:
                    self.case.set_target("phone", phone)
                    checker = PhoneBreachCheck(phone)
                    results = checker.run_all()
                    self.session_results[f"phone_{phone}"] = results
                    
                    if results.get("summary", {}).get("count", 0) > 0:
                        self.evidence.add_evidence("phone_leak", 
                                                  {"phone": phone, "summary": results.get("summary")},
                                                  source="PhoneBreachCheck")

            elif choice == "5":
                username = input(f"  {C.Y}Username{C.RST} ⟫ ").strip()
                if username:
                    self.case.set_target("username", username)
                    hunter = UsernameHunter(username)
                    results = hunter.hunt()
                    self.session_results[f"user_{username}"] = results
                    
                    if results.get("breaches"):
                        self.evidence.add_evidence("username_breach", 
                                                  {"username": username, "breaches": results.get("breaches")},
                                                  source="UsernameHunter")
                    if results.get("stats", {}).get("found", 0) > 5:
                        self.evidence.add_evidence("high_exposure", 
                                                  {"username": username, "profiles": results.get("stats", {}).get("found")},
                                                  source="UsernameHunter")

            elif choice == "6":
                ip = input(f"  {C.Y}IP Address{C.RST} ⟫ ").strip()
                if ip:
                    self.case.set_target("ip", ip)
                    intel = IPIntel(ip)
                    results = intel.run_all()
                    self.session_results[f"ip_{ip}"] = results
                    
                    rep = results.get("reputation", {})
                    if rep.get("blacklisted"):
                        self.evidence.add_evidence("blacklisted_ip", 
                                                  {"ip": ip, "lists": rep.get("lists")},
                                                  source="IPIntel")
                    if results.get("shodan", {}).get("vulns"):
                        self.evidence.add_evidence("vulnerable_ip", 
                                                  {"ip": ip, "vulns": results.get("shodan", {}).get("vulns")},
                                                  source="IPIntel")

            elif choice == "7":
                print(f"\n  {C.Y}Inserisci target (uno per riga, riga vuota per finire):{C.RST}")
                targets = []
                while True:
                    t = input(f"  {C.CY}⟫{C.RST} ").strip()
                    if not t:
                        break
                    targets.append(t)
                
                if targets:
                    recon = DataLeakRecon(targets)
                    results = recon.run()
                    self.session_results[f"dataleak_{datetime.now().strftime('%H%M%S')}"] = results
                    
                    if results.get("summary", {}).get("leak_hits", 0) > 0:
                        self.evidence.add_evidence("data_leak", 
                                                  {"targets": targets, "summary": results.get("summary")},
                                                  source="DataLeakRecon")

            elif choice == "8":
                # Leak Intelligence Engine (noise-aware)
                targets = []
                print(f"\n  {C.DIM}Inserisci target (uno per riga, riga vuota per finire):{C.RST}")
                while True:
                    t = input("  ⟫ ").strip()
                    if not t:
                        break
                    targets.append(t)
                engine = LeakIntelligenceEngine(targets)
                results = engine.run()
                self.session_results[f"leakintel_{int(time.time())}"] = results

            elif choice == "9":
                self._evidence_menu()

            elif choice == "10":
                self._password_menu()

            elif choice == "11":
                my_ip_checker = MyIP()
                results = my_ip_checker.detect()

                if not results or not isinstance(results, dict):
                    status("✗", "Impossibile rilevare IP pubblico", C.R)
                    continue

                public_ip = results.get("public_ip")
                if not public_ip:
                    status("✗", "IP pubblico non disponibile nella risposta", C.R)
                    continue

                self.session_results[f"myip_{public_ip}"] = results
                self.case.set_target("ip", public_ip)

                ip_info = results.get("ip_info")
                if isinstance(ip_info, dict):
                    rep = ip_info.get("reputation", {})
                    if isinstance(rep, dict) and rep.get("blacklisted"):
                        self.evidence.add_evidence(
                            "blacklisted_ip",
                            {
                                "ip": public_ip,
                                "lists": rep.get("lists")
                            },
                            source="MyIP"
                        )

            elif choice == "w":
                domain = input(f"  {C.Y}Domain per WHOIS{C.RST} ⟫ ").strip()
                if domain:
                    whois_quick_lookup(self, domain)

            elif choice == "12":
                # Incident Intel (OSINT pivots) — domains/emails only
                targets = []
                print("\n  Inserisci target (uno per riga, riga vuota per finire):")
                while True:
                    line = input("  ⟫ ").strip()
                    if not line:
                        break
                    targets.append(line)

                if not targets:
                    self._warn("Nessun target inserito.")
                    continue

                # Strict validation: accept only domains or full emails to avoid noise/misuse
                rejected = []
                accepted = []
                for t in targets:
                    tt = t.strip()
                    is_email = ("@" in tt and "." in tt.split("@")[-1])
                    is_domain = bool(re.match(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$", tt))
                    if is_email or is_domain:
                        accepted.append(tt)
                    else:
                        rejected.append(tt)

                print("\n" + "═"*60)
                mode_label = "AGGR ENTERPRISE" if self.aggressive_mode else "SAFE"
                print(f"  📰 INCIDENT INTEL (PIVOTS) [{mode_label}]")
                print("═"*60 + "\n")

                if rejected:
                    print("  ⚠ Targets rifiutati (solo email complete o domini):")
                    for rj in rejected:
                        print(f"    • {rj}")
                    print()

                engine = IncidentIntelEngine(aggressive_mode=self.aggressive_mode)
                res = engine.run(accepted)

                # Compact printable output (no crash even if huge)
                for item in res.get("targets", []):
                    t = item.get("target", "")
                    piv = item.get("pivots", [])[:30]  # cap to keep terminal readable
                    print(f"  Target: {t}")
                    print("  🔗 Links (verify):")
                    for p in piv:
                        print(f"    • {p.get('url')}")
                    print()
            elif choice == "0":
                self._exit_with_report()

            elif choice == "a":
                new_mode = not Config.aggressive_mode
                Config.set_aggressive(new_mode)
                self.aggressive_mode = bool(new_mode)
                status("⚡", f"Modalità aggressiva: {'ATTIVA' if new_mode else 'DISATTIVA'}", C.Y if new_mode else C.G)


            elif choice in ("q", "quit", "exit"):
                self._exit_with_report()

            else:
                status("⚠", "Opzione non valida. Riprova.", C.Y)

    def _case_management_menu(self):
        while True:
            summary = self.case.get_summary()
            
            lines = [
                f"Case ID:     {summary.get('case_id', 'N/A')}",
                f"Created:     {summary.get('created_at', 'N/A')[:19]}",
                f"Last Update: {summary.get('updated_at', 'N/A')[:19]}",
                f"",
                f"{C.BLD}Targets:{C.RST}"
            ]
            
            targets = summary.get('targets', {})
            if targets:
                for k, v in targets.items():
                    lines.append(f"  {k}: {v}")
            else:
                lines.append("  Nessun target impostato")
            
            lines.extend([
                f"",
                f"{C.BLD}Notes:{C.RST} {summary.get('notes_count', 0)}",
                f"{C.BLD}Evidence:{C.RST} {summary.get('evidence_count', 0)}"
            ])
            
            print(f"\n{box('📁 CASE MANAGEMENT', lines, C.CY)}")
            
            print(f"\n  {C.G}[1]{C.RST} Imposta target")
            print(f"  {C.G}[2]{C.RST} Aggiungi nota")
            print(f"  {C.G}[3]{C.RST} Visualizza note")
            print(f"  {C.G}[4]{C.RST} Clear cache")
            print(f"  {C.R}[0]{C.RST} Torna al menu principale")
            
            choice = input(f"\n  {C.CY}⟫{C.RST} ").strip()
            
            if choice == "1":
                print(f"\n  {C.Y}Tipo target:{C.RST}")
                print(f"  [1] Domain")
                print(f"  [2] Email")
                print(f"  [3] Phone")
                print(f"  [4] Username")
                print(f"  [5] IP")
                
                t_choice = input(f"  {C.CY}⟫{C.RST} ").strip()
                target_type = {
                    "1": "domain", "2": "email", "3": "phone", "4": "username", "5": "ip"
                }.get(t_choice)
                
                if target_type:
                    value = input(f"  {C.Y}Valore:{C.RST} ").strip()
                    if value:
                        self.case.set_target(target_type, value)
                        status("✓", f"Target {target_type} impostato", C.G)
            
            elif choice == "2":
                note = input(f"  {C.Y}Nota:{C.RST} ").strip()
                if note:
                    self.case.add_note(note)
                    status("✓", "Nota aggiunta", C.G)
            
            elif choice == "3":
                notes = summary.get('notes', [])
                if notes:
                    print(f"\n  {C.BLD}NOTE:{C.RST}")
                    for i, note in enumerate(notes, 1):
                        if isinstance(note, dict):
                            print(f"  {C.CY}{i}.{C.RST} [{note.get('timestamp', '')[:19]}] {note.get('content', '')}")
                else:
                    status("○", "Nessuna nota", C.DIM)
            
            elif choice == "4":
                session_cache.clear()
                status("🧹", "Cache pulita", C.G)
            
            elif choice == "0":
                break

    def _evidence_menu(self):
        summary = self.evidence.get_summary()
        
        lines = [
            f"Total Evidence: {summary.get('total', 0)}",
            f"",
            f"{C.BLD}Tipi:{C.RST}"
        ]
        
        for ev_type, count in summary.get('types', {}).items():
            lines.append(f"  {ev_type}: {count}")
        
        print(f"\n{box('📋 EVIDENCE COLLECTION', lines, C.M)}")
        
        if summary.get('total', 0) > 0:
            print(f"\n  {C.G}[1]{C.RST} Esporta evidenze (JSON)")
            print(f"  {C.G}[2]{C.RST} Esporta evidenze (TEXT)")
            print(f"  {C.R}[0]{C.RST} Torna indietro")
            
            choice = input(f"\n  {C.CY}⟫{C.RST} ").strip()
            
            if choice == "1":
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"evidence_{ts}.json"
                try:
                    with open(filename, 'w') as f:
                        f.write(self.evidence.export("json"))
                    status("💾", f"Evidence salvate in {filename}", C.G)
                except Exception as e:
                    status("✗", f"Errore salvataggio: {str(e)}", C.R)
            
            elif choice == "2":
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"evidence_{ts}.txt"
                try:
                    with open(filename, 'w') as f:
                        f.write(self.evidence.export("text"))
                    status("💾", f"Evidence salvate in {filename}", C.G)
                except Exception as e:
                    status("✗", f"Errore salvataggio: {str(e)}", C.R)

    def _password_menu(self):
        print(f"\n  {C.BLD}{C.Y}🔐 VERIFICA BREACH PASSWORD/HASH{C.RST}")
        print(f"  {C.DIM}{'─'*40}{C.RST}")
        print(f"  {C.G}[1]{C.RST} Controlla password")
        print(f"  {C.G}[2]{C.RST} Controlla hash SHA1")
        print(f"  {C.R}[0]{C.RST} Annulla")
        print(f"  {C.DIM}{'─'*40}{C.RST}")

        sub = input(f"  {C.CY}⟫{C.RST} ").strip()

        if sub == "1":
            print(f"\n  {C.Y}Inserisci la password da verificare{C.RST}")
            print(f"  {C.DIM}(Non verrà mai inviata in chiaro - k-anonymity){C.RST}")
            pwd = input(f"  {C.CY}Password{C.RST} ⟫ ").strip()

            if not pwd:
                status("⚠", "Password non inserita", C.Y)
            elif len(pwd) < 4:
                status("⚠", "Password troppo corta (min 4 caratteri)", C.Y)
            else:
                pwd_hash = hashlib.md5(pwd.encode()).hexdigest()[:8]
                status("🔍", "Verifica in corso con HIBP...", C.CY)

                result = PasswordBreachCheck.check_password(pwd)

                if result and "error" not in result:
                    session_id = f"password_check_{pwd_hash}"
                    self.session_results[session_id] = result
                    status("💾", f"Risultato salvato in sessione [ID: {session_id}]", C.G)

                    if result.get("breached", False):
                        self.evidence.add_evidence("compromised_password", 
                                                  {"hash": pwd_hash, "count": result.get("count")},
                                                  source="PasswordCheck")

        elif sub == "2":
            print(f"\n  {C.Y}Inserisci hash SHA1 da verificare{C.RST}")
            print(f"  {C.DIM}(Formato: 40 caratteri esadecimali){C.RST}")
            print(f"  {C.DIM}Esempio: 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8{C.RST}")
            h = input(f"  {C.CY}Hash SHA1{C.RST} ⟫ ").strip().upper()

            if not h:
                status("⚠", "Hash non inserito", C.Y)
            elif not re.match(r'^[A-F0-9]{40}$', h):
                status("✗", "Formato hash non valido (richiesti 40 caratteri esadecimali)", C.R)
                print(f"  {C.DIM}Hai inserito: {h[:20]}... ({len(h)} caratteri){C.RST}")
            else:
                status("🔍", "Verifica in corso con HIBP...", C.CY)

                result = PasswordBreachCheck.check_hash(h)

                if result and "error" not in result:
                    session_id = f"hash_check_{h[:8]}"
                    self.session_results[session_id] = result
                    status("💾", f"Risultato salvato in sessione [ID: {session_id}]", C.G)

                    if result.get("breached", False):
                        self.evidence.add_evidence("compromised_hash", 
                                                  {"hash": h[:16], "count": result.get("count")},
                                                  source="HashCheck")

    def _exit_with_report(self):
        """Esce salvando automaticamente un report in chiaro (JSON + HTML), senza redazione e senza cifratura."""
        try:
            if self.session_results:
                self.reporter.save_json(self.session_results, redact=False)
                self.reporter.save_html(self.session_results, redact=False)
                status("✓", "Report salvato (chiaro): JSON + HTML", C.G)
            else:
                status("○", "Nessun risultato da salvare.", C.Y)
        except Exception as e:
            status("✗", f"Errore salvataggio report: {e}", C.R)
        print("\nArrivederci!\n")
        raise SystemExit(0)


    def _show_menu(self):
        print(f"\n  {C.CY}{C.BLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RST}")
        print(f"  {C.CY}  ██╗  ██╗ ██████╗ ███████╗████████╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗{C.RST}")
        print(f"  {C.CY}  ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║{C.RST}")
        print(f"  {C.CY}  ███████║██║   ██║███████╗   ██║       ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║{C.RST}")
        print(f"  {C.CY}  ██╔══██║██║   ██║╚════██║   ██║       ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║{C.RST}")
        print(f"  {C.CY}  ██║  ██║╚██████╔╝███████║   ██║       ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║{C.RST}")
        print(f"  {C.CY}  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝       ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝{C.RST}")
        print(f"  {C.CY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RST}\n")
        print(f"  {C.DIM}┌─────────────────────────────────────────────────────────────────────┐{C.RST}")
        print(f"  {C.DIM}│  {C.W}{C.BLD}MODULO                     DESCRIZIONE                              {C.DIM}│{C.RST}")
        print(f"  {C.DIM}├─────────────────────────────────────────────────────────────────────┤{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[1]{C.RST}  📁 Case Management      Gestione caso e target                {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[2]{C.RST}  🌐 Domain Intel         DNS, SSL, subdomains, TLS score      {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[3]{C.RST}  📧 Email OSINT          Breach DB, Presence, Exposure        {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[4]{C.RST}  📱 Phone Breach Check   Breach su numeri telefono            {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[5]{C.RST}  🎯 Username Hunter      50+ social platforms                  {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[6]{C.RST}  📍 IP Intelligence       Geolocation, ASN, Reputation        {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[7]{C.RST}  🔍 Data Leak Recon       Cerca leak multipli                  {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[8]{C.RST}  🧠 Leak Intelligence    Noise-aware + proof-ready      {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[9]{C.RST}  📋 Evidence             Raccolta evidenze                     {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[10]{C.RST} 🔐 Password/Hash Check  HIBP k-anonymity                      {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[11]{C.RST} 🕵️  My IP                Rileva IP pubblico + intel            {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[12]{C.RST} 📰 Incident Intel        Ransomware/Leak OSINT pivots           {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[0]{C.RST}  ❌ Exit                 Esci e genera report                  {C.DIM}│{C.RST}")
        print(f"  {C.DIM}├─────────────────────────────────────────────────────────────────────┤{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[w]{C.RST}  🔍 WHOIS Rapido         Lookup RDAP veloce                    {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[a]{C.RST}  ⚡ Aggressive Mode      {'ATTIVO' if Config.aggressive_mode else 'DISATTIVO'}                    {C.DIM}│{C.RST}")
        print(f"  {C.DIM}└─────────────────────────────────────────────────────────────────────┘{C.RST}")


# ==================== ENTRY POINT ====================

if __name__ == "__main__":
    try:
        app = GhostRecon()
        app.run()
    except KeyboardInterrupt:
        print(f"\n\n  {C.R}❌ Interruzione manuale{C.RST}")
        sys.exit(0)
    except Exception as e:
        print(f"\n  {C.R}❌ Errore critico: {e}{C.RST}")
        sys.exit(1)
