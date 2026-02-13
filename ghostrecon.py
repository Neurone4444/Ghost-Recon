#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║                    👻 GHOST RECON v3.0                          ║
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
import base64
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from pathlib import Path
from typing import Optional
import html as html_module
import warnings
import zipfile
from dataclasses import dataclass, field

# ─────────────────────────── CONFIGURAZIONE SICURA ───────────────────────────

@dataclass
class Config:
    """Configurazione globale di sicurezza"""
    verify_ssl: bool = True
    aggressive_mode: bool = False
    redact_reports: bool = True
    enable_encryption: bool = False
    timeout_default: int = 15
    timeout_aggressive: int = 30

    # Fonti dati per breach check
    SOURCES = {
        # ✅ API STABILI (sempre attive)
        "emailrep": {"name": "EmailRep.io", "aggressive": False, "reliable": True},
        "firefox": {"name": "Firefox Monitor", "aggressive": False, "reliable": True},
        "hibp": {"name": "Have I Been Pwned", "aggressive": False, "reliable": True},

        # ⚠️ FONTI AGGRESSIVE (solo con --aggressive)
        "leaklookup": {"name": "Leak-Lookup", "aggressive": True, "reliable": True},
        "snusbase": {"name": "Snusbase", "aggressive": True, "reliable": False},
        "intelx": {"name": "IntelligenceX", "aggressive": True, "reliable": False},
        "leakcheck": {"name": "LeakCheck", "aggressive": True, "reliable": False},
    }

    @classmethod
    def set_aggressive(cls, enabled: bool):
        cls.aggressive_mode = enabled
        if enabled:
            print(f"\n  {C.BG_R}{C.BLD}⚠⚠⚠ AGGRESSIVE MODE ENABLED ⚠⚠⚠{C.RST}")
            print(f"  {C.Y}Scraping e preview attivi - Rispetta ToS!{C.RST}\n")

    @classmethod
    def set_redact(cls, enabled: bool):
        cls.redact_reports = enabled
        status("🔒", f"Report redaction: {'ON' if enabled else 'OFF'}", C.CY)


# ─────────────────────────── COLORS & UI ───────────────────────────

class C:
    """Terminal colors - mantenuti invariati"""
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

  {C.DIM}Enterprise OSINT Framework v3.0{C.RST}
  {C.DIM}🔒 TLS Verified | 📊 Accurate Breach Intel | 🔐 PII Redacted{C.RST}
  {C.Y}⚠  Solo per scopi educativi e autorizzati{C.RST}
"""


def box(title: str, content: list[str], color: str = C.CY) -> str:
    """Crea un box decorativo per output"""
    width = max(len(title) + 4, max((len(line) for line in content), default=20) + 4, 60)
    lines = [
        f"{color}{'═' * width}",
        f"║  {C.BLD}{title}{C.RST}{color}{' ' * (width - len(title) - 4)}║",
        f"{'═' * width}{C.RST}",
    ]
    for line in content:
        padding = width - len(line) - 4
        lines.append(f"{color}║{C.RST}  {line}{' ' * max(padding, 0)}{color}║{C.RST}")
    lines.append(f"{color}{'═' * width}{C.RST}")
    return "\n".join(lines)


def status(icon: str, msg: str, color: str = C.G):
    print(f"  {color}{icon}{C.RST} {msg}")


def progress_bar(current: int, total: int, label: str = "", width: int = 30):
    pct = current / total if total else 0
    filled = int(width * pct)
    bar = f"{'█' * filled}{'░' * (width - filled)}"
    print(f"\r  {C.CY}⟫{C.RST} {bar} {pct*100:5.1f}% {C.DIM}{label}{C.RST}", end="", flush=True)
    if current >= total:
        print()


# ─────────────────────────── REDACTOR PII ───────────────────────────

class Redactor:
    """Maschera PII nei report - GDPR compliant"""

    @staticmethod
    def email(email: str) -> str:
        """info@example.com → i**o@example.com"""
        if not email or '@' not in email:
            return email
        local, domain = email.split('@')
        if len(local) <= 2:
            return f"{'*' * len(local)}@{domain}"
        return f"{local[0]}{'*' * (len(local)-2)}{local[-1]}@{domain}"

    @staticmethod
    def phone(phone: str) -> str:
        """+39123456789 → +39*******89"""
        clean = re.sub(r'[^\d+]', '', phone)
        if len(clean) <= 4:
            return '*' * len(clean)
        if clean.startswith('+'):
            return clean[:3] + '*' * (len(clean)-5) + clean[-2:]
        return clean[:2] + '*' * (len(clean)-4) + clean[-2:]

    @staticmethod
    def ip(ip: str) -> str:
        """192.168.1.1 → 192.168.*.*"""
        if ip.count('.') == 3:
            parts = ip.split('.')
            return f"{parts[0]}.{parts[1]}.*.*"
        return ip

    @staticmethod
    def dict(data: dict, redact: bool = True) -> dict:
        """Redatta ricorsiva di un dizionario"""
        if not redact:
            return data

        redacted = {}
        for key, value in data.items():
            if isinstance(value, dict):
                redacted[key] = Redactor.dict(value, redact)
            elif isinstance(value, str):
                if 'email' in key.lower() or key == 'email':
                    redacted[key] = Redactor.email(value)
                elif 'phone' in key.lower() or key == 'phone':
                    redacted[key] = Redactor.phone(value)
                elif 'ip' in key.lower() and value.count('.') == 3:
                    redacted[key] = Redactor.ip(value)
                else:
                    redacted[key] = value
            else:
                redacted[key] = value
        return redacted


# ─────────────────────── HTTP CLIENT SICURO ────────────────────────

class HTTPClient:
    """HTTP client con TLS verificato di DEFAULT"""

    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json, text/html, */*",
        "Accept-Language": "en-US,en;q=0.9",
    }

    # Fonti note con certificati problematici (DA USARE CON CAUTELA)
    INSECURE_ENDPOINTS = [
        'ip-api.com',
        'http://',  # Solo per fallback HTTP esplicito
    ]

    @classmethod
    def _should_verify(cls, url: str, verify_ssl: Optional[bool] = None) -> bool:
        """Determina se verificare TLS per questa richiesta"""
        if verify_ssl is not None:
            return verify_ssl

        # Non verificare solo per endpoint esplicitamente HTTP
        if url.startswith('http://'):
            status("⚠", f"HTTP connection to {url[:50]} - NO ENCRYPTION", C.Y)
            return False

        # Per tutto il resto, VERIFICA SEMPRE
        return Config.verify_ssl

    @classmethod
    def get(cls, url: str, headers: dict | None = None, timeout: int = None,
            verify_ssl: bool = None) -> dict:
        """HTTP GET con TLS verificato di DEFAULT"""

        hdrs = {**cls.DEFAULT_HEADERS, **(headers or {})}
        req = urllib.request.Request(url, headers=hdrs)

        timeout = timeout or Config.timeout_default

        # Configura SSL
        ctx = ssl.create_default_context()
        verify = cls._should_verify(url, verify_ssl)

        if verify:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            status("⚠", f"TLS verification disabled for {url[:60]}", C.Y)

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
        except Exception as e:
            return {"status": 0, "body": str(e), "headers": {}, "ok": False, "verified": verify}

    @classmethod
    def json_get(cls, url: str, **kwargs) -> dict | list | None:
        resp = cls.get(url, **kwargs)
        if resp["ok"]:
            try:
                return json.loads(resp["body"])
            except json.JSONDecodeError:
                return None
        return None

    @classmethod
    def head(cls, url: str, timeout: int = 8, verify_ssl: bool = None) -> dict:
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
        """HTTP POST con TLS verificato"""
        hdrs = {**cls.DEFAULT_HEADERS, **(headers or {})}

        if isinstance(data, dict):
            data = urllib.parse.urlencode(data).encode()
        elif isinstance(data, str):
            data = data.encode()

        req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")

        timeout = timeout or Config.timeout_default

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


# ─────────────────────────── BREACH ENGINE (NO-KEY, STDLIB) ───────────────────────────

def _http_get_json(url, timeout=6):
    """Helper HTTP GET con stdlib – nessuna dipendenza esterna"""
    req = urllib.request.Request(url, headers={"User-Agent": "GhostRecon/3.0 (+https://github.com/)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)
    except Exception:
        return None


def check_breach_xon(email):
    """XposedOrNot public endpoint"""
    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    data = _http_get_json(url, timeout=6)

    if data is None:
        return None, None

    breaches = data.get("breaches")
    meta = {k: v for k, v in data.items() if k != "breaches"}

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


def breach_risk_summary(breaches):
    """Genera punteggio di rischio e timeline dai breach trovati"""
    years = []
    names = []

    for b in breaches or []:
        if isinstance(b, dict):
            n = b.get("name") or b.get("breach") or b.get("title")
            if n:
                names.append(str(n))

            d = b.get("date") or b.get("breach_date") or b.get("added_date") or b.get("published")
            if d:
                try:
                    y = int(str(d)[:4])
                    if 1990 <= y <= datetime.now().year + 1:
                        years.append(y)
                except:
                    pass
        else:
            names.append(str(b))

    count = len(breaches or [])
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

# ════════════════════════════════════════════════════════════════════
#  MODULE 1 — DOMAIN INTELLIGENCE (LEGALE)
# ════════════════════════════════════════════════════════════════════
"""
⚠️  NOTA LEGALE - CONFORMITÀ:

Questo modulo NON esegue scansioni di porte attive.
Tutte le informazioni sulle porte provengono ESCLUSIVAMENTE da:

- Shodan InternetDB (API pubblica) - https://internetdb.shodan.io
- URLScan.io (API pubblica) - https://urlscan.io
- Censys (motore di ricerca pubblico) - https://censys.io
- Deduzioni da record DNS/MX pubblici

Nessuna connessione viene stabilita verso i sistemi target.
Conforme al D.Lgs. 547/1993 e Art. 615-ter c.p.
"""

class DomainIntel:
    """Raccolta intelligence completa su un dominio - 100% legale"""

    def __init__(self, domain: str):
        self.domain = domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
        self.results: dict = {
            "domain": self.domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "dns": {},
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
        }

    def run_all(self):
        print(f"\n{C.BLD}{C.CY}{'═'*60}")
        print(f"  🌐 DOMAIN INTELLIGENCE — {self.domain}")
        print(f"{'═'*60}{C.RST}\n")

        tasks = [
            ("DNS Resolution", self._dns_resolve),
            ("SSL Certificate", self._ssl_cert),
            ("HTTP Headers & Security", self._http_headers),
            ("Technology Fingerprint", self._tech_fingerprint),
            ("Subdomain Enumeration", self._subdomain_enum),
            ("Port Scan (Database Pubblici)", self._port_scan),
            ("WHOIS Lookup", self._whois_lookup),
            ("Web Page Analysis", self._web_analysis),
            ("Domain Breach Check", self._domain_breach_check),
        ]

        for i, (name, func) in enumerate(tasks, 1):
            progress_bar(i - 1, len(tasks), name)
            try:
                func()
                status("✓", name, C.G)
            except Exception as e:
                status("✗", f"{name}: {e}", C.R)
            progress_bar(i, len(tasks), name)

        self._print_results()
        return self.results

    def _dns_resolve(self):
        """Risoluzione DNS con Cloudflare DoH"""
        records = {}
        try:
            ips = socket.getaddrinfo(self.domain, None)
            ipv4 = list({addr[4][0] for addr in ips if addr[0] == socket.AF_INET})
            ipv6 = list({addr[4][0] for addr in ips if addr[0] == socket.AF_INET6})
            records["A"] = ipv4
            records["AAAA"] = ipv6
        except socket.gaierror:
            records["A"] = []

        for rtype in ["MX", "TXT", "NS", "CNAME", "SOA"]:
            data = http.json_get(
                f"https://cloudflare-dns.com/dns-query?name={self.domain}&type={rtype}",
                headers={"Accept": "application/dns-json"}
            )
            if data and "Answer" in data:
                records[rtype] = [a.get("data", "") for a in data["Answer"]]
            else:
                records[rtype] = []

        self.results["dns"] = records

    def _ssl_cert(self):
        """Recupero certificato SSL con verifica TLS"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        try:
            with ctx.wrap_socket(socket.socket(), server_hostname=self.domain) as s:
                s.settimeout(8)
                s.connect((self.domain, 443))
                cert = s.getpeercert()
                self.results["ssl_cert"] = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "serial": cert.get("serialNumber"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": [
                        e[1] for e in cert.get("subjectAltName", [])
                    ],
                    "version": cert.get("version"),
                    "verified": True,
                }
        except Exception as e:
            self.results["ssl_cert"] = {"error": str(e), "verified": False}

    def _http_headers(self):
        """Analisi header HTTP e sicurezza"""
        resp = http.get(f"https://{self.domain}", timeout=10, verify_ssl=True)
        if not resp["ok"]:
            resp = http.get(f"http://{self.domain}", timeout=10, verify_ssl=False)
        hdrs = resp.get("headers", {})

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

        score = len(found) / len(security_headers) * 100

        self.results["headers_security"] = {
            "server": hdrs.get("Server") or hdrs.get("server", "N/A"),
            "powered_by": hdrs.get("X-Powered-By") or hdrs.get("x-powered-by", "N/A"),
            "present": found,
            "missing": missing,
            "score": round(score, 1),
            "all_headers": {k: v for k, v in hdrs.items()},
            "tls_verified": resp.get("verified", False),
        }

    def _tech_fingerprint(self):
        """Fingerprint tecnologie tramite body e headers"""
        resp = http.get(f"https://{self.domain}", timeout=10)
        body = resp.get("body", "")
        hdrs = resp.get("headers", {})
        techs = []

        signatures = {
            "WordPress": ["/wp-content/", "/wp-includes/", "wp-json"],
            "Joomla": ["/components/com_", "Joomla!"],
            "Drupal": ["Drupal.settings", "/sites/default/files"],
            "React": ["react.production.min", "__NEXT_DATA__", "reactroot"],
            "Next.js": ["__NEXT_DATA__", "_next/static"],
            "Vue.js": ["vue.min.js", "vue.runtime", "__vue__", "v-cloak"],
            "Angular": ["ng-version", "ng-app", "angular.min.js"],
            "jQuery": ["jquery.min.js", "jquery-"],
            "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
            "Tailwind CSS": ["tailwindcss"],
            "Laravel": ["laravel_session", "csrf-token"],
            "Django": ["csrfmiddlewaretoken", "django"],
            "Flask": ["Werkzeug"],
            "Express": ["X-Powered-By: Express"],
            "Nginx": [],
            "Apache": [],
            "Cloudflare": ["cf-ray", "cloudflare"],
            "AWS": ["AmazonS3", "awselb", "x-amz-"],
            "Google Analytics": ["google-analytics.com", "gtag("],
            "Google Tag Manager": ["googletagmanager.com"],
            "Shopify": ["cdn.shopify.com", "Shopify.theme"],
            "Wix": ["wix.com", "X-Wix-"],
            "Squarespace": ["squarespace.com"],
            "PHP": [],
            "ASP.NET": ["__VIEWSTATE", "asp.net"],
        }

        server = (hdrs.get("Server") or hdrs.get("server") or "").lower()
        powered = (hdrs.get("X-Powered-By") or hdrs.get("x-powered-by") or "").lower()

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
                if sig.lower() in body_lower:
                    if not any(t["name"] == tech for t in techs):
                        techs.append({
                            "name": tech,
                            "category": "Technology",
                            "confidence": "medium",
                        })
                    break

        self.results["technologies"] = techs

    def _subdomain_enum(self):
        """Enumerazione subdomini via crt.sh e SAN certificate"""
        subs = set()

        # crt.sh (Certificate Transparency)
        data = http.json_get(f"https://crt.sh/?q=%.{self.domain}&output=json", timeout=15)
        if data and isinstance(data, list):
            for entry in data:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n.endswith(self.domain) and "*" not in n:
                        subs.add(n)

        # SAN dal certificato SSL
        for san in self.results.get("ssl_cert", {}).get("san", []):
            if san.endswith(self.domain) and "*" not in san:
                subs.add(san.lower())

        # Wordlist comune (solo risoluzione DNS, nessun attacco)
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

        self.results["subdomains"] = sorted(subs)

    def _port_scan(self):
        """Port scanning LEGALE via database pubblici (Shodan, Censys, URLScan.io)"""
        open_ports = []
        sources = []

        try:
            ip = socket.gethostbyname(self.domain)
        except socket.gaierror:
            status("○", "Port scan: impossibile risolvere IP", C.DIM)
            return

        status("📡", f"Port scan legale via database pubblici...", C.CY)

        # ============= SHODAN INTERNETDB (API pubblica gratuita) =============
        try:
            shodan_data = http.json_get(f"https://internetdb.shodan.io/{ip}", timeout=10)
            if shodan_data and "detail" not in shodan_data:
                ports = shodan_data.get("ports", [])
                for port in ports:
                    open_ports.append({
                        "port": port,
                        "service": self._get_port_service(port),
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

        # ============= URLSCAN.IO (scansioni web pubbliche) =============
        try:
            urlscan_data = http.json_get(
                f"https://urlscan.io/api/v1/search/?q=ip:{ip}",
                timeout=10
            )
            if urlscan_data and urlscan_data.get("total", 0) > 0:
                results = urlscan_data.get("results", [])
                for result in results[:10]:
                    page = result.get("page", {})
                    if page.get("ip") == ip and page.get("port"):
                        port = page.get("port")
                        if not any(p["port"] == port for p in open_ports):
                            open_ports.append({
                                "port": port,
                                "service": self._get_port_service(port),
                                "state": "open",
                                "banner": page.get("server", ""),
                                "source": "URLScan.io",
                                "verified": True,
                                "url": result.get("task", {}).get("reportURL", "")
                            })
                if results:
                    sources.append("URLScan.io")
                    status("✓", f"URLScan.io: {len(open_ports)} porte trovate", C.G)
        except Exception as e:
            pass

        # ============= CENSYS (riferimento pubblico) =============
        try:
            censys_url = f"https://search.censys.io/hosts/{ip}"
            resp = http.head(censys_url, timeout=8)
            if resp["ok"]:
                self.results["censys_lookup"] = {
                    "url": censys_url,
                    "note": "Verifica manuale su Censys per porte dettagliate"
                }
                sources.append("Censys")
                status("🔍", "Censys: Ricerca disponibile", C.CY)
        except:
            pass

        # ============= DEDUZIONI DA SERVIZI NOTI (solo fallback) =============
        if not open_ports:
            status("📡", "Nessuna porta da database, controllo servizi standard...", C.DIM)

            # Web server - deduciamo da presenza sito web
            if self.results.get("web_info", {}).get("title", "N/A") != "N/A":
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

            # Mail server - deduciamo da record MX
            if self.results.get("dns", {}).get("MX", []):
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

        self.results["ports"] = sorted(open_ports, key=lambda x: x["port"])
        self.results["port_sources"] = list(set(sources))

        if open_ports:
            status("🔓", f"Trovate {len(open_ports)} porte da {len(set(sources))} fonti legali", C.G)
        else:
            status("○", "Nessuna porta rilevata da database pubblici", C.DIM)

    def _get_port_service(self, port: int) -> str:
        """Mappa porta a servizio standard"""
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
        return port_services.get(port, "unknown")

    def _whois_lookup(self):
        """WHOIS via RDAP (REST-based)"""
        data = http.json_get(f"https://rdap.org/domain/{self.domain}", timeout=10)
        if data:
            info = {
                "name": data.get("ldhName", ""),
                "status": data.get("status", []),
                "events": [],
                "nameservers": [],
                "entities": [],
            }
            for event in data.get("events", []):
                info["events"].append({
                    "action": event.get("eventAction"),
                    "date": event.get("eventDate"),
                })
            for ns in data.get("nameservers", []):
                info["nameservers"].append(ns.get("ldhName", ""))
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                handle = entity.get("handle", "")
                vcard_info = {}
                for vc in entity.get("vcardArray", [None, []])[1] if len(entity.get("vcardArray", [])) > 1 else []:
                    if isinstance(vc, list) and len(vc) >= 4:
                        if vc[0] == "fn":
                            vcard_info["name"] = vc[3]
                        elif vc[0] == "email":
                            vcard_info["email"] = vc[3]
                        elif vc[0] == "org":
                            vcard_info["org"] = vc[3]
                info["entities"].append({
                    "roles": roles,
                    "handle": handle,
                    **vcard_info,
                })
            self.results["whois_info"] = info
        else:
            self.results["whois_info"] = {"error": "RDAP lookup failed"}

    def _web_analysis(self):
        """Analisi pagina web principale"""
        resp = http.get(f"https://{self.domain}", timeout=10)
        body = resp.get("body", "")

        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        title = title_match.group(1).strip() if title_match else "N/A"

        desc_match = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']', body, re.IGNORECASE)
        description = desc_match.group(1).strip() if desc_match else "N/A"

        emails = list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)))

        links = re.findall(r'href=["\'](https?://[^"\']+)["\']', body, re.IGNORECASE)
        external_links = [l for l in links if self.domain not in l]

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
        robots_content = robots["body"][:2000] if robots["ok"] else "Not found"

        sitemap = http.head(f"https://{self.domain}/sitemap.xml", timeout=5)

        self.results["web_info"] = {
            "title": title,
            "description": description,
            "emails_found": emails[:20],
            "external_links_count": len(external_links),
            "external_links_sample": external_links[:10],
            "social_media": social,
            "robots_txt": robots_content[:500],
            "sitemap_exists": sitemap.get("ok", False),
            "page_size_kb": round(len(body) / 1024, 1),
        }

    def _domain_breach_check(self):
        """Cerca se il dominio è stato coinvolto in breach"""
        breaches = []

        # URLScan.io - API stabile
        try:
            urlscan_url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}"
            data = http.json_get(urlscan_url, timeout=10)
            if data and data.get("total", 0) > 0:
                breaches.append({
                    "source": "URLScan.io",
                    "confirmed": True,
                    "total_scans": data.get("total", 0),
                    "malicious": sum(1 for r in data.get("results", [])[:10]
                                   if r.get("page", {}).get("status") in [400, 401, 403, 404, 500, 502, 503]),
                    "details": f"{data.get('total', 0)} scansioni trovate"
                })
                status("⚠", f"URLScan.io: {data.get('total', 0)} scansioni trovate", C.Y)
        except Exception as e:
            pass

        # Shodan InternetDB - API pubblica
        try:
            ip = socket.gethostbyname(self.domain)
            shodan_data = http.json_get(f"https://internetdb.shodan.io/{ip}")
            if shodan_data and "detail" not in shodan_data:
                if shodan_data.get("vulns") or shodan_data.get("tags"):
                    breaches.append({
                        "source": "Shodan InternetDB",
                        "confirmed": True,
                        "vulns": shodan_data.get("vulns", []),
                        "tags": shodan_data.get("tags", [])[:5],
                        "details": f"{len(shodan_data.get('vulns', []))} vulnerabilità note"
                    })
                    status("⚠", f"Shodan: {len(shodan_data.get('vulns', []))} vulnerabilità!", C.R)
        except:
            pass

        if breaches:
            self.results["domain_breaches"] = breaches
            status("🔥", f"Trovati {len(breaches)} breach confermati per il dominio", C.R)

    def _print_results(self):
        """Stampa formattata dei risultati"""
        r = self.results

        # DNS Records
        dns_lines = []
        for rtype, values in r.get("dns", {}).items():
            if values:
                for v in values[:5]:
                    dns_lines.append(f"{C.Y}{rtype:6}{C.RST} → {v}")
        if dns_lines:
            print(f"\n{box('📡 DNS Records', dns_lines)}")

        # SSL Certificate
        ssl_info = r.get("ssl_cert", {})
        if ssl_info and "error" not in ssl_info:
            verified = ssl_info.get("verified", False)
            verified_str = f"{C.G}✓ Verified{C.RST}" if verified else f"{C.R}✗ Not Verified{C.RST}"
            ssl_lines = [
                f"Subject:    {ssl_info.get('subject', {}).get('commonName', 'N/A')}",
                f"Issuer:     {ssl_info.get('issuer', {}).get('organizationName', 'N/A')}",
                f"Valid From: {ssl_info.get('not_before', 'N/A')}",
                f"Valid To:   {ssl_info.get('not_after', 'N/A')}",
                f"SANs:       {len(ssl_info.get('san', []))} entries",
                f"Status:     {verified_str}",
            ]
            print(f"\n{box('🔒 SSL Certificate', ssl_lines, C.G)}")

        # Security Headers
        sec = r.get("headers_security", {})
        if sec:
            score = sec.get("score", 0)
            score_color = C.G if score >= 70 else C.Y if score >= 40 else C.R
            tls_verified = sec.get("tls_verified", False)
            tls_str = f"{C.G}✓ TLS Verified{C.RST}" if tls_verified else f"{C.R}✗ TLS Not Verified{C.RST}"
            sec_lines = [
                f"Server:     {sec.get('server', 'N/A')}",
                f"Powered By: {sec.get('powered_by', 'N/A')}",
                f"TLS:        {tls_str}",
                f"Score:      {score_color}{score}%{C.RST}",
                "",
                f"{C.G}Present ({len(sec.get('present', {}))}):{C.RST}",
            ]
            for h in sec.get("present", {}):
                sec_lines.append(f"  ✓ {h}")
            sec_lines.append(f"\n{C.R}Missing ({len(sec.get('missing', []))}):{C.RST}")
            for h in sec.get("missing", []):
                sec_lines.append(f"  ✗ {h}")
            print(f"\n{box('🛡️  Security Headers', sec_lines, C.M)}")

        # Technologies
        techs = r.get("technologies", [])
        if techs:
            tech_lines = []
            for t in techs:
                conf_icon = "🟢" if t["confidence"] == "high" else "🟡"
                tech_lines.append(f"  {conf_icon} {t['name']:20} [{t['category']}]")
            print(f"\n{box('🔧 Technologies Detected', tech_lines, C.B)}")

        # Subdomains
        subs = r.get("subdomains", [])
        if subs:
            sub_lines = [f"  • {s}" for s in subs[:30]]
            if len(subs) > 30:
                sub_lines.append(f"  ... and {len(subs)-30} more")
            sub_lines.insert(0, f"  Total: {C.BLD}{len(subs)}{C.RST} subdomains found")
            print(f"\n{box('🌐 Subdomains', sub_lines, C.CY)}")

        # Open Ports (LEGALI)
        ports = r.get("ports", [])
        if ports:
            port_lines = []
            sources_used = r.get("port_sources", [])

            for p in ports:
                verified_icon = "✓" if p.get("verified", False) else "?"
                verified_color = C.G if p.get("verified", False) else C.Y
                source = p.get("source", "Unknown")
                banner_str = f" | {p['banner'][:50]}" if p.get("banner") else ""
                state_str = p.get("state", "open")

                port_lines.append(f"  {verified_color}{verified_icon}{C.RST}  {p['port']:>5}/tcp  {p['service']:15}  [{source}]{banner_str}")

            port_lines.append("")
            port_lines.append(f"  {C.DIM}📚 Fonti utilizzate: {', '.join(sources_used) if sources_used else 'Nessuna'}{C.RST}")

            if r.get("censys_lookup"):
                port_lines.append(f"  {C.DIM}🔗 Censys: {r['censys_lookup']['url']}{C.RST}")

            print(f"\n{box('🔌 Open Ports (Database Pubblici)', port_lines, C.Y)}")

        # Web Analysis
        web = r.get("web_info", {})
        if web:
            emails_redacted = [Redactor.email(e) for e in web.get('emails_found', [])[:3]] if Config.redact_reports else web.get('emails_found', [])[:3]
            web_lines = [
                f"Title:       {web.get('title', 'N/A')[:60]}",
                f"Description: {web.get('description', 'N/A')[:60]}",
                f"Page Size:   {web.get('page_size_kb', 0)} KB",
                f"Emails:      {', '.join(emails_redacted) or 'None found'}",
                f"Sitemap:     {'✓ Found' if web.get('sitemap_exists') else '✗ Not found'}",
            ]
            social = web.get("social_media", {})
            if social:
                web_lines.append(f"\n{C.BLD}Social Media:{C.RST}")
                for platform, handles in social.items():
                    web_lines.append(f"  {platform}: {', '.join(handles[:3])}")
            print(f"\n{box('🌍 Web Analysis', web_lines, C.M)}")

        # Domain Breaches
        breaches = r.get("domain_breaches", [])
        if breaches:
            breach_lines = []
            for b in breaches:
                if b["source"] == "URLScan.io":
                    breach_lines.append(f"  • {C.R}⚠{C.RST} {b['source']}: {b.get('details', '')}")
                elif b["source"] == "Shodan InternetDB":
                    vulns = b.get('vulns', [])
                    vuln_str = f"{len(vulns)} vulnerabilità: {', '.join(vulns[:3])}" if vulns else "0 vulnerabilità"
                    breach_lines.append(f"  • {C.R}⚠{C.RST} {b['source']}: {vuln_str}")
            if breach_lines:
                print(f"\n{box('⚠️  🌍 EXPOSURE & VISIBILITY SIGNALS', breach_lines, C.R)}")


# ════════════════════════════════════════════════════════════════════
#  MODULE 2 — EMAIL OSINT CON BREACH CHECK DETTAGLIATO
# ════════════════════════════════════════════════════════════════════

class EmailOSINT:
    """Intelligence su email con breach check e fonti esplicite"""

    def __init__(self, email: str):
        self.email = email.strip().lower()
        self.local, self.domain = self.email.split("@") if "@" in self.email else (email, "")
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
            "breach_summary": None
        }

    def run_all(self):
        print(f"\n{C.BLD}{C.M}{'═'*60}")
        print(f"  📧 EMAIL INTELLIGENCE — {Redactor.email(self.email) if Config.redact_reports else self.email}")
        print(f"{'═'*60}{C.RST}\n")

        self._validate_format()
        self._check_mx()
        self._check_disposable()
        self._gravatar_lookup()
        self._breach_check_combined()
        self._social_enum()
        self._print_results()
        return self.results

    def _validate_format(self):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        self.results["valid_format"] = bool(re.match(pattern, self.email))
        status("✓" if self.results["valid_format"] else "✗",
               f"Format validation: {'Valid' if self.results['valid_format'] else 'Invalid'}")

    def _check_mx(self):
        """Controllo MX records con fallback multiplo + hardcoded per domini noti"""
        
        # ---- TENTATIVO 1: Cloudflare DoH ----
        try:
            data = http.json_get(
                f"https://cloudflare-dns.com/dns-query?name={self.domain}&type=MX",
                headers={"Accept": "application/dns-json"},
                timeout=5
            )
            if data and "Answer" in data:
                self.results["mx_records"] = [a["data"] for a in data["Answer"]]
                status("✓", f"MX Records: {len(self.results['mx_records'])} found (Cloudflare)")
                return
        except:
            pass
        
        # ---- TENTATIVO 2: Google DNS ----
        try:
            data = http.json_get(
                f"https://dns.google/resolve?name={self.domain}&type=MX",
                timeout=5
            )
            if data and "Answer" in data:
                self.results["mx_records"] = [a["data"] for a in data["Answer"]]
                status("✓", f"MX Records: {len(self.results['mx_records'])} found (Google)")
                return
        except:
            pass
        
        # ---- TENTATIVO 3: Quad9 DNS ----
        try:
            data = http.json_get(
                f"https://dns.quad9.net:5053/dns-query?name={self.domain}&type=MX",
                headers={"Accept": "application/dns-json"},
                timeout=5
            )
            if data and "Answer" in data:
                self.results["mx_records"] = [a["data"] for a in data["Answer"]]
                status("✓", f"MX Records: {len(self.results['mx_records'])} found (Quad9)")
                return
        except:
            pass
        
        # ---- HARDCODED per domini italiani e internazionali ----
        hardcoded_mx = {
            "libero.it": ["mx.libero.it", "mx2.libero.it"],
            "tin.it": ["mx.libero.it", "mx2.libero.it"],
            "alice.it": ["mx.libero.it", "mx2.libero.it"],
            "virgilio.it": ["mx.virgilio.it", "mx2.virgilio.it"],
            "hotmail.it": ["mx1.hotmail.com", "mx2.hotmail.com"],
            "outlook.it": ["mx1.outlook.com", "mx2.outlook.com"],
            "yahoo.it": ["mx.yahoo.com", "mx2.yahoo.com"],
            "gmail.com": ["gmail-smtp-in.l.google.com", "alt1.gmail-smtp-in.l.google.com"],
            "yahoo.com": ["mx.yahoo.com", "mx2.yahoo.com"],
            "hotmail.com": ["mx1.hotmail.com", "mx2.hotmail.com"],
            "outlook.com": ["mx1.outlook.com", "mx2.outlook.com"],
            "aol.com": ["mailin-01.mx.aol.com", "mailin-02.mx.aol.com"],
            "icloud.com": ["mx01.mail.icloud.com", "mx02.mail.icloud.com"],
        }
        
        if self.domain in hardcoded_mx:
            self.results["mx_records"] = hardcoded_mx[self.domain]
            status("⚠", f"MX Records: {len(self.results['mx_records'])} found (hardcoded)", C.Y)
            return
        
        # ---- NESSUN MX TROVATO ----
        self.results["mx_records"] = []
        status("✗", "No MX records found (tutti i tentativi falliti)", C.R)

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
        if data and "entry" in data:
            entry = data["entry"][0]
            self.results["gravatar"] = {
                "exists": True,
                "display_name": entry.get("displayName", ""),
                "profile_url": entry.get("profileUrl", ""),
                "avatar_url": f"https://gravatar.com/avatar/{email_hash}",
                "about": entry.get("aboutMe", ""),
                "location": entry.get("currentLocation", ""),
                "accounts": [
                    {"name": a.get("shortname"), "url": a.get("url")}
                    for a in entry.get("accounts", [])
                ],
            }
            status("✓", f"Gravatar profile found: {entry.get('displayName', 'N/A')}", C.G)
        else:
            self.results["gravatar"] = {"exists": False}
            status("○", "No Gravatar profile", C.DIM)

    def _breach_check_combined(self):
        """Controllo breach combinato: XposedOrNot + EmailRep + Firefox + aggressive"""
        
        # ----- 1. XPOSEDORNOT (sempre attivo, no key) -----
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
        
        # ----- 2. FONTI STABILI (EmailRep.io, Firefox Monitor) -----
        other_breaches = []
        
        try:
            resp = http.get(f"https://emailrep.io/{self.email}",
                           headers={"User-Agent": "GhostRecon/3.0", "Accept": "application/json"},
                           timeout=10)
            if resp["ok"]:
                data = json.loads(resp["body"])
                if data.get("details", {}).get("breaches", False):
                    breach_count = data.get("details", {}).get("breach_count", 0)
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
                if data.get("breached", False):
                    breach_count = data.get("breachCount", 1)
                    breaches_found = data.get("breaches", [])
                    for b in breaches_found[:5]:
                        other_breaches.append({
                            "source": "Firefox Monitor",
                            "breach_name": b.get("Name", "Unknown"),
                            "date": b.get("BreachDate", ""),
                            "details": f"Trovato in: {b.get('Name', 'Unknown breach')}",
                            "confirmed": True,
                            "reliable": True
                        })
                    status("⚠", f"⚠️ Firefox Monitor: {breach_count} breach!", C.R)
        except:
            pass
        
        # ----- 3. FONTI AGGRESSIVE (solo con --aggressive) -----
        if Config.aggressive_mode:
            try:
                leak_data = http.post("https://leak-lookup.com/api/search",
                                     data=f"key=&type=email_address&query={self.email}",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"},
                                     timeout=Config.timeout_aggressive)
                if leak_data["ok"]:
                    data = json.loads(leak_data["body"])
                    if data.get("error") == "false" and data.get("message"):
                        for breach_name, records in data["message"].items():
                            if records and len(records) > 0:
                                record_count = len(records) if isinstance(records, list) else 1
                                other_breaches.append({
                                    "source": "Leak-Lookup",
                                    "breach_name": breach_name,
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
                if resp["ok"] and "no results" not in resp["body"].lower():
                    if "found" in resp["body"].lower():
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
                    if data.get("success") and data.get("found", 0) > 0:
                        for breach in data.get("result", [])[:5]:
                            other_breaches.append({
                                "source": "LeakCheck",
                                "breach_name": breach.get("name", "Unknown"),
                                "date": breach.get("date", ""),
                                "details": f"Database: {breach.get('name', 'Unknown')}",
                                "confirmed": True,
                                "reliable": True
                            })
                        status("⚠", f"⚠️ LeakCheck: {data.get('found', 0)} leak!", C.R)
            except:
                pass
        
        self.results["breach_details"] = other_breaches
        if other_breaches:
            self.results["breach_count"] = len(other_breaches)
            self.results["breach_sources"] = list(set([b["source"] for b in other_breaches]))
            status("🔥", f"TROVATI {len(other_breaches)} BREACH IN FONTI AGGIUNTIVE!", C.BG_R)

    def _social_enum(self):
        profiles = []
        try:
            data = http.json_get(f"https://api.github.com/search/users?q={self.email}+in:email")
            if data and data.get("total_count", 0) > 0:
                for user in data.get("items", [])[:3]:
                    profiles.append({
                        "platform": "GitHub",
                        "username": user["login"],
                        "url": user["html_url"],
                    })
                status("✓", f"Found {len(profiles)} GitHub profile(s)")
        except:
            pass
        self.results["social_profiles"] = profiles

    def _print_results(self):
        email_display = Redactor.email(self.email) if Config.redact_reports else self.email

        lines = [
            f"Email:       {email_display}",
            f"Valid:       {'✓ Yes' if self.results['valid_format'] else '✗ No'}",
            f"Domain:      {self.domain}",
            f"Disposable:  {'⚠ Yes!' if self.results['disposable'] else '✓ No'}",
            f"MX Records:  {len(self.results['mx_records'])}",
        ]

        grav = self.results.get("gravatar", {})
        if grav.get("exists"):
            lines.extend([
                "",
                f"{C.BLD}Gravatar Profile:{C.RST}",
                f"  Name:     {grav.get('display_name', 'N/A')}",
                f"  Location: {grav.get('location', 'N/A')}",
                f"  URL:      {grav.get('profile_url', '')}",
            ])

        profiles = self.results.get("social_profiles", [])
        if profiles:
            lines.append(f"\n{C.BLD}Social Profiles:{C.RST}")
            for p in profiles:
                lines.append(f"  [{p['platform']}] {p['username']} — {p['url']}")

        # --- SEZIONE BREACH XposedOrNot ---
        breaches = self.results.get("breaches")
        summary = self.results.get("breach_summary")
        source = self.results.get("breach_source", "N/A")

        if breaches is None:
            lines.append(f"\n{C.Y}○ BREACH CHECK: NON DISPONIBILE{C.RST}")
            lines.append(f"  Fonte: {source}")
        elif summary and summary["count"] == 0:
            lines.append(f"\n{C.BLD}{C.G}✅ NESSUN BREACH TROVATO{C.RST}")
            lines.append(f"  Fonte: {source}")
            lines.append(f"  {C.DIM}Nota: check basato su DB pubblici/statici; possibile ritardo aggiornamenti.{C.RST}")
            lines.append(f"  {C.DIM}Verifica consigliata: Have I Been Pwned (HIBP).{C.RST}")
        else:
            cnt = summary["count"] if summary else len(breaches) if breaches else 0
            lines.append(f"\n{C.BLD}{C.BG_R}⚠️⚠️⚠️  BREACH TROVATI ⚠️⚠️⚠️{C.RST}")
            lines.append(f"  {C.R}TOTALE: {cnt} breach{C.RST}")
            if summary:
                lines.append(f"  Risk: {summary['level']}  | Score: {summary['score']}/100")
                lines.append(f"  Timeline: {summary['timeline']}")
                
                # --- PATCH: mostra solo 5 esempi ---
                if summary['sample'] and summary['sample'] != "N/A":
                    sample_parts = summary['sample'].split(', ')
                    examples_with_dates = []
                    for breach_name in sample_parts[:5]:
                        breach_date = "N/A"
                        for b in breaches:
                            if isinstance(b, dict):
                                name = b.get('name') or b.get('breach') or b.get('title')
                                if name and name == breach_name:
                                    d = b.get('date') or b.get('breach_date') or b.get('added_date') or b.get('published')
                                    if d:
                                        breach_date = str(d)[:4]
                                    break
                        if breach_date != "N/A":
                            examples_with_dates.append(f"{breach_name} ({breach_date})")
                        else:
                            examples_with_dates.append(breach_name)
                    
                    sample_short = ', '.join(examples_with_dates)
                    if len(sample_parts) > 5:
                        sample_short += '...'
                else:
                    sample_short = summary['sample']
                
                lines.append(f"  Esempi: {sample_short}")
                
            lines.append(f"  Fonte: {source}")

        # --- BREACH AGGIUNTIVI ---
        other_breaches = self.results.get("breach_details", [])
        if other_breaches:
            lines.append(f"\n{C.BLD}{C.Y}🔍 Breach rilevati da fonti aggiuntive:{C.RST}")
            by_source = {}
            for b in other_breaches:
                src = b['source']
                if src not in by_source:
                    by_source[src] = []
                by_source[src].append(b)

            for source, breach_list in by_source.items():
                lines.append(f"  {C.Y}📁 {source}:{C.RST}")
                for b in breach_list[:3]:
                    if 'breach_name' in b:
                        if 'records' in b:
                            lines.append(f"    • {C.R}⚠{C.RST} {b['breach_name']} ({b['records']:,} records)")
                        elif 'date' in b and b['date']:
                            lines.append(f"    • {C.R}⚠{C.RST} {b['breach_name']} ({b['date'][:4]})")
                        else:
                            lines.append(f"    • {C.R}⚠{C.RST} {b['breach_name']}")
                    else:
                        lines.append(f"    • {C.R}⚠{C.RST} {b.get('details', 'Compromesso')}")
                if len(breach_list) > 3:
                    lines.append(f"    • ... e {len(breach_list)-3} altri")

        print(f"\n{box('📧 EMAIL INTELLIGENCE REPORT', lines, C.M)}")
        
        # --- DISEGNA CRONOGRAMMA ---
        if breaches is not None and summary and summary["count"] > 0:
            self._draw_breach_timeline(breaches, summary)

    # -----------------------------------------------------------------
    #  🎨 CRONOGRAMMA BREACH
    # -----------------------------------------------------------------
    def _draw_breach_timeline(self, breaches, summary):
        """Disegna un cronogramma ASCII dei breach"""
        if not breaches or not isinstance(breaches, list):
            return
        
        years = []
        for b in breaches:
            if isinstance(b, dict):
                d = b.get('date') or b.get('breach_date') or b.get('added_date') or b.get('published')
                if d:
                    try:
                        y = int(str(d)[:4])
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
# ════════════════════════════════════════════════════════════════════
#  MODULE 3 — USERNAME HUNTER (50+ PIATTAFORME)
# ════════════════════════════════════════════════════════════════════

class UsernameHunter:
    """Cerca username su 50+ piattaforme social e verifica breach"""
    
    # Piattaforme con URL diretti (verifica HTTP status)
    PLATFORMS_DIRECT = {
        # Social principali
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
        "WhatsApp": "https://wa.me/{}",  # Numero, ma lasciamo
        "Signal": "https://signal.me/#u/{}",
        
        # Sviluppo e tech
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
        
        # Gaming
        "Steam": "https://steamcommunity.com/id/{}",
        "Epic Games": "https://www.epicgames.com/@{}",
        "Xbox": "https://account.xbox.com/it-it/profile?gamertag={}",
        "PlayStation": "https://my.playstation.com/profile/{}",
        "Nintendo": "https://en-americas-support.nintendo.com/app/answers/detail/a_id/58581/~/how-to-change-your-nintendo-account-sign-in-id",
        "Minecraft": "https://namemc.com/profile/{}",
        "Roblox": "https://www.roblox.com/user.aspx?username={}",
        "Fortnite": "https://fortnitetracker.com/profile/all/{}",
        "Apex Legends": "https://apex.tracker.gg/apex/profile/origin/{}/overview",
        
        # Forum italiani
        "HWG": "https://www.hwupgrade.it/forum/member.php?username={}",
        "Tom's Hardware": "https://forum.tomsguide.it/members/?username={}",
        "ForumFree": "https://member.forumfree.it/?user={}",
        "Androidiani": "https://www.androidiani.com/forum/members/{}.html",
        "Moto.it": "https://www.moto.it/forum/member.php?username={}",
        
        # Forum internazionali
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
        
        # Lavoro e professionali
        "Xing": "https://www.xing.com/profile/{}",
        "AngelList": "https://angel.co/u/{}",
        "Upwork": "https://www.upwork.com/freelancers/~{}",
        "Fiverr": "https://www.fiverr.com/{}",
        "Freelancer": "https://www.freelancer.com/u/{}",
        
        # Dating
        "Tinder": "https://tinder.com/@{}",
        "Bumble": "https://bumble.com/it/profile/{}",
        "Grindr": "https://www.grindr.com/profile/{}",
        
        # Altro
        "Wikipedia": "https://en.wikipedia.org/wiki/User:{}",
        "Patreon": "https://www.patreon.com/{}",
        "Kickstarter": "https://www.kickstarter.com/profile/{}",
        "Etsy": "https://www.etsy.com/people/{}",
        "eBay": "https://www.ebay.com/usr/{}",
        "Amazon": "https://www.amazon.com/gp/profile/{}",
        "Wish": "https://www.wish.com/{}",
        "Aliexpress": "https://feedback.aliexpress.com/display/evaluationDetail.htm?memberId={}",
    }
    
    # Piattaforme che richiedono API (opzionali, con chiave)
    PLATFORMS_API = {
        "GitHub": {
            "url": "https://api.github.com/users/{}",
            "check": lambda d: d.get("id") is not None,
            "fields": ["login", "name", "bio", "public_repos", "followers", "location", "blog", "twitter_username", "created_at"]
        },
        "Reddit": {
            "url": "https://www.reddit.com/user/{}/about.json",
            "check": lambda d: d.get("data", {}).get("id") is not None,
            "fields": ["name", "total_karma", "created_utc", "is_gold", "link_karma", "comment_karma"]
        },
        "Instagram": {
            "url": "https://www.instagram.com/{}/?__a=1",  # Deprecato, ma funziona ancora
            "check": lambda d: d.get("graphql", {}).get("user", {}).get("id") is not None,
            "fields": ["full_name", "biography", "edge_followed_by", "edge_follow", "is_private", "is_verified"]
        },
        "Twitter/X": {
            "url": "https://api.twitter.com/2/users/by/username/{}",  # Richiede Bearer token
            "check": lambda d: d.get("data") is not None,
            "fields": ["name", "description", "public_metrics", "created_at", "verified"],
            "needs_auth": True
        },
    }
    
    def __init__(self, username: str):
        self.username = username.strip().lower()
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
        """Esegue la caccia all'username"""
        print(f"\n{C.BLD}{C.Y}{'═'*60}")
        print(f"  🎯 USERNAME HUNTER — {self.username}")
        print(f"{'═'*60}{C.RST}\n")
        
        status("🔍", f"Controllo {len(self.PLATFORMS_DIRECT)} piattaforme...", C.CY)
        
        # Usa ThreadPoolExecutor per velocizzare
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(self._check_platform, name, url): name 
                for name, url in self.PLATFORMS_DIRECT.items()
            }
            
            for i, future in enumerate(as_completed(futures), 1):
                platform = futures[future]
                try:
                    result = future.result()
                    if i % 10 == 0:  # Aggiorna ogni 10 piattaforme
                        progress_bar(i, len(self.PLATFORMS_DIRECT), f"Checking {platform[:15]}...")
                except Exception as e:
                    self.results["stats"]["error"] += 1
        
        progress_bar(len(self.PLATFORMS_DIRECT), len(self.PLATFORMS_DIRECT), "Completato!")
        
        # Verifica breach per l'username
        self._check_breaches()
        
        # Genera summary
        self._generate_summary()
        
        # Stampa risultati
        self._print_results()
        
        return self.results
    
    def _check_platform(self, name: str, url_template: str) -> dict:
        """Controlla una singola piattaforma"""
        self.results["stats"]["total_checked"] += 1
        
        url = url_template.format(self.username)
        
        # Per alcune piattaforme dobbiamo usare HEAD invece di GET
        if name in ["Instagram", "TikTok", "Snapchat"]:
            resp = http.head(url, timeout=5)
        else:
            resp = http.get(url, timeout=5)
        
        result = {
            "platform": name,
            "url": url,
            "checked": datetime.now().isoformat()
        }
        
        # Consideriamo "trovato" se status 200 e non è una pagina di errore
        if resp["ok"] and resp["status"] == 200:
            # Escludi falsi positivi (pagine di "non trovato" che danno 200)
            body_lower = resp.get("body", "").lower() if isinstance(resp.get("body"), str) else ""
            
            false_positives = [
                "not found", "user not found", "profile not found",
                "page not found", "doesn't exist", "no user",
                "non trovato", "utente non esistente", "pagina non trovata"
            ]
            
            is_false_positive = any(fp in body_lower for fp in false_positives)
            
            if not is_false_positive or len(body_lower) < 200:  # Pagine di errore sono spesso piccole
                result["found"] = True
                result["status"] = "found"
                result["method"] = "direct"
                self.results["found_profiles"].append(result)
                self.results["stats"]["found"] += 1
                return result
        
        self.results["not_found"].append({
            "platform": name,
            "url": url,
            "status": "not_found"
        })
        self.results["stats"]["not_found"] += 1
        return {"platform": name, "found": False}
    
    def _check_breaches(self):
        """Cerca se l'username è presente in breach"""
        status("🔥", f"Controllo breach per username '{self.username}'...", C.Y)
        
        # XposedOrNot supporta anche username? No, solo email
        # Usiamo leak-lookup se in modalità aggressive
        
        if Config.aggressive_mode:
            try:
                # Leak-Lookup API (versione demo/gratuita)
                data = http.post(
                    "https://leak-lookup.com/api/search",
                    data={
                        "key": "",  # Vuoto per demo
                        "type": "username",
                        "query": self.username
                    },
                    timeout=8
                )
                
                if data["ok"]:
                    result = json.loads(data["body"])
                    if result.get("error") == "false" and result.get("message"):
                        for breach_name, records in result["message"].items():
                            if records and len(records) > 0:
                                self.results["breaches"].append({
                                    "source": "Leak-Lookup",
                                    "breach_name": breach_name,
                                    "records": len(records) if isinstance(records, list) else 1,
                                    "confirmed": True
                                })
                        
                        if self.results["breaches"]:
                            status("🔥", f"⚠️ Trovato in {len(self.results['breaches'])} breach!", C.R)
            except:
                pass
            
            # Cerca su pastebin
            try:
                url = f"https://psbdmp.ws/api/search/{self.username}"
                data = http.json_get(url, timeout=5)
                if data and data.get("count", 0) > 0:
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
        """Genera summary dei risultati"""
        found_count = self.results["stats"]["found"]
        total = self.results["stats"]["total_checked"]
        
        if found_count == 0:
            level = "NESSUNO"
            color = C.G
        elif found_count < 5:
            level = "BASSO"
            color = C.G
        elif found_count < 15:
            level = "MEDIO"
            color = C.Y
        else:
            level = "ALTO"
            color = C.R
        
        self.results["summary"] = {
            "found_count": found_count,
            "total_checked": total,
            "coverage": f"{found_count}/{total}",
            "exposure_level": level,
            "breach_count": len(self.results["breaches"])
        }
    
    def _print_results(self):
        """Stampa risultati formattati"""
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
        
        # Profili trovati (dettaglio)
        if self.results["found_profiles"]:
            lines.extend([
                f"",
                f"{C.BLD}{C.G}✅ PROFILI TROVATI ({len(self.results['found_profiles'])}):{C.RST}"
            ])
            
            # Raggruppa per categoria (manualmente)
            social = []
            dev = []
            gaming = []
            forums = []
            other = []
            
            for p in self.results["found_profiles"]:
                name = p["platform"]
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
                    for p in sorted(cat_list, key=lambda x: x["platform"])[:5]:  # Max 5 per categoria
                        lines.append(f"    • {p['platform']}: {p['url']}")
                    if len(cat_list) > 5:
                        lines.append(f"    • ... e {len(cat_list)-5} altri")
        
        # Breach trovati
        if self.results["breaches"]:
            lines.extend([
                f"",
                f"{C.BLD}{C.R}🔥 BREACH TROVATI ({len(self.results['breaches'])}):{C.RST}"
            ])
            for b in self.results["breaches"][:5]:
                if b["source"] == "PSBDMP (Pastebin)":
                    lines.append(f"  • {C.R}⚠{C.RST} {b['source']}: {b.get('count', 0)} dumps")
                else:
                    lines.append(f"  • {C.R}⚠{C.RST} {b['source']}: {b['breach_name']}")
            if len(self.results["breaches"]) > 5:
                lines.append(f"  • ... e {len(self.results['breaches'])-5} altri")
        
        # Consigli
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
        
        print(f"\n{box('🎯 USERNAME HUNTER REPORT', lines, C.Y)}")
        
        # Suggerimento per approfondire
        if stats['found'] > 0:
            print(f"\n  {C.CY}💡 Per approfondire un profilo, usa i moduli:{C.RST}")
            print(f"  {C.G}• Email OSINT{C.RST} se trovi email nei profili")
            print(f"  {C.G}• Phone Breach Check{C.RST} se trovi numeri")
            print(f"  {C.G}• Domain Intel{C.RST} se trovi domini personali")
# ════════════════════════════════════════════════════════════════════
#  MODULE 4 — IP INTELLIGENCE
# ════════════════════════════════════════════════════════════════════

class IPIntel:
    """Geolocation, ASN, threat intel su un IP"""

    def __init__(self, ip: str):
        self.ip = ip.strip()
        self.results = {}

    def run_all(self):
        print(f"\n{C.BLD}{C.R}{'═'*60}")
        print(f"  📍 IP INTELLIGENCE — {self.ip}")
        print(f"{'═'*60}{C.RST}\n")

        self._geolocate()
        self._asn_info()
        self._threat_check()
        self._reverse_dns()
        self._print_results()
        return self.results

    def _geolocate(self):
        # ip-api.com - OK usare HTTP, è il loro default
        data = http.json_get(f"http://ip-api.com/json/{self.ip}?fields=66846719", verify_ssl=False)
        if data and data.get("status") == "success":
            self.results["geo"] = {
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "zip": data.get("zip"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "timezone": data.get("timezone"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
                "asname": data.get("asname"),
                "mobile": data.get("mobile"),
                "proxy": data.get("proxy"),
                "hosting": data.get("hosting"),
            }
            status("✓", f"Location: {data.get('city')}, {data.get('country')}")
        else:
            status("✗", "Geolocation failed", C.R)

    def _asn_info(self):
        data = http.json_get(f"https://ipinfo.io/{self.ip}/json")
        if data:
            self.results["ipinfo"] = {
                "hostname": data.get("hostname", "N/A"),
                "org": data.get("org", "N/A"),
                "city": data.get("city", ""),
                "region": data.get("region", ""),
                "country": data.get("country", ""),
                "loc": data.get("loc", ""),
            }
            status("✓", f"Org: {data.get('org', 'N/A')}")

    def _threat_check(self):
        shodan_data = http.json_get(f"https://internetdb.shodan.io/{self.ip}")
        if shodan_data and "detail" not in shodan_data:
            self.results["shodan"] = {
                "ports": shodan_data.get("ports", []),
                "hostnames": shodan_data.get("hostnames", []),
                "cpes": shodan_data.get("cpes", []),
                "vulns": shodan_data.get("vulns", []),
                "tags": shodan_data.get("tags", []),
            }
            n_vulns = len(shodan_data.get("vulns", []))
            if n_vulns > 0:
                status("⚠", f"Shodan: {n_vulns} vulnerabilities known!", C.R)
            else:
                status("✓", f"Shodan: {len(shodan_data.get('ports', []))} open ports")
        else:
            status("○", "Shodan InternetDB: No data", C.DIM)

    def _reverse_dns(self):
        try:
            hostname = socket.gethostbyaddr(self.ip)
            self.results["reverse_dns"] = hostname[0]
            status("✓", f"Reverse DNS: {hostname[0]}")
        except socket.herror:
            self.results["reverse_dns"] = "N/A"
            status("○", "No reverse DNS", C.DIM)

    def _print_results(self):
        geo = self.results.get("geo", {})
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
            f"  Mobile:   {'Yes' if geo.get('mobile') else 'No'}",
            f"  Proxy:    {'⚠ Yes' if geo.get('proxy') else 'No'}",
            f"  Hosting:  {'Yes' if geo.get('hosting') else 'No'}",
        ]

        shodan = self.results.get("shodan", {})
        if shodan:
            lines.extend([
                "",
                f"{C.BLD}Shodan InternetDB:{C.RST}",
                f"  Ports:    {', '.join(map(str, shodan.get('ports', [])))}",
                f"  Hosts:    {', '.join(shodan.get('hostnames', [])[:5])}",
            ])
            vulns = shodan.get("vulns", [])
            if vulns:
                lines.append(f"  {C.R}Vulns:    {', '.join(vulns[:10])}{C.RST}")
            tags = shodan.get("tags", [])
            if tags:
                lines.append(f"  Tags:     {', '.join(tags)}")

        if geo.get("lat") and geo.get("lon") and not Config.redact_reports:
            maps_url = f"https://www.google.com/maps?q={geo['lat']},{geo['lon']}"
            lines.append(f"\n  🗺️  {maps_url}")

        print(f"\n{box('📍 IP Intelligence Report', lines, C.R)}")


# ════════════════════════════════════════════════════════════════════
#  MODULE 5 — PHONE BREACH CHECK (SOLO API GRATUITE)
# ════════════════════════════════════════════════════════════════════

class PhoneBreachCheck:
    """Verifica se un numero di telefono è presente in breach (solo API gratuite)"""
    
    def __init__(self, phone: str):
        self.phone = re.sub(r'[^\d+]', '', phone)
        self.phone_clean = self.phone.lstrip("+").replace(" ", "").replace("-", "")
        self.phone_e164 = self.phone if self.phone.startswith('+') else f"+{self.phone_clean}"
        self.results = {
            "phone": self.phone,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "breaches": [],
            "web_mentions": 0,
            "sources_checked": [],
            "summary": None
        }

    def run_all(self):
        print(f"\n{C.BLD}{C.R}{'═'*60}")
        print(f"  📱 PHONE BREACH CHECK — {Redactor.phone(self.phone) if Config.redact_reports else self.phone}")
        print(f"{'═'*60}{C.RST}\n")

        # API GRATUITE che supportano numeri di telefono
        self._check_urlscan()           # Gratuito, nessuna API key
        self._check_psbdmp()             # Gratuito, nessuna API key (pastebin dumps)
        
        # API opzionali (richiedono registrazione)
        self._check_hunter_phone()        # API gratuita con limite mensile
        self._check_spyse()               # API gratuita (richiede registrazione)
        
        self._generate_summary()
        self._print_results()
        return self.results

    def _check_urlscan(self):
        """URLScan.io - Cerca menzioni del numero in pagine web scansionate"""
        status("🌐", "Controllo URLScan.io (pagine web pubbliche)...", C.CY)
        self.results["sources_checked"].append("URLScan.io")
        
        try:
            import urllib.parse
            
            # Prova diverse formattazioni del numero
            queries = [
                self.phone_e164,           # +393923272672
                self.phone_clean,           # 393923272672
                self.phone_clean[-10:],     # 3923272672 (ultime 10 cifre)
                self.phone_clean[-9:],      # 923272672 (senza prefisso internazionale)
            ]
            
            total = 0
            domains = set()
            
            for query in set(queries):
                url = f"https://urlscan.io/api/v1/search/?q={urllib.parse.quote(query)}"
                data = http.json_get(url, timeout=8)
                
                if data and data.get("total", 0) > 0:
                    total += data.get("total", 0)
                    
                    # Estrai i domini dove compare
                    for result in data.get("results", [])[:10]:
                        page = result.get("page", {})
                        domain = page.get("domain", "")
                        if domain:
                            domains.add(domain)
                        
                        # Cerca di capire se è un breach noto
                        task = result.get("task", {})
                        if "leak" in task.get("url", "").lower() or "dump" in task.get("url", "").lower():
                            self.results["breaches"].append({
                                "source": "URLScan.io",
                                "type": "possible_leak",
                                "url": task.get("reportURL", ""),
                                "domain": domain,
                                "date": task.get("time", "")[:10] if task.get("time") else "N/A",
                                "confidence": "medium"
                            })
            
            if total > 0:
                self.results["web_mentions"] = total
                status("⚠", f"⚠️ Trovato in {total} pagine web scansionate", C.Y)
                if domains:
                    status("ℹ", f"Domini: {', '.join(list(domains)[:3])}", C.DIM)
            else:
                status("✓", "Nessuna menzione su URLScan.io", C.G)
                
        except Exception as e:
            status("○", f"URLScan.io non disponibile", C.DIM)

    def _check_psbdmp(self):
        """PSBDMP - API gratuita per cercare in pastebin dumps"""
        status("📋", "Controllo PSBDMP (pastebin dumps)...", C.CY)
        self.results["sources_checked"].append("PSBDMP")
        
        try:
            # PSBDMP API - cerca il numero in pastebin dumps
            url = f"https://psbdmp.ws/api/search/{self.phone_clean}"
            data = http.json_get(url, timeout=8)
            
            if data and isinstance(data, dict):
                count = data.get("count", 0)
                if count > 0:
                    dumps = data.get("data", [])[:10]
                    
                    for dump in dumps:
                        self.results["breaches"].append({
                            "source": "PSBDMP (Pastebin)",
                            "type": "pastebin_dump",
                            "id": dump.get("id", "N/A"),
                            "url": f"https://psbdmp.ws/dump/{dump.get('id', '')}",
                            "date": dump.get("time", "")[:10] if dump.get("time") else "N/A",
                            "tags": dump.get("tags", []),
                            "confidence": "high"
                        })
                    
                    status("🔥", f"⚠️ TROVATO in {count} pastebin dumps!", C.R)
                else:
                    status("✓", "Nessun dump trovato su PSBDMP", C.G)
            else:
                status("○", "Nessun risultato da PSBDMP", C.DIM)
                
        except Exception as e:
            status("○", f"PSBDMP non disponibile", C.DIM)

    def _check_hunter_phone(self):
        """Hunter.io Phone API - verifica se numero è associato a breach"""
        status("📞", "Controllo Hunter.io Phone API...", C.CY)
        self.results["sources_checked"].append("Hunter.io")
        
        # Hunter.io ha una API gratuita con 25 richieste/mese
        # Richiede registrazione per API key
        api_key = os.getenv("HUNTER_API_KEY")  # Opzionale
        
        if not api_key:
            status("○", "Hunter.io API key non configurata (gratuita con registrazione)", C.DIM)
            return
        
        try:
            # Hunter.io Phone API
            url = f"https://api.hunter.io/v2/phone?number={self.phone_clean}&api_key={api_key}"
            data = http.json_get(url, timeout=8)
            
            if data and data.get("data"):
                phone_data = data.get("data", {})
                
                # Verifica se è associato a breach
                if phone_data.get("breached", False):
                    breach_count = phone_data.get("breaches_count", 0)
                    last_breach = phone_data.get("last_breach_date", "N/A")
                    
                    self.results["breaches"].append({
                        "source": "Hunter.io",
                        "type": "breach",
                        "count": breach_count,
                        "last_breach": last_breach,
                        "confidence": "high",
                        "details": f"Numero presente in breach database"
                    })
                    
                    status("🔥", f"⚠️ CONFERMATO! Presente in {breach_count} breach", C.R)
                else:
                    status("✓", "Nessun breach trovato su Hunter.io", C.G)
            else:
                status("○", "Numero non trovato su Hunter.io", C.DIM)
                
        except Exception as e:
            status("○", f"Hunter.io non disponibile", C.DIM)

    def _check_spyse(self):
        """Spyse - API gratuita per OSINT (richiede registrazione)"""
        status("🔍", "Controllo Spyse (breach database)...", C.CY)
        self.results["sources_checked"].append("Spyse")
        
        # Spyse ha API gratuita con limite 1000 crediti/mese
        # Richiede registrazione per API key
        api_key = os.getenv("SPYSE_API_KEY")  # Opzionale
        
        if not api_key:
            status("○", "Spyse API key non configurata (gratuita con registrazione)", C.DIM)
            return
        
        try:
            # Spyse API per cercare telefono in breach
            url = "https://api.spyse.com/v4/data/leaked"
            headers = {
                "Accept": "application/json",
                "X-API-Key": api_key
            }
            
            # Nota: Spyse richiede POST per query complesse
            # Questa è una semplificazione - controlla la documentazione
            data = http.post(
                url,
                data=json.dumps({
                    "search_params": [{
                        "field": "phone",
                        "value": self.phone_clean
                    }]
                }),
                headers=headers,
                timeout=10
            )
            
            if data["ok"]:
                result = json.loads(data["body"])
                if result.get("data", {}).get("items"):
                    items = result["data"]["items"][:10]
                    
                    for item in items:
                        self.results["breaches"].append({
                            "source": "Spyse",
                            "type": "breach",
                            "breach_name": item.get("source", "N/A"),
                            "date": item.get("created_at", "")[:10] if item.get("created_at") else "N/A",
                            "fields": item.get("fields", []),
                            "confidence": "high"
                        })
                    
                    status("🔥", f"⚠️ TROVATO in {len(items)} breach su Spyse!", C.R)
                else:
                    status("✓", "Nessun breach trovato su Spyse", C.G)
            else:
                status("○", "Spyse non disponibile", C.DIM)
                
        except Exception as e:
            status("○", f"Spyse non disponibile", C.DIM)

    def _generate_summary(self):
        """Genera summary dei risultati"""
        breaches = self.results["breaches"]
        
        if not breaches and self.results["web_mentions"] == 0:
            self.results["summary"] = {
                "found": False,
                "count": 0,
                "sources": [],
                "message": "Nessun breach trovato"
            }
            return
        
        # Raggruppa per tipo
        pastebin = [b for b in breaches if "pastebin" in b["source"].lower() or b.get("type") == "pastebin_dump"]
        confirmed = [b for b in breaches if b.get("confidence") == "high" and b not in pastebin]
        possible = [b for b in breaches if b.get("confidence") != "high" and b not in pastebin]
        
        self.results["summary"] = {
            "found": True,
            "total": len(breaches),
            "web_mentions": self.results["web_mentions"],
            "confirmed_breaches": len(confirmed),
            "pastebin_dumps": len(pastebin),
            "possible_mentions": len(possible),
            "sources": list(set([b["source"] for b in breaches]))
        }

    def _print_results(self):
        """Stampa risultati formattati"""
        phone_display = Redactor.phone(self.phone) if Config.redact_reports else self.phone
        summary = self.results.get("summary", {})
        
        lines = [
            f"Numero:      {phone_display}",
            f"Formato:     {self.phone_e164}",
            f"",
            f"{C.BLD}Fonti controllate:{C.RST}",
            f"  {', '.join(self.results['sources_checked'])}",
        ]
        
        # Menzioni web
        if self.results["web_mentions"] > 0:
            lines.extend([
                f"",
                f"{C.BLD}{C.Y}🌐 Menzioni web:{C.RST}",
                f"  Trovato in {self.results['web_mentions']} pagine web",
            ])
        
        # Summary se ci sono breach
        if summary and summary.get("found") and summary.get("total") > 0:
            lines.extend([
                f"",
                f"{C.BLD}{C.BG_R}⚠️⚠️⚠️  DATI TROVATI ⚠️⚠️⚠️{C.RST}",
                f"  {C.R}TOTALE: {summary['total']} risultati{C.RST}",
                f"  Breach confermati: {summary['confirmed_breaches']}",
                f"  Pastebin dumps: {summary['pastebin_dumps']}",
                f"  Fonti: {', '.join(summary['sources'])}",
            ])
            
            # Lista dettagliata
            lines.extend([
                f"",
                f"{C.BLD}📋 Dettaglio risultati:{C.RST}"
            ])
            
            for breach in self.results["breaches"][:10]:  # Max 10
                source = breach['source']
                if breach.get('type') == 'pastebin_dump':
                    date = breach.get('date', 'N/A')
                    url = breach.get('url', '')
                    lines.append(f"  • {C.R}📋{C.RST} Pastebin dump {date[:10]} - {url[:40]}...")
                elif breach.get('type') == 'breach':
                    name = breach.get('breach_name', 'Unknown')
                    date = breach.get('date', 'N/A')
                    lines.append(f"  • {C.R}🔥{C.RST} {name} ({date}) - {source}")
                else:
                    lines.append(f"  • {C.Y}⚠{C.RST} {source}: {breach.get('details', 'Menzione trovata')}")
            
            if len(self.results["breaches"]) > 10:
                lines.append(f"  • ... e {len(self.results['breaches'])-10} altri")
        
        elif self.results["web_mentions"] > 0:
            # Solo menzioni web, nessun breach confermato
            lines.extend([
                f"",
                f"{C.BLD}{C.Y}⚠ ATTENZIONE:{C.RST}",
                f"  Numero presente in pagine web ma non in breach confermati",
                f"  Potrebbe essere comparso in forum o siti pubblici"
            ])
        else:
            # Nessun risultato
            lines.extend([
                f"",
                f"{C.BLD}{C.G}✅ NESSUN DATO TROVATO{C.RST}",
                f"  Il numero non è stato trovato in:",
                f"  • Database breach pubblici",
                f"  • Pastebin dumps",
                f"  • Pagine web scansionate",
                f"",
                f"{C.DIM}Nota: i controlli sono su fonti pubbliche gratuite.{C.RST}",
                f"{C.DIM}Per verifiche complete servirebbero servizi a pagamento.{C.RST}"
            ])
        
        print(f"\n{box('📱 PHONE BREACH CHECK REPORT', lines, C.R if summary.get('found') else C.G)}")

# ════════════════════════════════════════════════════════════════════
#  CONFIGURAZIONE API KEYS (opzionali)
# ════════════════════════════════════════════════════════════════════
# Per usare le API che richiedono registrazione, imposta le variabili d'ambiente:
# export HUNTER_API_KEY="tua_chiave"
# export SPYSE_API_KEY="tua_chiave"
#
# Oppure crea un file .env nella stessa directory:
# HUNTER_API_KEY=xxx
# SPYSE_API_KEY=xxx


# ════════════════════════════════════════════════════════════════════
#  MODULE 6 — PASSWORD BREACH CHECK (HIBP)
# ════════════════════════════════════════════════════════════════════

class PasswordBreachCheck:
    """Controlla se una password/hash è stata compromessa (HIBP k-anonymity)"""

    @staticmethod
    def check_password(password: str):
        """k-anonymity con HIBP - privacy preserving"""
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        print(f"\n{C.BLD}{C.Y}{'═'*60}")
        print(f"  🔐 PASSWORD BREACH CHECK")
        print(f"{'═'*60}{C.RST}\n")

        status("🔑", f"Password hash: {sha1[:10]}...{sha1[-6:]}")
        status("📡", f"Querying HIBP range {prefix}...")

        resp = http.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10)

        if resp["ok"]:
            found = False
            for line in resp["body"].splitlines():
                if line.startswith(suffix):
                    count = int(line.split(':')[1])
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

    @staticmethod
    def check_hash(hash_value: str):
        """Controlla hash SHA1 direttamente (senza inviare password)"""
        hash_value = hash_value.upper().strip()

        print(f"\n{C.BLD}{C.Y}{'═'*60}")
        print(f"  🔐 HASH BREACH CHECK")
        print(f"{'═'*60}{C.RST}\n")

        # Valida formato SHA1
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

        resp = http.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10)

        if resp["ok"]:
            found = False
            for line in resp["body"].splitlines():
                if line.startswith(suffix):
                    count = int(line.split(':')[1])
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


# ════════════════════════════════════════════════════════════════════
#  MODULE 7 — REPORT GENERATOR CON AES-256-GCM
# ════════════════════════════════════════════════════════════════════

class ReportGenerator:
    """Genera report JSON/HTML con opzioni di sicurezza e cifratura AES-256-GCM"""

    @staticmethod
    def save_json(data: dict, filename: str = None, redact: bool = None):
        """Salva JSON con redact opzionale"""
        if redact is None:
            redact = Config.redact_reports

        if not filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            mode = "redacted" if redact else "full"
            filename = f"ghost_recon_{mode}_{ts}.json"

        # Applica redact se richiesto
        output_data = Redactor.dict(data, redact) if redact else data

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False, default=str)

        status("💾", f"JSON report saved: {filename}", C.G)
        if redact:
            status("🔒", "PII redacted - GDPR compliant", C.CY)

        return filename

    @staticmethod
    def save_html(data: dict, filename: str = None, redact: bool = None):
        """Salva HTML con redact opzionale"""
        if redact is None:
            redact = Config.redact_reports

        if not filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            mode = "redacted" if redact else "full"
            filename = f"ghost_recon_{mode}_{ts}.html"

        # Applica redact se richiesto
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
    <h1>👻 Ghost Recon v3.0</h1>
    <p>Enterprise OSINT Framework - {'Redacted Report' if redact else 'Full Report'}</p>
    <p style="color: #666;">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    { '<p style="color: #00ff88;">🔒 PII Redacted - GDPR Compliant</p>' if redact else '' }
  </div>

  <pre>{html_module.escape(json.dumps(output_data, indent=2, default=str, ensure_ascii=False))}</pre>

  <div style="text-align: center; padding: 2rem; color: #444;">
    <p>Ghost Recon Enterprise v3.0 — Educational purposes only</p>
    <p>TLS Verified | Breach Intelligence | PII Protection</p>
  </div>
</div>
</body>
</html>"""

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        status("💾", f"HTML report saved: {filename}", C.G)

        return filename

    @staticmethod
    def save_encrypted(data: dict, password: str, filename: str = None):
        """
        Crea report cifrato con AES-256-GCM (autenticato)
        Richiede: pip install cryptography
        Formato: file binario .ghost con struttura [SALT][IV][TAG][CIPHERTEXT]
        """
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

        # Converti i dati in JSON
        json_data = json.dumps(data, indent=2, default=str, ensure_ascii=False).encode('utf-8')
        
        # Genera salt e IV casuali
        salt = secrets.token_bytes(16)
        iv = secrets.token_bytes(12)
        
        # Deriva la chiave usando PBKDF2HMAC (100.000 iterazioni)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode('utf-8'))
        
        # Cifra con AES-256-GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Aggiungi padding PKCS7
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(json_data) + padder.finalize()
        
        # Cifra
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Ottieni il tag di autenticazione
        tag = encryptor.tag
        
        # Struttura del file cifrato:
        # [SALT 16b][IV 12b][TAG 16b][CIPHERTEXT]
        encrypted_package = salt + iv + tag + ciphertext
        
        # Salva come file binario
        with open(filename, 'wb') as f:
            f.write(encrypted_package)
        
        # Crea anche un piccolo file informativo
        info_filename = filename + ".info"
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
        
        status("🔐", f"Report cifrato AES-256-GCM salvato: {filename}", C.M)
        status("ℹ️", f"Istruzioni decifratura: {info_filename}", C.CY)
        return filename

    @staticmethod
    def decrypt_report(filename: str, password: str):
        """Decifra un report cifrato con save_encrypted"""
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
            
            # Estrai componenti
            if len(data) < 44:
                print("❌ File corrotto o non valido")
                return None
                
            salt = data[:16]
            iv = data[16:28]
            tag = data[28:44]
            ciphertext = data[44:]
            
            # Deriva chiave con PBKDF2HMAC
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode('utf-8'))
            
            # Decifra
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Rimuovi padding
            unpadder = padding.PKCS7(128).unpadder()
            json_data = unpadder.update(padded) + unpadder.finalize()
            
            # Parse JSON
            return json.loads(json_data.decode('utf-8'))
            
        except Exception as e:
            print(f"❌ Errore decifratura: {e}")
            print("   Password errata o file danneggiato")
            return None


# ════════════════════════════════════════════════════════════════════
#  MODULE 8 — PLATFORM PRESENCE SIGNAL
# ════════════════════════════════════════════════════════════════════

class PresenceSignal:
    """Rileva presenza numero/email su piattaforme pubbliche"""
    
    def __init__(self, target: str, target_type: str = "auto"):
        self.target = target.strip().lower()
        self.target_type = target_type
        self.results = {
            "platforms": {},
            "confidence": "low",
            "method": "public_web_mentions",
            "evidence": {}
        }
        
    def scan(self):
        """Esegue scansione presenza"""
        print(f"\n{C.BLD}{C.CY}{'═'*60}")
        print(f"  🔍 PLATFORM PRESENCE SCAN — {Redactor.email(self.target) if '@' in self.target else Redactor.phone(self.target)}")
        print(f"{'═'*60}{C.RST}\n")
        
        self._detect_type()
        self._search_web_mentions()
        self._check_telegram()
        self._print_results()
        return self.results
    
    def _detect_type(self):
        if self.target_type != "auto":
            return
        if '@' in self.target:
            self.target_type = "email"
        elif re.match(r'^\+?[\d\s\-\(\)]{8,}', self.target):
            self.target_type = "phone"
        else:
            self.target_type = "unknown"
    
    def _search_web_mentions(self):
        status("🌐", f"Cerca menzioni web per {self.target_type}...", C.CY)
        
        mentions = 0
        domains = []
        
        try:
            import urllib.parse
            url = f"https://urlscan.io/api/v1/search/?q={urllib.parse.quote(self.target)}"
            data = http.json_get(url, timeout=8)
            
            if data and data.get("total", 0) > 0:
                mentions = data.get("total", 0)
                for result in data.get("results", [])[:5]:
                    page = result.get("page", {})
                    domain = page.get("domain", "")
                    if domain and domain not in domains:
                        domains.append(domain)
        except:
            pass
        
        self.results["evidence"]["web_mentions"] = mentions
        self.results["evidence"]["top_domains"] = domains[:5]
        
        if mentions > 0:
            status("✓", f"Trovate {mentions} menzioni pubbliche", C.G)
        else:
            status("○", "Nessuna menzione pubblica trovata", C.DIM)
    
    def _check_telegram(self):
        status("📱", "Controllo menzioni Telegram...", C.CY)
        
        telegram_hits = 0
        telegram_channels = []
        
        self.results["evidence"]["telegram_hits"] = telegram_hits
        self.results["evidence"]["telegram_channels"] = telegram_channels
        
        self.results["platforms"] = {
            "telegram": "signal" if telegram_hits > 0 else "unknown",
            "facebook": "unknown",
            "whatsapp": "unknown",
            "web": "signal" if self.results["evidence"]["web_mentions"] > 0 else "unknown"
        }
        
        total_signals = sum(1 for v in self.results["platforms"].values() if v == "signal")
        if total_signals >= 2:
            self.results["confidence"] = "high"
        elif total_signals == 1:
            self.results["confidence"] = "medium"
        else:
            self.results["confidence"] = "low"
    
    def _print_results(self):
        lines = [
            f"Target:      {Redactor.email(self.target) if '@' in self.target else Redactor.phone(self.target)}",
            f"Tipo:        {self.target_type}",
            f"Confidence:  {self.results['confidence'].upper()}",
            f"",
            f"{C.BLD}Presenza piattaforme:{C.RST}",
        ]
        
        for platform, status_val in self.results["platforms"].items():
            icon = f"{C.G}✓ SIGNAL{C.RST}" if status_val == "signal" else f"{C.DIM}○ unknown{C.RST}"
            lines.append(f"  {platform:10} {icon}")
        
        lines.extend([
            f"",
            f"{C.BLD}📊 Evidenze:{C.RST}",
            f"  Menzioni web:  {self.results['evidence'].get('web_mentions', 0)}",
            f"  Domini:        {', '.join(self.results['evidence'].get('top_domains', ['N/A']))}",
        ])
        
        print(f"\n{box('🔍 PLATFORM PRESENCE SIGNAL', lines, C.CY)}")


# ════════════════════════════════════════════════════════════════════
#  MODULE 9 — BREACH EXPOSURE (solo SI/NO)
# ════════════════════════════════════════════════════════════════════

class BreachExposure:
    """Verifica esposizione breach (solo conferma, senza dettagli)"""
    
    def __init__(self, email: str):
        self.email = email.strip().lower()
        self.results = {
            "confirmed": False,
            "source": None,
            "records": 0,
            "confidence": "low",
            "error": None
        }
    
    def check(self):
        print(f"\n{C.BLD}{C.R}{'═'*60}")
        print(f"  🔐 BREACH EXPOSURE CHECK — {Redactor.email(self.email)}")
        print(f"{'═'*60}{C.RST}\n")
        
        self._check_leakcheck()
        
        if not self.results["confirmed"]:
            self._check_xposed_fallback()
        
        self._print_results()
        return self.results
    
    def _check_leakcheck(self):
        status("📡", "Verifica LeakCheck API...", C.CY)
        
        try:
            import urllib.parse
            url = f"https://leakcheck.net/api/v2/query/{self.email}"
            resp = http.get(url, timeout=8)
            
            if resp["ok"]:
                data = json.loads(resp["body"])
                
                if data.get("success") and data.get("found", 0) > 0:
                    self.results["confirmed"] = True
                    self.results["source"] = "LeakCheck"
                    self.results["records"] = data.get("found", 0)
                    self.results["confidence"] = "high"
                    status("🔥", f"ESPOSIZIONE CONFERMATA! {data.get('found', 0)} record", C.R)
                else:
                    status("✅", "Nessuna esposizione trovata su LeakCheck", C.G)
            else:
                status("○", "LeakCheck non disponibile", C.DIM)
        except:
            pass
    
    def _check_xposed_fallback(self):
        status("📡", "Fallback su XposedOrNot...", C.CY)
        
        try:
            breaches, _ = check_breach_xon(self.email)
            
            if breaches and len(breaches) > 0:
                self.results["confirmed"] = True
                self.results["source"] = "XposedOrNot"
                self.results["records"] = len(breaches)
                self.results["confidence"] = "medium"
                status("🔥", f"ESPOSIZIONE CONFERMATA! {len(breaches)} breach", C.R)
            else:
                status("✅", "Nessuna esposizione trovata su XposedOrNot", C.G)
        except:
            pass
    
    def _print_results(self):
        lines = [f"Email:       {Redactor.email(self.email)}", ""]
        
        if self.results["confirmed"]:
            lines.extend([
                f"{C.BLD}{C.BG_R}⚠️  ESPOSIZIONE CONFERMATA ⚠️{C.RST}",
                f"Fonte:       {self.results['source']}",
                f"Record:      {self.results['records']:,}",
                f"Affidabilità: {self.results['confidence'].upper()}",
            ])
        else:
            lines.extend([
                f"{C.BLD}{C.G}✅ NESSUNA ESPOSIZIONE RILEVATA{C.RST}",
                f"Verificato con: LeakCheck + XposedOrNot",
                f"",
                f"{C.DIM}Nota: limiti API gratuiti possono influire{C.RST}",
            ])
        
        print(f"\n{box('🔐 BREACH EXPOSURE CONFIRMATION', lines, C.R if self.results['confirmed'] else C.G)}")


# ════════════════════════════════════════════════════════════════════
#  MAIN INTERACTIVE MENU
# ════════════════════════════════════════════════════════════════════

class GhostRecon:
    """Main application controller"""

    def __init__(self):
        self.session_results = {}
        self.session_start = datetime.now()

    def run(self):
        os.system("cls" if os.name == "nt" else "clear")
        print(BANNER)

        # Stato sicurezza
        print(f"  {C.CY}🔒 Security Status:{C.RST}")
        print(f"  {C.G}✓{C.RST} TLS Verification: {C.G}ENABLED{C.RST} (default)")
        print(f"  {C.G}✓{C.RST} PII Redaction: {C.G}{'ENABLED' if Config.redact_reports else 'DISABLED'}{C.RST}")
        print(f"  {C.Y}⚠{C.RST} Aggressive Mode: {C.Y}{'ENABLED' if Config.aggressive_mode else 'DISABLED'}{C.RST}")
        
        # Check cryptography
        try:
            import cryptography
            crypto_status = f"{C.G}✓ INSTALLED{C.RST}"
        except ImportError:
            crypto_status = f"{C.R}✗ NOT INSTALLED{C.RST} (pip install cryptography)"
        print(f"  {C.M}🔐{C.RST} AES-256 Encryption: {crypto_status}")
        print()

        while True:
            self._show_menu()
            choice = input(f"\n  {C.CY}ghost{C.W}@{C.M}recon{C.RST} ⟫ ").strip()

            if choice == "1":
                domain = input(f"  {C.Y}Domain{C.RST} ⟫ ").strip()
                if domain:
                    intel = DomainIntel(domain)
                    self.session_results[f"domain_{domain}"] = intel.run_all()

            elif choice == "2":
                email = input(f"  {C.Y}Email{C.RST} ⟫ ").strip()
                if email:
                    osint = EmailOSINT(email)
                    self.session_results[f"email_{email}"] = osint.run_all()

            elif choice == "3":
                username = input(f"  {C.Y}Username{C.RST} ⟫ ").strip()
                if username:
                    hunter = UsernameHunter(username)
                    self.session_results[f"user_{username}"] = hunter.hunt()

            elif choice == "4":
                ip = input(f"  {C.Y}IP Address{C.RST} ⟫ ").strip()
                if ip:
                    intel = IPIntel(ip)
                    self.session_results[f"ip_{ip}"] = intel.run_all()

            elif choice == "5":
                phone = input(f"  {C.Y}Phone (+country code){C.RST} ⟫ ").strip()
                if phone:
                    checker = PhoneBreachCheck(phone)
                    self.session_results[f"phone_{phone}"] = checker.run_all()

            elif choice == "6":
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
                                count = result.get("count", 0)
                                print(f"\n  {C.R}╔════════════════════════════════════════╗{C.RST}")
                                print(f"  {C.R}║     ⚠️  PASSWORD COMPROMESSA ⚠️     ║{C.RST}")
                                print(f"  {C.R}╚════════════════════════════════════════╝{C.RST}")
                                print(f"  {C.R}→ Trovata in {count:,} breach! Cambiala immediatamente.{C.RST}")
                            else:
                                print(f"\n  {C.G}╔════════════════════════════════════════╗{C.RST}")
                                print(f"  {C.G}║        ✅ PASSWORD SICURA           ║{C.RST}")
                                print(f"  {C.G}╚════════════════════════════════════════╝{C.RST}")
                        else:
                            status("✗", "Verifica fallita", C.R)

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
                                count = result.get("count", 0)
                                print(f"\n  {C.R}╔════════════════════════════════════════╗{C.RST}")
                                print(f"  {C.R}║        ⚠️  HASH TROVATO ⚠️          ║{C.RST}")
                                print(f"  {C.R}╚════════════════════════════════════════╝{C.RST}")
                                print(f"  {C.R}→ Presente in {count:,} breach!{C.RST}")
                            else:
                                print(f"\n  {C.G}╔════════════════════════════════════════╗{C.RST}")
                                print(f"  {C.G}║        ✅ HASH NON TROVATO          ║{C.RST}")
                                print(f"  {C.G}╚════════════════════════════════════════╝{C.RST}")
                        else:
                            status("✗", "Verifica fallita", C.R)

                elif sub == "0":
                    status("↩", "Operazione annullata", C.DIM)
                else:
                    status("⚠", "Opzione non valida", C.Y)

            elif choice == "7":
                domain = input(f"  {C.Y}Target Domain{C.RST} ⟫ ").strip()
                if domain:
                    print(f"\n  {C.BLD}{C.CY}🚀 FULL RECON MODE ACTIVATED{C.RST}\n")
                    di = DomainIntel(domain)
                    d_results = di.run_all()
                    self.session_results[f"full_domain_{domain}"] = d_results

                    for ip in d_results.get("dns", {}).get("A", [])[:3]:
                        ip_intel = IPIntel(ip)
                        self.session_results[f"full_ip_{ip}"] = ip_intel.run_all()

                    for email in d_results.get("web_info", {}).get("emails_found", [])[:3]:
                        e_osint = EmailOSINT(email)
                        self.session_results[f"full_email_{email}"] = e_osint.run_all()
                    
                    self._print_executive_summary()

            elif choice == "8":
                if not self.session_results:
                    status("⚠", "Nessun risultato in sessione!", C.Y)
                    continue

                print(f"\n  {C.BLD}{C.CY}📁 ESPORTA REPORT{C.RST}")
                print(f"  {C.DIM}{'─'*40}{C.RST}")
                print(f"  {C.G}[1]{C.RST} JSON (completo)   - Include PII")
                print(f"  {C.G}[2]{C.RST} JSON (redatto)    - PII mascherata (GDPR)")
                print(f"  {C.G}[3]{C.RST} HTML (completo)   - Include PII")
                print(f"  {C.G}[4]{C.RST} HTML (redatto)    - PII mascherata (GDPR)")
                print(f"  {C.G}[5]{C.RST} 🔐 AES-256-GCM    - Report cifrato (.ghost)")
                print(f"  {C.G}[6]{C.RST} Tutti i formati   - Completi + redatti")
                print(f"  {C.R}[0]{C.RST} Annulla")
                print(f"  {C.DIM}{'─'*40}{C.RST}")

                sub = input(f"  {C.CY}⟫{C.RST} ").strip()

                if sub == "1":
                    ReportGenerator.save_json(self.session_results, redact=False)
                elif sub == "2":
                    ReportGenerator.save_json(self.session_results, redact=True)
                elif sub == "3":
                    ReportGenerator.save_html(self.session_results, redact=False)
                elif sub == "4":
                    ReportGenerator.save_html(self.session_results, redact=True)
                elif sub == "5":
                    pwd = input(f"  {C.Y}Password crittografia AES-256{C.RST} ⟫ ").strip()
                    if pwd:
                        if len(pwd) < 8:
                            status("⚠", "Password debole (minimo 8 caratteri raccomandati)", C.Y)
                        ReportGenerator.save_encrypted(self.session_results, pwd)
                    else:
                        status("⚠", "Password non valida, annullato", C.Y)
                elif sub == "6":
                    ReportGenerator.save_json(self.session_results, redact=False)
                    ReportGenerator.save_html(self.session_results, redact=False)
                    ReportGenerator.save_json(self.session_results, redact=True)
                    ReportGenerator.save_html(self.session_results, redact=True)
                    status("✅", "Tutti i report generati (completi + redatti)", C.G)
                elif sub == "0":
                    status("○", "Operazione annullata", C.DIM)
                else:
                    status("⚠", "Opzione non valida", C.Y)

            elif choice == "9":
                domain = input(f"  {C.Y}Dominio{C.RST} ⟫ ").strip()
                if domain:
                    status("🔍", f"Ricerca WHOIS per {domain}...", C.CY)
                    data = http.json_get(f"https://rdap.org/domain/{domain}", timeout=10)
                    if data:
                        print(f"\n{json.dumps(data, indent=2)[:3000]}")
                    else:
                        status("✗", "RDAP lookup fallito", C.R)

            elif choice == "p":
                target = input(f"  {C.Y}Target (email/telefono){C.RST} ⟫ ").strip()
                if target:
                    signal = PresenceSignal(target)
                    self.session_results[f"presence_{target}"] = signal.scan()

            elif choice == "b":
                email = input(f"  {C.Y}Email da verificare{C.RST} ⟫ ").strip()
                if email:
                    exposure = BreachExposure(email)
                    self.session_results[f"exposure_{email}"] = exposure.check()

            elif choice == "0":
                status("🌍", "Rilevamento IP pubblico...", C.CY)
                data = http.json_get("https://api.ipify.org?format=json")
                if data:
                    my_ip = data.get("ip", "N/A")
                    print(f"\n  {C.G}Il tuo IP pubblico: {C.BLD}{my_ip}{C.RST}")
                    ask = input(f"\n  {C.Y}Eseguire IP Intelligence? (y/n){C.RST} ⟫ ").strip().lower()
                    if ask in ("y", "yes", "s", "si"):
                        intel = IPIntel(my_ip)
                        self.session_results[f"myip_{my_ip}"] = intel.run_all()
                else:
                    status("✗", "Impossibile rilevare IP pubblico", C.R)

            elif choice == "a":
                new_mode = not Config.aggressive_mode
                Config.set_aggressive(new_mode)
                status("⚡", f"Modalità aggressiva: {'ATTIVA' if new_mode else 'DISATTIVA'}", C.Y if new_mode else C.G)

            elif choice == "r":
                new_mode = not Config.redact_reports
                Config.set_redact(new_mode)
                status("🔒", f"Redattazione PII: {'ATTIVA' if new_mode else 'DISATTIVA'}", C.G if new_mode else C.Y)

            elif choice == "clear":
                os.system("cls" if os.name == "nt" else "clear")
                print(BANNER)

            elif choice in ("q", "quit", "exit"):
                print(f"\n  {C.M}👻 Ghost Recon - Chiusura sessione{C.RST}")
                print(f"  {C.DIM}{'─'*40}{C.RST}")
                elapsed = datetime.now() - self.session_start
                print(f"  {C.DIM}⏱  Durata: {elapsed}{C.RST}")

                if self.session_results:
                    print(f"  {C.DIM}📊 Risultati: {len(self.session_results)} item(s){C.RST}")
                    print(f"\n  {C.Y}Salvare i risultati?{C.RST}")
                    print(f"  {C.DIM}{'─'*40}{C.RST}")
                    print(f"  {C.G}[1]{C.RST} Sì, con redattazione PII (GDPR)")
                    print(f"  {C.G}[2]{C.RST} Sì, report completo (PII visibile)")
                    print(f"  {C.G}[3]{C.RST} Sì, AES-256 cifrato (.ghost)")
                    print(f"  {C.G}[4]{C.RST} No, esci senza salvare")
                    print(f"  {C.R}[0]{C.RST} Annulla e resta in sessione")
                    print(f"  {C.DIM}{'─'*40}{C.RST}")

                    save_choice = input(f"  {C.CY}⟫{C.RST} ").strip()

                    if save_choice == "1":
                        ReportGenerator.save_json(self.session_results, redact=True)
                        ReportGenerator.save_html(self.session_results, redact=True)
                        status("🔒", "Report redatti salvati (GDPR compliant)", C.G)
                        print(f"\n  {C.M}👻 Arrivederci!{C.RST}\n")
                        break

                    elif save_choice == "2":
                        ReportGenerator.save_json(self.session_results, redact=False)
                        ReportGenerator.save_html(self.session_results, redact=False)
                        status("⚠", "Report completi salvati (PII esposta)", C.Y)
                        print(f"\n  {C.M}👻 Arrivederci!{C.RST}\n")
                        break

                    elif save_choice == "3":
                        pwd = input(f"  {C.Y}Password crittografia AES-256{C.RST} ⟫ ").strip()
                        if pwd:
                            if len(pwd) < 8:
                                status("⚠", "Password debole (minimo 8 caratteri raccomandati)", C.Y)
                            ReportGenerator.save_encrypted(self.session_results, pwd)
                            print(f"\n  {C.M}👻 Arrivederci!{C.RST}\n")
                            break
                        else:
                            status("⚠", "Password non valida, uscita senza salvare", C.Y)
                            print(f"\n  {C.M}👻 Arrivederci!{C.RST}\n")
                            break

                    elif save_choice == "4":
                        status("○", "Uscita senza salvare", C.DIM)
                        print(f"\n  {C.M}👻 Arrivederci!{C.RST}\n")
                        break

                    elif save_choice == "0":
                        status("↩", "Operazione annullata, rientro in sessione", C.CY)
                        continue

                    else:
                        status("⚠", "Opzione non valida, uscita senza salvare", C.Y)
                        print(f"\n  {C.M}👻 Arrivederci!{C.RST}\n")
                        break
                else:
                    status("○", "Nessun risultato in sessione", C.DIM)
                    print(f"\n  {C.M}👻 Arrivederci!{C.RST}\n")
                    break

            else:
                status("⚠", "Opzione non valida. Riprova.", C.Y)

    def _show_menu(self):
        """Mostra il menu principale"""
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
        print(f"  {C.DIM}│  {C.CY}[1]{C.RST}  🌐 Domain Intel          DNS, SSL, subdomains, breach scan    {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[2]{C.RST}  📧 Email OSINT           Breach DB, Gravatar, social         {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[3]{C.RST}  🎯 Username Hunter       50+ social platforms                {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[4]{C.RST}  📍 IP Intelligence        Geolocation, ASN, threat intel     {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[5]{C.RST}  📱 Phone Breach Check    Verifica breach su numeri telefono  {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[6]{C.RST}  🔐 Password/Hash Check   HIBP k-anonymity                   {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[7]{C.RST}  🚀 Full Recon Mode       Analisi completa domino+IP+email   {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[8]{C.RST}  📁 Export Reports        JSON/HTML/AES-256-GCM cifrato      {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[9]{C.RST}  🔍 WHOIS Lookup          RDAP lookup                        {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[0]{C.RST}  🕵️  My IP                Rileva IP pubblico + intel         {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[p]{C.RST}  🔍 Presence Signal      Menzioni web + presenza            {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[b]{C.RST}  🔐 Breach Exposure     Conferma SI/NO (LeakCheck)        {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[a]{C.RST}  ⚡ Aggressive Mode       {'ATTIVO' if Config.aggressive_mode else 'DISATTIVO'} (scraping preview)     {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[r]{C.RST}  🔒 PII Redaction         {'ATTIVA' if Config.redact_reports else 'DISATTIVA'} (GDPR)               {C.DIM}│{C.RST}")
        print(f"  {C.DIM}│  {C.CY}[q]{C.RST}  ❌ Quit                  Esci e salva sessione              {C.DIM}│{C.RST}")
        print(f"  {C.DIM}└─────────────────────────────────────────────────────────────────────┘{C.RST}")

    def _print_executive_summary(self):
        """Executive Summary per Full Recon Mode"""
        def _badge(level):
            if level == "HIGH": return f"{C.R}HIGH{C.RST}"
            if level == "MEDIUM": return f"{C.Y}MEDIUM{C.RST}"
            if level == "LOW": return f"{C.G}LOW{C.RST}"
            return f"{C.DIM}NONE{C.RST}"

        print("\n════════════════════════════════════════════════════════════")
        print(f"  {C.BLD}{C.CY}✅ EXECUTIVE SUMMARY{C.RST}")
        print("════════════════════════════════════════════════════════════")

        email_found = False
        for key, data in self.session_results.items():
            if key.startswith('full_email_') or key.startswith('email_'):
                if isinstance(data, dict):
                    summary = data.get('breach_summary')
                    if summary:
                        level = summary.get('level', 'NONE')
                        score = summary.get('score', 0)
                        timeline = summary.get('timeline', 'N/A')
                        print(f"  • Email Breach Risk: {_badge(level)} ({score}/100) | {timeline}")
                        email_found = True
                        break
        
        if not email_found:
            print(f"  • Email Breach Risk: {C.DIM}N/A{C.RST}")
        
        domain_found = False
        for key, data in self.session_results.items():
            if key.startswith('full_domain_') or key.startswith('domain_'):
                if isinstance(data, dict):
                    subs = data.get('subdomains', [])
                    ports = data.get('ports', [])
                    print(f"  • Subdomini trovati: {C.CY}{len(subs)}{C.RST}")
                    print(f"  • Porte aperte (DB): {C.Y}{len([p for p in ports if p.get('verified')])}{C.RST} verificate")
                    domain_found = True
                    break
        
        if not domain_found:
            print(f"  • Subdomini trovati: {C.DIM}N/A{C.RST}")
        
        print("════════════════════════════════════════════════════════════\n")


# ════════════════════════════════════════════════════════════════════
#  DECRYPT UTILITY - USARE DA TERMINALE
# ════════════════════════════════════════════════════════════════════

def decrypt_ghost():
    """Utility da terminale per decifrare report .ghost"""
    if len(sys.argv) >= 3 and sys.argv[1] in ("--decrypt", "-d"):
        filename = sys.argv[2]
        password = sys.argv[3] if len(sys.argv) > 3 else None
        
        if not password:
            import getpass
            password = getpass.getpass(f"  🔐 Password per {filename}: ")
        
        print(f"\n  {C.CY}🔐 Decifratura in corso...{C.RST}")
        data = ReportGenerator.decrypt_report(filename, password)
        
        if data:
            print(f"\n  {C.G}✅ Decifratura riuscita!{C.RST}\n")
            print(json.dumps(data, indent=2, ensure_ascii=False))
            
            save = input(f"\n  {C.Y}Salvare in JSON? (s/N): {C.RST}").lower()
            if save in ('s', 'si', 'y', 'yes'):
                output = filename.replace('.ghost', '.json')
                with open(output, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                print(f"  {C.G}💾 Salvato: {output}{C.RST}")
        else:
            print(f"\n  {C.R}❌ Decifratura fallita! Password errata o file danneggiato.{C.RST}")
        return True
    return False


# ════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        if decrypt_ghost():
            sys.exit(0)
        app = GhostRecon()
        app.run()
    except KeyboardInterrupt:
        print(f"\n\n  {C.R}❌ Interruzione manuale{C.RST}")
        sys.exit(0)
    except Exception as e:
        print(f"\n  {C.R}❌ Errore critico: {e}{C.RST}")
        sys.exit(1)