#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
websect.py - single-file real-time web penetration test harness.

Install once:  pip install requests
Run:           python3 websect.py https://your-site.tld
Full run:      python3 websect.py https://your-site.tld --full --ports full
"""
from __future__ import annotations   # keep this as the first statement after the docstring

import argparse
import concurrent.futures as cf
import html
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse as up
from collections import Counter
from datetime import datetime

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.exit("[!] missing dependency -> pip install requests")

UA       = "Mozilla/5.0 (compatible; websect/1.0)"
TIMEOUT  = 8.0
VERIFY   = True
FINDINGS: list[dict] = []
LOCK     = threading.Lock()
T0       = time.time()

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
COLOR = {"critical": "\033[1;91m", "high": "\033[91m", "medium": "\033[93m",
         "low": "\033[94m", "info": "\033[90m"}
RESET = "\033[0m"


# ----------------------------------------------------------------------------- output
def say(msg: str) -> None:
    print(f"\n\033[1m[*] {msg}\033[0m", flush=True)


def add(sev: str, title: str, category: str, endpoint: str = "",
        evidence: str = "", fix: str = "") -> None:
    f = {"sev": sev, "title": title, "category": category, "endpoint": endpoint,
         "evidence": evidence.strip()[:2000], "fix": fix,
         "time": datetime.now().isoformat(timespec="seconds")}
    with LOCK:
        FINDINGS.append(f)
    print(f"  {COLOR[sev]}[{sev.upper():8}]{RESET} {title}", flush=True)
    if evidence:
        for line in evidence.strip().splitlines()[:6]:
            print(f"             {line[:160]}", flush=True)


def req(s: requests.Session, method: str, url: str, **kw):
    kw.setdefault("timeout", TIMEOUT)
    kw.setdefault("allow_redirects", True)
    try:
        return s.request(method, url, **kw)
    except requests.RequestException:
        return None


# ----------------------------------------------------------------------------- recon
def normalise(raw: str):
    if not re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I):
        raw = "https://" + raw
    p = up.urlsplit(raw)
    scheme = (p.scheme or "https").lower()
    host = p.hostname or ""
    port = p.port or (443 if scheme == "https" else 80)
    netloc = host if port in (80, 443) else f"{host}:{port}"
    return scheme, host, port, f"{scheme}://{netloc}"


def dns_phase(host: str):
    say(f"DNS resolution: {host}")
    try:
        ips = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except socket.gaierror as e:
        add("info", "Target does not resolve", "dns", host, str(e))
        return []
    for ip in ips:
        try:
            ptr = socket.gethostbyaddr(ip)[0]
        except Exception:
            ptr = "-"
        print(f"  {ip:39} ptr={ptr}", flush=True)
    add("info", "Resolved addresses", "dns", host, "\n".join(ips))
    return ips


TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
             636, 993, 995, 1433, 1521, 2049, 2082, 2083, 2181, 2375, 2376, 3000,
             3306, 3389, 4443, 5000, 5432, 5601, 5672, 5900, 5984, 6379, 6443,
             7001, 8000, 8008, 8009, 8080, 8081, 8088, 8180, 8443, 8888, 9000,
             9090, 9200, 9443, 10000, 11211, 27017]

SERVICE = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
           110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
           443: "https", 445: "smb", 465: "smtps", 587: "submission", 636: "ldaps",
           993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
           2375: "docker", 2376: "docker-tls", 3000: "http-alt", 3306: "mysql",
           3389: "rdp", 4443: "https-alt", 5000: "http-alt", 5432: "postgres",
           5601: "kibana", 5672: "amqp", 5900: "vnc", 5984: "couchdb",
           6379: "redis", 6443: "k8s-api", 7001: "weblogic", 8000: "http-alt",
           8008: "http-alt", 8009: "ajp", 8080: "http-proxy", 8081: "http-alt",
           8088: "http-alt", 8180: "http-alt", 8443: "https-alt", 8888: "http-alt",
           9000: "http-alt", 9090: "http-alt", 9200: "elasticsearch",
           9443: "https-alt", 10000: "webmin", 11211: "memcached", 27017: "mongodb"}

HTTP_PORTS = set(TOP_PORTS) & {80, 81, 443, 2082, 2083, 2375, 3000, 4443, 5000,
                               7001, 8000, 8008, 8009, 8080, 8081, 8088, 8180,
                               8443, 8888, 9000, 9090, 9443}
TLS_PORTS = {443, 4443, 465, 636, 993, 995, 2083, 5061, 8443, 9443}
RISKY_PORTS = {21: "FTP (cleartext creds)", 23: "Telnet (cleartext)", 445: "SMB",
               2375: "Docker API unauthenticated", 3306: "MySQL exposed",
               5432: "PostgreSQL exposed", 6379: "Redis exposed",
               9200: "Elasticsearch exposed", 11211: "memcached exposed",
               27017: "MongoDB exposed", 5900: "VNC exposed",
               1433: "MSSQL exposed", 2049: "NFS exposed"}


def _scan_port(ip, port, timeout):
    t = time.time()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return port, int((time.time() - t) * 1000)
    except OSError:
        return None


def port_phase(ip, ports, threads):
    say(f"TCP connect scan: {ip} ({len(ports)} ports)")
    open_ports = []
    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(_scan_port, ip, p, min(TIMEOUT, 5)) for p in ports]
        for fut in cf.as_completed(futs):
            res = fut.result()
            if res:
                port, ms = res
                svc = SERVICE.get(port, "?")
                print(f"  open {port:5}/tcp  {svc:14} {ms}ms", flush=True)
                open_ports.append(res)
                if port in RISKY_PORTS:
                    add("medium", f"Sensitive service exposed: {RISKY_PORTS[port]}",
                        "ports", f"{ip}:{port}", f"port {port}/tcp open", 
                        "Restrict to management VLAN / firewall rule, require auth+TLS.")
    return sorted(p for p, _ in open_ports)


def banner_of(ip, port, host, timeout=3.0):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        if port in TLS_PORTS:
            s = ssl._create_unverified_context().wrap_socket(s)
        if port in HTTP_PORTS:
            s.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = s.recv(2048)
        s.close()
    except Exception:
        return ""
    txt = data.decode("utf-8", "ignore")
    line = txt.splitlines()[0].strip() if txt.strip() else ""
    for l in txt.splitlines()[1:10]:
        if l.lower().startswith("server:"):
            line += " | " + l.strip()
            break
    return line[:180]


# ----------------------------------------------------------------------------- TLS
def _proto(host, port, ver):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ctx.maximum_version = ver
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return ss.version(), ss.cipher()[0]
    except Exception:
        return None


def tls_phase(host, port):
    say(f"TLS audit: {host}:{port}")
    cert, proto, cipher, err = None, None, None, None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert, proto, cipher = ss.getpeercert(), ss.version(), ss.cipher()[0]
    except ssl.SSLCertVerificationError as e:
        err = getattr(e, "verify_message", str(e))
    except Exception as e:
        print(f"  !! TLS handshake failed: {e}")
        return

    if cert is None:                       # read the cert anyway to report details
        try:
            uctx = ssl._create_unverified_context()
            with socket.create_connection((host, port), timeout=8) as sock:
                with uctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert, proto, cipher = ss.getpeercert(), ss.version(), ss.cipher()[0]
        except Exception:
            return
        add("high", "Invalid TLS certificate", "tls", f"{host}:{port}", err or "verification failed",
            "Renew/fix the chain; keep the hostname inside the SAN list.")

    subj = dict(x[0] for x in cert.get("subject", []))
    issr = dict(x[0] for x in cert.get("issuer", []))
    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
    not_after = cert.get("notAfter", "")
    days = None
    try:
        days = int((ssl.cert_time_to_seconds(not_after) - time.time()) / 86400)
    except Exception:
        pass
    print(f"  protocol={proto} cipher={cipher}")
    print(f"  subject={subj.get('commonName')}  issuer={issr.get('organizationName')}")
    print(f"  expires={not_after} ({days} days)  SANs={', '.join(sans[:6])}")
    add("info", "TLS certificate", "tls", f"{host}:{port}",
        f"proto={proto} cipher={cipher}\nsubject={subj.get('commonName')}\n"
        f"issuer={issr.get('organizationName')}\nexpires={not_after} ({days}d)\n"
        f"SANs={', '.join(sans)}")
    if days is not None and days < 0:
        add("high", "TLS certificate expired", "tls", host, not_after, "Renew now.")
    elif days is not None and days < 21:
        add("medium", "TLS certificate expiring soon", "tls", host, f"{days} days left",
            "Automate renewal (ACME).")

    weak = []
    for label, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        if hasattr(ssl.TLSVersion, ver.name) and _proto(host, port, ver):
            weak.append(label)
    if weak:
        add("medium", f"Deprecated TLS version(s) accepted: {', '.join(weak)}", "tls",
            f"{host}:{port}", "server negotiates " + ", ".join(weak),
            "Require TLS 1.2+ (ideally 1.3) and disable legacy protocols.")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=0:RC4-SHA:3DES")
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                c = ss.cipher()
                if c and any(x in c[0].upper() for x in ("RC4", "3DES", "DES", "NULL", "EXPORT")):
                    add("medium", f"Legacy cipher negotiated: {c[0]}", "tls", f"{host}:{port}",
                        str(c), "Prefer AEAD suites (ECDHE-*-GCM / CHACHA20).")
    except Exception:
        pass


# ----------------------------------------------------------------------------- HTTP
SEC_HEADERS = {
    "strict-transport-security": ("Strict-Transport-Security", "medium",
        "Add: max-age=31536000; includeSubDomains; preload"),
    "content-security-policy": ("Content-Security-Policy", "medium",
        "Deploy a restrictive CSP, avoid 'unsafe-inline' and wildcard script-src"),
    "x-content-type-options": ("X-Content-Type-Options", "low", "Add: nosniff"),
    "x-frame-options": ("X-Frame-Options", "low", "Add: DENY or SAMEORIGIN (or use CSP frame-ancestors)"),
    "referrer-policy": ("Referrer-Policy", "low", "Add: strict-origin-when-cross-origin"),
    "permissions-policy": ("Permissions-Policy", "info", "Restrict camera/mic/geo APIs"),
    "cross-origin-opener-policy": ("Cross-Origin-Opener-Policy", "info", "Add: same-origin"),
}


def http_phase(base, s, scheme):
    say(f"HTTP fingerprint: {base}")
    r = req(s, "GET", base)
    if r is None:
        add("medium", "Base URL not reachable", "http", base, "connection/ TLS error",
            "Check service availability and TLS config.")
        return None
    print(f"  status={r.status_code}  final={r.url}  bytes={len(r.content)}  "
          f"ttfb={r.elapsed.total_seconds():.3f}s")
    for h in ("Server", "X-Powered-By", "Via", "X-Generator", "X-AspNet-Version",
              "X-Drupal-Cache", "X-Runtime", "CF-RAY"):
        if h in r.headers:
            print(f"  {h}: {r.headers[h]}")
    tech = [f"{k}: {v}" for k, v in r.headers.items()
            if k.lower() in ("server", "x-powered-by", "x-generator", "x-aspnet-version")]
    add("info", "HTTP fingerprint", "http", base,
        "\n".join(tech) or f"status={r.status_code}")

    # --- security headers
    missing = []
    for key, (hname, sev, fix) in SEC_HEADERS.items():
        if key == "strict-transport-security" and scheme != "https":
            continue
        if key not in {h.lower() for h in r.headers}:
            missing.append(hname)
            add(sev, f"Missing security header: {hname}", "headers", base, f"absent on {r.url}", fix)

    # --- cookie flags
    raw_cookies = []
    try:
        raw_cookies = r.raw.headers.getlist("Set-Cookie")
    except Exception:
        if "Set-Cookie" in r.headers:
            raw_cookies = [r.headers["Set-Cookie"]]
    for c in raw_cookies:
        name = c.split("=")[0].strip()
        low = c.lower()
        problems = [p for p, cond in
                    (("Secure", "secure" not in low), ("HttpOnly", "httponly" not in low),
                     ("SameSite", "samesite" not in low)) if cond]
        if problems:
            add("medium", f"Cookie '{name}' missing flag(s): {', '.join(problems)}", "cookies",
                base, c[:200], "Set Secure; HttpOnly; SameSite=Lax/Strict on session cookies.")

    # --- HTTP -> HTTPS redirect
    if scheme == "https":
        plain = "http://" + base.split("://", 1)[1]
        rp = req(s, "GET", plain, allow_redirects=False)
        if rp is not None and not (300 <= rp.status_code < 400 and
                                   rp.headers.get("Location", "").startswith("https://")):
            add("medium", "HTTP does not redirect to HTTPS", "tls", plain,
                f"status={rp.status_code} Location={rp.headers.get('Location','-')}",
                "Return 301 to the HTTPS origin.")

    # --- methods
    say("HTTP method handling")
    ro = req(s, "OPTIONS", base)
    allow = ro.headers.get("Allow", "") if ro else ""
    print(f"  Allow: {allow or '(not advertised)'}")
    if allow:
        add("info", "Advertised HTTP methods", "http", base, allow)
        for m in ("PUT", "DELETE", "PATCH", "PROPFIND"):
            if m in allow.upper():
                add("low", f"Write method advertised: {m}", "http", base, allow,
                    "Confirm authorization checks on write methods, disable if unused.")
    rt = req(s, "TRACE", base)
    if rt is not None and rt.status_code < 400 and re.search(r"TRACE .* HTTP/", rt.text, re.I):
        add("medium", "HTTP TRACE enabled (Cross-Site Tracing)", "http", base,
            rt.text[:160], "Disable TraceEnable / limit methods.")

    # --- CORS
    origin = "https://hqx7z.example"
    rc = req(s, "GET", base, headers={"Origin": origin})
    if rc is not None:
        acao = rc.headers.get("Access-Control-Allow-Origin", "")
        acac = rc.headers.get("Access-Control-Allow-Credentials", "").lower()
        if acao == origin and acac == "true":
            add("high", "CORS reflects arbitrary origin with credentials", "cors", base,
                f"ACAO={acao} ACAC={acac}", "Whitelist trusted origins explicitly.")
        elif acao == origin:
            add("medium", "CORS reflects arbitrary origin", "cors", base,
                f"ACAO={acao}", "Whitelist trusted origins explicitly.")
        elif acao == "*":
            add("info", "CORS wildcard", "cors", base, "ACAO=*",
                "Acceptable for public data only.")

    # --- host header injection
    rh = req(s, "GET", base, headers={"Host": "hqx7z.example"})
    if rh is not None:
        loc = rh.headers.get("Location", "")
        if "hqx7z.example" in rh.text or "hqx7z.example" in loc:
            add("medium", "Host header reflected (cache poison / reset-poison risk)", "http",
                base, f"Location={loc or '-'}", "Validate Host against an allow-list.")

    # --- robots / sitemap
    say("robots.txt / sitemap.xml")
    extra_paths = []
    rr = req(s, "GET", base + "/robots.txt")
    if rr is not None and rr.status_code == 200 and "user-agent" in rr.text.lower():
        dis = re.findall(r"(?im)^\s*Disallow:\s*(\S+)", rr.text)
        print(f"  robots.txt found, {len(dis)} Disallow rules")
        add("info", "robots.txt discloses paths", "recon", base + "/robots.txt",
            "\n".join(dis[:40]), "Do not rely on robots.txt for access control.")
        extra_paths = [d.strip("/") for d in dis if d.strip() and d.strip() != "/"]
    for sm in ("/sitemap.xml", "/sitemap_index.xml"):
        rs = req(s, "GET", base + sm)
        if rs is not None and rs.status_code == 200 and "<" in rs.text[:200]:
            print(f"  {sm} found")
            add("info", f"{sm} present", "recon", base + sm, rs.text[:200])
    return extra_paths


DIRS = ["admin", "administrator", "login", "logout", "dashboard", "wp-admin",
        "wp-login.php", "wp-json/wp/v2/users", "api", "api/v1", "api/v2", "graphql",
        "swagger", "swagger-ui", "swagger.json", "openapi.json", "docs", "redoc",
        "backup", "backups", "uploads", "files", "static", "assets", "media",
        "phpinfo.php", "info.php", "console", "actuator", "actuator/health",
        "actuator/env", "debug", "test", "tests", "dev", "staging", "old", "tmp",
        "db", "database", "sql", "logs", "log", "config", "conf", "private",
        "secure", "cgi-bin", "vendor", ".well-known/security.txt",
        ".well-known/change-password", "crossdomain.xml", "server-status",
        "server-info", "metrics", "health", "status", "version", "robots.txt"]

SENSITIVE = {
    ".git/HEAD": ("high", "Exposed .git repository (full source recovery)"),
    ".git/config": ("high", "Exposed .git/config"),
    ".env": ("critical", "Exposed .env with secrets / DB credentials"),
    ".env.local": ("critical", "Exposed .env.local"),
    ".svn/entries": ("medium", "Exposed Subversion metadata"),
    ".DS_Store": ("low", "Exposed .DS_Store (file name disclosure)"),
    ".htaccess": ("low", "Readable .htaccess"),
    "wp-config.php.bak": ("high", "Backup of wp-config.php"),
    "config.php.bak": ("high", "Backup of config.php"),
    "web.config": ("medium", "Readable web.config"),
    "backup.zip": ("high", "Downloadable backup archive"),
    "backup.sql": ("high", "Downloadable SQL dump"),
    "db.sql": ("high", "Downloadable SQL dump"),
    "dump.sql": ("high", "Downloadable SQL dump"),
    "server-status": ("medium", "Apache mod_status exposed"),
    "phpinfo.php": ("medium", "phpinfo() exposed (env/paths disclosure)"),
    "actuator/env": ("high", "Spring Boot actuator /env exposed"),
    "actuator/health": ("low", "Actuator health endpoint exposed"),
    "swagger.json": ("low", "API schema exposed"),
    "openapi.json": ("low", "API schema exposed"),
    "package.json": ("low", "package.json readable"),
    "composer.json": ("low", "composer.json readable"),
    "metrics": ("low", "Metrics endpoint exposed"),
}


def dir_phase(base, extra, threads):
    say("Content discovery")
    probe = f"{base}/hqx7z{int(time.time())}"
    try:
        b = requests.get(probe, timeout=TIMEOUT, headers={"User-Agent": UA},
                         verify=VERIFY, allow_redirects=False)
        b_status, b_len = b.status_code, len(b.content)
    except requests.RequestException:
        b_status, b_len = 404, 0

    candidates = list(dict.fromkeys(list(SENSITIVE) + DIRS + list(extra)))

    def check(path):
        url = f"{base}/{path.lstrip('/')}"
        try:
            r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": UA},
                             verify=VERIFY, allow_redirects=False)
        except requests.RequestException:
            return None
        if r.status_code == 404:
            return None
        if r.status_code == b_status and abs(len(r.content) - b_len) < 40:
            return None                     # soft-404
        return path, r.status_code, len(r.content), url, r.text[:400]

    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        for res in ex.map(check, candidates):
            if not res:
                continue
            path, code, size, url, body = res
            if path in SENSITIVE:
                sev, title = SENSITIVE[path]
            elif code in (401, 403):
                sev, title = "low", f"Protected path discovered: /{path}"
            elif code in (301, 302):
                sev, title = "info", f"Redirecting path: /{path}"
            else:
                sev, title = "info", f"Path discovered: /{path}"
            print(f"  {code} {url} ({size}b)", flush=True)
            add(sev, title, "discovery", url, f"status={code} size={size}\n{body[:200]}",
                "Remove or protect unintended content; block dotfiles in the web server.")


# ----------------------------------------------------------------------------- crawl
class Point:
    def __init__(self, url, method, params, name):
        self.url, self.method, self.params, self.name = url, method, dict(params), name

    def send(self, s, value):
        p = dict(self.params)
        p[self.name] = value
        if self.method == "GET":
            sp = up.urlsplit(self.url)
            q = up.urlencode(p, doseq=True)
            return req(s, "GET", up.urlunsplit((sp.scheme, sp.netloc, sp.path, q, "")))
        return req(s, "POST", self.url, data=p)

    def label(self):
        return f"{self.method} {self.url} [{self.name}]"


def crawl(base, s, max_pages=30):
    say(f"Crawling {base} (max {max_pages} pages)")
    host = up.urlsplit(base).netloc
    seen, queue, param_urls, forms = set(), [(base, 0)], {}, []
    while queue and len(seen) < max_pages:
        url, depth = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        r = req(s, "GET", url)
        if r is None or "html" not in r.headers.get("Content-Type", "").lower():
            continue
        sp0 = up.urlsplit(url)
        if sp0.query:
            param_urls[url] = list(up.parse_qs(sp0.query, keep_blank_values=True))
        for m in re.finditer(r"""href\s*=\s*["']([^"'#]+)""", r.text, re.I):
            link = up.urljoin(url, m.group(1))
            sp = up.urlsplit(link)
            if sp.netloc != host:
                continue
            if re.search(r"\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map|pdf|zip|mp4)$",
                         sp.path, re.I):
                continue
            clean = up.urlunsplit((sp.scheme, sp.netloc, sp.path, sp.query, ""))
            if up.parse_qs(sp.query):
                param_urls.setdefault(clean, list(up.parse_qs(sp.query)))
                if clean not in seen:
                    queue.append((clean, depth))
            elif depth < 2 and clean not in seen:
                queue.append((clean, depth + 1))
        for fm in re.finditer(r"<form\b.*?</form>", r.text, re.I | re.S):
            block = fm.group(0)
            action = re.search(r'action\s*=\s*["\']([^"\']*)', block, re.I)
            method = "POST" if re.search(r'method\s*=\s*["\']?post', block, re.I) else "GET"
            fields = re.findall(r'<(?:input|textarea|select)[^>]*name\s*=\s*["\']([^"\']+)', block, re.I)
            if fields:
                forms.append({"action": up.urljoin(url, action.group(1)) if action else url,
                              "method": method, "fields": fields})
    print(f"  pages={len(seen)} param_urls={len(param_urls)} forms={len(forms)}")
    return param_urls, forms


SQL_ERRORS = ["you have an error in your sql syntax", "warning: mysqli", "warning: mysql",
              "unclosed quotation mark", "quoted string not properly terminated",
              "pg_query()", "postgresql query failed", "ora-0", "oracle error",
              "sqlite3::", "sqlite error", "microsoft ole db", "odbc sql server",
              "syntax error at or near", "division by zero", "unknown column",
              "incorrect syntax near", "mysqli_sql_exception"]
REDIRECT_NAMES = {"url", "uri", "redirect", "redirect_uri", "redirect_url", "next",
                  "return", "returnurl", "return_url", "dest", "destination", "goto",
                  "continue", "callback", "target", "r", "u", "link", "out", "view"}
LFI_NAMES = {"file", "filename", "filepath", "path", "page", "include", "inc",
             "view", "template", "tpl", "doc", "document", "folder", "root", "pg", "load"}


def build_points(param_urls, forms, limit=20):
    pts = []
    for url, names in list(param_urls.items())[:limit]:
        sp = up.urlsplit(url)
        q = {k: (v[0] if v else "") for k, v in
             up.parse_qs(sp.query, keep_blank_values=True).items()}
        base = up.urlunsplit((sp.scheme, sp.netloc, sp.path, "", ""))
        for n in names:
            pts.append(Point(base, "GET", q, n))
    for f in forms[:limit]:
        for n in f["fields"]:
            pts.append(Point(f["action"], f["method"], {x: "" for x in f["fields"]}, n))
    return pts


def test_sqli(pt, s):
    r0 = pt.send(s, "hqx7z1")
    if r0 is None:
        return
    for payload in ("'", '"', "')", "';", "\\"):
        r = pt.send(s, "hqx7z1" + payload)
        if r is None:
            continue
        low = r.text.lower()
        for sig in SQL_ERRORS:
            if sig in low:
                add("high", f"SQL injection (error-based) - parameter '{pt.name}'", "sqli",
                    pt.label(), f"payload={payload!r} -> DB error: '{sig}'",
                    "Use parameterised queries / prepared statements.")
                return
    t, f = pt.send(s, "1' AND '1'='1"), pt.send(s, "1' AND '1'='2")
    if t is not None and f is not None and t.status_code == f.status_code == r0.status_code:
        lt, lf = len(t.content), len(f.content)
        if abs(lt - lf) > max(40, 0.05 * max(lf, 1)):
            add("medium", f"Possible boolean-based SQLi - parameter '{pt.name}'", "sqli",
                pt.label(), f"len(TRUE)={lt} vs len(FALSE)={lf}",
                "Confirm with sqlmap, then fix with prepared statements.")


def test_xss(pt, s):
    marker = "hqx7z"
    for payload in (f"<{marker}>", f'{marker}"><{marker}>', f"'><{marker}>"):
        r = pt.send(s, payload)
        if r is None:
            continue
        if "html" not in r.headers.get("Content-Type", "").lower():
            return
        if payload in r.text:
            add("medium", f"Reflected XSS candidate - parameter '{pt.name}'", "xss",
                pt.label(), f"payload={payload} returned verbatim",
                "Context-aware output encoding + input validation; confirm script execution.")
            return


def test_open_redirect(pt, s):
    if pt.name.lower() not in REDIRECT_NAMES:
        return
    evil = "https://hqx7z.example/"
    r = pt.send(s, evil)
    if r is None:
        return
    hist = [h.headers.get("Location", "") for h in r.history]
    loc = r.headers.get("Location", "")
    if any(l.startswith("https://hqx7z.example") for l in hist + [loc]):
        add("medium", f"Open redirect - parameter '{pt.name}'", "redirect", pt.label(),
            f"Location: {loc or hist[-1]}", "Allow-list redirect destinations.")


def test_lfi(pt, s):
    if pt.name.lower() not in LFI_NAMES:
        return
    for payload in ("../../../../../../etc/passwd", "..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
                    "....//....//....//etc/passwd"):
        r = pt.send(s, payload)
        if r is not None and re.search(r"root:.*:0:0:", r.text):
            add("high", f"Local file inclusion - parameter '{pt.name}'", "lfi", pt.label(),
                f"payload={payload} returned /etc/passwd",
                "Use a whitelist of allowed files; never pass user input to include().")
            return


def inject_phase(param_urls, forms, s):
    pts = build_points(param_urls, forms)
    say(f"Injection probes on {len(pts)} parameter(s)")
    for pt in pts:
        print(f"  -> {pt.label()}", flush=True)
        test_sqli(pt, s)
        test_xss(pt, s)
        test_open_redirect(pt, s)
        test_lfi(pt, s)


# ----------------------------------------------------------------------------- subdomains
def subdomain_phase(domain, threads):
    say(f"Certificate transparency subdomain enum: {domain}")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=max(25, TIMEOUT * 3), headers={"User-Agent": UA})
        names = {n.strip().lower().lstrip("*.")
                 for row in r.json() for n in row.get("name_value", "").split("\n")}
    except Exception as e:
        print(f"  !! crt.sh unavailable: {e}")
        return
    subs = sorted(n for n in names if n.endswith(domain) and "@" not in n)
    print(f"  {len(subs)} unique names, probing liveness…")

    def probe(d):
        try:
            ip = socket.gethostbyname(d)
        except OSError:
            return None
        code = "-"
        for scheme in ("https", "http"):
            try:
                rr = requests.get(f"{scheme}://{d}", timeout=min(TIMEOUT, 6),
                                  headers={"User-Agent": UA}, verify=False,
                                  allow_redirects=True)
                code = str(rr.status_code)
                break
            except requests.RequestException:
                continue
        return d, ip, code

    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        for res in ex.map(probe, subs):
            if res:
                d, ip, code = res
                print(f"  {d:45} {ip:16} http={code}", flush=True)
                add("info", "Live subdomain", "dns", d, f"{ip} http={code}",
                    "Inventory it; check for takeover (dangling CNAME) and stale apps.")


# ----------------------------------------------------------------------------- report
def write_reports(base, outdir):
    os.makedirs(outdir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    host = up.urlsplit(base).netloc.replace(":", "_")
    order = sorted(FINDINGS, key=lambda f: (SEV_ORDER[f["sev"]], f["category"]))
    counts = Counter(f["sev"] for f in FINDINGS)
    dur = round(time.time() - T0, 1)

    jp = os.path.join(outdir, f"{host}-{stamp}.json")
    with open(jp, "w", encoding="utf-8") as fh:
        json.dump({"target": base, "duration_s": dur,
                   "counts": dict(counts), "findings": order}, fh, indent=2)

    css = """
    body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:32px;color:#16202a}
    h1{font-size:22px} table{border-collapse:collapse;width:100%}
    th,td{border:1px solid #dfe6ee;padding:8px 10px;vertical-align:top;text-align:left}
    th{background:#f4f7fa} .critical{background:#ffe3e3}.high{background:#ffefef}
    .medium{background:#fff8e1}.low{background:#eef6ff}.info{background:#fafafa}
    code{font-size:12px;word-break:break-all;white-space:pre-wrap}
    """
    rows = "".join(
        f"<tr class='{f['sev']}'><td>{f['sev'].upper()}</td><td>{html.escape(f['category'])}</td>"
        f"<td>{html.escape(f['title'])}</td><td><code>{html.escape(f['endpoint'])}</code></td>"
        f"<td><code>{html.escape(f['evidence'])}</code></td>"
        f"<td>{html.escape(f['fix'])}</td></tr>" for f in order)
    hp = os.path.join(outdir, f"{host}-{stamp}.html")
    with open(hp, "w", encoding="utf-8") as fh:
        fh.write(f"""<!doctype html><meta charset="utf-8"><title>Pentest - {html.escape(base)}</title>
<style>{css}</style><h1>Penetration test report</h1>
<p><b>Target:</b> {html.escape(base)} &nbsp; <b>Duration:</b> {dur}s &nbsp;
<b>Findings:</b> {len(order)} &nbsp; {' &nbsp; '.join(f'{k}: {v}' for k, v in counts.items())}</p>
<table><tr><th>Severity</th><th>Category</th><th>Issue</th><th>Endpoint</th>
<th>Evidence</th><th>Remediation</th></tr>{rows}</table>""")
    print(f"\n  JSON -> {jp}\n  HTML -> {hp}")


# ----------------------------------------------------------------------------- main
def main():
    global TIMEOUT, VERIFY
    ap = argparse.ArgumentParser(description="Real-time web penetration test")
    ap.add_argument("target", help="URL or host, e.g. https://example.com")
    ap.add_argument("--ports", choices=["top", "full", "none"], default="top")
    ap.add_argument("--threads", type=int, default=150)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--max-pages", type=int, default=30)
    ap.add_argument("--full", action="store_true", help="all phases, deeper crawl")
    ap.add_argument("--insecure", action="store_true", help="ignore TLS errors")
    ap.add_argument("--no-ports", action="store_true")
    ap.add_argument("--no-dirs", action="store_true")
    ap.add_argument("--no-inject", action="store_true")
    ap.add_argument("--no-subdomains", action="store_true")
    ap.add_argument("--output", default="pentest-reports")
    a = ap.parse_args()

    TIMEOUT, VERIFY = a.timeout, not a.insecure
    scheme, host, port, base = normalise(a.target)

    print("=" * 74)
    print(f" websect - live pentest of {base}   started {datetime.now():%Y-%m-%d %H:%M:%S}")
    print("=" * 74)

    ips = dns_phase(host)
    ip = ips[0] if ips else None

    if ip and not a.no_ports and a.ports != "none":
        ports = list(range(1, 65536)) if (a.ports == "full" or a.full) else TOP_PORTS
        open_ports = port_phase(ip, ports, a.threads)
        say("Service banners")
        for p in open_ports:
            bn = banner_of(ip, p, host)
            if bn:
                print(f"  {p}/tcp {SERVICE.get(p,'?'):14} {bn}", flush=True)

    if scheme == "https" or port in TLS_PORTS:
        tls_phase(host, port)

    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    s.verify = VERIFY

    extra = http_phase(base, s, scheme) or []
    if not a.no_dirs:
        dir_phase(base, extra, a.threads)
    if not a.no_inject:
        param_urls, forms = crawl(base, s, a.max_pages if a.full else min(a.max_pages, 15))
        inject_phase(param_urls, forms, s)
    if not a.no_subdomains:
        subdomain_phase(host, min(a.threads, 60))

    counts = Counter(f["sev"] for f in FINDINGS)
    print("\n" + "=" * 74)
    print(" SUMMARY " + " | ".join(f"{k}: {counts.get(k, 0)}" for k in
                                   ("critical", "high", "medium", "low", "info")))
    print(f" duration: {time.time() - T0:.1f}s")
    print("=" * 74)
    write_reports(base, a.output)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted - writing partial report")
        sys.exit(130)