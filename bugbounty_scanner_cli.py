#!/usr/bin/env python3
"""
╔══════════════════════════════════════════╗
║   ⚡ Automated Bug Bounty Scanner CLI ⚡  ║
║      Termux-compatible, No GUI needed    ║
╚══════════════════════════════════════════╝
"""

import sys
import socket
import ssl
import json
import re
import os
import time
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse, urljoin, quote
from http.client import HTTPConnection, HTTPSConnection

# ── Colour helpers (ANSI) ─────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def banner():
    print(f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════════╗
║        ⚡  Bug Bounty Scanner  ⚡                ║
║   Termux CLI Edition — No GUI Required           ║
║   Use only on targets you have permission to test║
╚══════════════════════════════════════════════════╝
{RESET}""")

def section(title):
    print(f"\n{BLUE}{BOLD}{'─'*50}{RESET}")
    print(f"{BLUE}{BOLD}  {title}{RESET}")
    print(f"{BLUE}{BOLD}{'─'*50}{RESET}")

def ok(msg):    print(f"  {GREEN}[+]{RESET} {msg}")
def warn(msg):  print(f"  {YELLOW}[!]{RESET} {msg}")
def bad(msg):   print(f"  {RED}[-]{RESET} {msg}")
def info(msg):  print(f"  {CYAN}[*]{RESET} {msg}")

# ── HTTP helper (pure stdlib, no requests) ────────────────────────────────────
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; BugBountyScanner/1.0)",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
}

def fetch(url, timeout=10, allow_redirects=True):
    """Return (status_code, headers_dict, body_text) or None on error."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = Request(url, headers=HEADERS)
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(1_000_000).decode("utf-8", errors="replace")
            return resp.status, dict(resp.headers), body
    except HTTPError as e:
        try:
            body = e.read(100_000).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, dict(e.headers), body
    except Exception:
        return None

# ── 1. Basic info ─────────────────────────────────────────────────────────────
def check_basic(url, parsed):
    section("1 · Basic Target Info")
    info(f"Target : {url}")
    info(f"Host   : {parsed.netloc}")
    info(f"Scheme : {parsed.scheme.upper()}")

    # DNS
    try:
        ip = socket.gethostbyname(parsed.hostname)
        ok(f"Resolved IP : {ip}")
    except Exception as e:
        bad(f"DNS resolution failed: {e}")

    # HTTPS redirect
    if parsed.scheme == "http":
        https_url = url.replace("http://", "https://", 1)
        r = fetch(https_url, timeout=6)
        if r:
            ok("HTTPS version is reachable")
        else:
            warn("HTTPS version not reachable — site may be HTTP-only")

# ── 2. Security headers ───────────────────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Frame-Options": "Clickjacking protection",
    "X-Content-Type-Options": "MIME sniffing protection",
    "Referrer-Policy": "Referrer policy",
    "Permissions-Policy": "Permissions policy",
    "X-XSS-Protection": "XSS filter (legacy)",
}

def check_headers(url):
    section("2 · Security Headers")
    r = fetch(url)
    if not r:
        bad("Could not fetch headers"); return {}
    _, headers, _ = r
    h_lower = {k.lower(): v for k, v in headers.items()}
    found = {}
    for header, label in SECURITY_HEADERS.items():
        if header.lower() in h_lower:
            ok(f"{label} ({header}) — present")
            found[header] = h_lower[header.lower()]
        else:
            warn(f"{label} ({header}) — MISSING")

    # Server banner leak
    srv = h_lower.get("server", "")
    if srv:
        warn(f"Server header leaks: '{srv}'")
    x_pow = h_lower.get("x-powered-by", "")
    if x_pow:
        warn(f"X-Powered-By leaks: '{x_pow}'")
    return found

# ── 3. SSL/TLS ────────────────────────────────────────────────────────────────
def check_ssl(parsed):
    section("3 · SSL / TLS")
    if parsed.scheme != "https":
        warn("Not HTTPS — skipping SSL checks"); return
    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((host, port), timeout=8),
                             server_hostname=host) as s:
            cert = s.getpeercert()
            proto = s.version()
            ok(f"Protocol : {proto}")
            # Expiry
            exp_str = cert.get("notAfter", "")
            if exp_str:
                exp = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                days = (exp - datetime.utcnow()).days
                if days < 30:
                    bad(f"Certificate expires in {days} days!")
                else:
                    ok(f"Certificate valid for {days} more days")
            # Subject
            subj = dict(x[0] for x in cert.get("subject", []))
            ok(f"Issued to : {subj.get('commonName', 'unknown')}")
    except ssl.SSLCertVerificationError as e:
        bad(f"SSL verification error: {e}")
    except Exception as e:
        bad(f"SSL check failed: {e}")

# ── 4. Common sensitive paths ─────────────────────────────────────────────────
SENSITIVE_PATHS = [
    "/.git/HEAD", "/.env", "/robots.txt", "/sitemap.xml",
    "/admin", "/admin/login", "/wp-admin", "/phpmyadmin",
    "/config.php", "/config.yml", "/config.json",
    "/.htaccess", "/server-status", "/server-info",
    "/api/v1/users", "/api/v1/admin", "/graphql",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/backup.zip", "/backup.sql", "/dump.sql",
    "/.DS_Store", "/web.config", "/crossdomain.xml",
]

def check_paths(base_url):
    section("4 · Sensitive Path Discovery")
    found = []
    for path in SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        r = fetch(url, timeout=6)
        if r:
            code, _, body = r
            if code == 200:
                size = len(body)
                bad(f"FOUND  [{code}] {path}  ({size} bytes)")
                found.append(path)
            elif code in (301, 302, 307, 308):
                warn(f"Redirect [{code}] {path}")
            # 403/401 = exists but protected — still interesting
            elif code in (401, 403):
                warn(f"Protected [{code}] {path}")
    if not found:
        ok("No obviously exposed sensitive paths found")
    return found

# ── 5. XSS probe (reflected) ──────────────────────────────────────────────────
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    '<svg onload=alert(1)>',
]

def check_xss(base_url):
    section("5 · Reflected XSS Probe")
    # Try appending payload to query string
    test_url = base_url.rstrip("/") + "/?q="
    for payload in XSS_PAYLOADS:
        encoded = quote(payload)
        url = test_url + encoded
        r = fetch(url, timeout=8)
        if r:
            _, _, body = r
            if payload.lower() in body.lower():
                bad(f"Possible XSS — payload reflected: {payload[:60]}")
                return
    ok("No obvious reflected XSS found (basic check only)")

# ── 6. Open redirect probe ────────────────────────────────────────────────────
REDIRECT_PARAMS = ["url", "redirect", "return", "next", "goto", "target", "redir"]

def check_open_redirect(base_url):
    section("6 · Open Redirect Probe")
    canary = "https://evil.example.com"
    for param in REDIRECT_PARAMS:
        url = f"{base_url.rstrip('/')}/?{param}={quote(canary)}"
        r = fetch(url, timeout=6)
        if r:
            code, hdrs, _ = r
            location = hdrs.get("Location", "") or hdrs.get("location", "")
            if "evil.example.com" in location:
                bad(f"Open redirect via ?{param}= — Location: {location}")
                return
    ok("No obvious open redirect found")

# ── 7. Information disclosure in body ────────────────────────────────────────
LEAK_PATTERNS = {
    "AWS Key":         r"AKIA[0-9A-Z]{16}",
    "Generic API Key": r"api[_-]?key['\"\s:=]+[A-Za-z0-9_\-]{20,}",
    "Private Key":     r"-----BEGIN (RSA |EC )?PRIVATE KEY",
    "Email address":   r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}",
    "Internal IP":     r"(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)",
    "SQL error":       r"(ORA-\d{5}|mysql_fetch|pg_query|SQLiteException|syntax error.*SQL)",
    "Stack trace":     r"(Traceback \(most recent|at [a-zA-Z0-9_.]+\([A-Za-z0-9_.]+:\d+\))",
}

def check_leaks(url):
    section("7 · Information Disclosure (page body)")
    r = fetch(url)
    if not r:
        bad("Could not fetch page body"); return
    _, _, body = r
    found_any = False
    for label, pattern in LEAK_PATTERNS.items():
        matches = re.findall(pattern, body, re.IGNORECASE)
        if matches:
            snippet = str(matches[0])[:80]
            bad(f"{label} — e.g. {snippet}")
            found_any = True
    if not found_any:
        ok("No obvious sensitive data leaks found in page body")

# ── 8. CORS misconfiguration ──────────────────────────────────────────────────
def check_cors(url):
    section("8 · CORS Misconfiguration")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = Request(url, headers={**HEADERS, "Origin": "https://evil.example.com"})
        with urlopen(req, timeout=8, context=ctx) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "*":
                warn("CORS: Access-Control-Allow-Origin: * (wildcard)")
            elif "evil.example.com" in acao:
                bad(f"CORS reflects arbitrary origin: {acao}")
                if acac.lower() == "true":
                    bad("CORS + credentials=true — HIGH severity!")
            else:
                ok(f"CORS origin header: '{acao or 'not set'}'")
    except Exception as e:
        info(f"CORS check error: {e}")

# ── 9. Cookie flags ───────────────────────────────────────────────────────────
def check_cookies(url):
    section("9 · Cookie Security Flags")
    r = fetch(url)
    if not r:
        bad("Could not fetch"); return
    _, headers, _ = r
    cookies_raw = headers.get("Set-Cookie", "") or headers.get("set-cookie", "")
    if not cookies_raw:
        info("No Set-Cookie header on root page")
        return
    # Could be multi-value — check common flags
    for flag, label in [("HttpOnly", "HttpOnly"), ("Secure", "Secure"),
                         ("SameSite", "SameSite")]:
        if flag.lower() in cookies_raw.lower():
            ok(f"Cookie has {label} flag")
        else:
            warn(f"Cookie missing {label} flag")

# ── 10. Summary report ────────────────────────────────────────────────────────
def save_report(url, results_text):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = urlparse(url).hostname.replace(".", "_")
    fname = f"scan_{hostname}_{ts}.txt"
    with open(fname, "w") as f:
        f.write(results_text)
    ok(f"Report saved → {fname}")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    banner()

    # Get target
    raw = input(f"{CYAN}Enter target URL (e.g. https://example.com): {RESET}").strip()
    if not raw:
        bad("No URL provided."); sys.exit(1)
    if not raw.startswith("http"):
        raw = "https://" + raw

    parsed = urlparse(raw)
    url = f"{parsed.scheme}://{parsed.netloc}"  # normalise

    print(f"\n{YELLOW}[*] Starting scan at {datetime.now().strftime('%H:%M:%S')} …{RESET}\n")

    # Run all checks
    import io
    old_stdout = sys.stdout
    sys.stdout = capture = io.StringIO()

    check_basic(url, parsed)
    check_headers(url)
    check_ssl(parsed)
    check_paths(url)
    check_xss(url)
    check_open_redirect(url)
    check_leaks(url)
    check_cors(url)
    check_cookies(url)

    sys.stdout = old_stdout
    output = capture.getvalue()
    print(output)

    section("Scan Complete")
    ok(f"Finished at {datetime.now().strftime('%H:%M:%S')}")

    save_q = input(f"\n{CYAN}Save report to file? (y/n): {RESET}").strip().lower()
    if save_q == "y":
        save_report(url, f"Bug Bounty Scan — {url}\n{datetime.now()}\n\n{output}")

    print(f"\n{YELLOW}⚠  Use this tool only on systems you have explicit permission to test.{RESET}\n")

if __name__ == "__main__":
    main()
