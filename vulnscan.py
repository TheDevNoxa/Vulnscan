#!/usr/bin/env python3
"""
web-vulnscan — Basic web vulnerability scanner
Author : Noxa (Valentin Lagarde)
Usage  : python3 vulnscan.py -u https://example.com

Checks performed:
  - Missing/misconfigured HTTP security headers
  - Basic SQL injection detection (error-based)
  - Basic XSS reflection detection
  - Directory listing detection
  - Sensitive file exposure
"""

import argparse
import requests
import urllib.parse
from dataclasses import dataclass, field

requests.packages.urllib3.disable_warnings()

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
]

SQLI_PAYLOADS = ["'", '"', "' OR '1'='1", "' OR 1=1--", '" OR "1"="1']
SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "syntax error",
    "pg_query",
    "sqlite3",
]

XSS_PAYLOAD = "<script>alert('xss')</script>"

SENSITIVE_PATHS = [
    "/.env", "/.git/HEAD", "/config.php", "/wp-config.php",
    "/phpinfo.php", "/admin/", "/backup/", "/db.sql",
    "/robots.txt", "/sitemap.xml", "/.htaccess",
]


@dataclass
class Finding:
    severity: str   # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category: str
    detail: str


@dataclass
class ScanResult:
    url: str
    findings: list[Finding] = field(default_factory=list)

    def add(self, severity, category, detail):
        self.findings.append(Finding(severity, category, detail))

    def summary(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


def get_session(timeout: int = 8) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0 (edu-vulnscan/1.0)"})
    s.verify = False
    return s


def check_headers(result: ScanResult, response: requests.Response) -> None:
    for header in SECURITY_HEADERS:
        if header.lower() not in [h.lower() for h in response.headers]:
            severity = "MEDIUM" if header in ("Content-Security-Policy", "Strict-Transport-Security") else "LOW"
            result.add(severity, "Missing Header", f"{header} not set")
        else:
            result.add("INFO", "Header OK", f"{header}: {response.headers.get(header, '')[:80]}")


def check_sqli(result: ScanResult, session: requests.Session, url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        result.add("INFO", "SQLi", "No query parameters found to test")
        return
    for param in params:
        for payload in SQLI_PAYLOADS:
            test_params = {**params, param: payload}
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True))
            )
            try:
                r = session.get(test_url, timeout=8)
                body = r.text.lower()
                for err in SQLI_ERRORS:
                    if err in body:
                        result.add("CRITICAL", "SQL Injection",
                                   f"Param '{param}' — error pattern '{err}' detected with payload: {payload}")
                        return
            except requests.RequestException:
                pass
    result.add("INFO", "SQLi", "No obvious SQL error patterns detected")


def check_xss(result: ScanResult, session: requests.Session, url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    if not params:
        result.add("INFO", "XSS", "No query parameters found to test")
        return
    for param in params:
        test_params = {**params, param: XSS_PAYLOAD}
        test_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(test_params, doseq=True))
        )
        try:
            r = session.get(test_url, timeout=8)
            if XSS_PAYLOAD in r.text:
                result.add("HIGH", "XSS Reflection",
                           f"Param '{param}' reflects payload unescaped — possible XSS")
                return
        except requests.RequestException:
            pass
    result.add("INFO", "XSS", "No reflected XSS detected")


def check_sensitive_files(result: ScanResult, session: requests.Session, base_url: str) -> None:
    base = base_url.rstrip("/")
    for path in SENSITIVE_PATHS:
        try:
            r = session.get(base + path, timeout=6)
            if r.status_code == 200 and len(r.text) > 0:
                result.add("HIGH", "Sensitive File",
                           f"{path} accessible (HTTP 200, {len(r.text)} bytes)")
            elif r.status_code == 403:
                result.add("LOW", "Sensitive Path",
                           f"{path} exists but forbidden (HTTP 403)")
        except requests.RequestException:
            pass


def check_directory_listing(result: ScanResult, session: requests.Session, base_url: str) -> None:
    try:
        r = session.get(base_url.rstrip("/") + "/", timeout=8)
        indicators = ["index of /", "directory listing", "parent directory"]
        body = r.text.lower()
        if any(ind in body for ind in indicators):
            result.add("MEDIUM", "Directory Listing", "Directory listing appears to be enabled")
        else:
            result.add("INFO", "Directory Listing", "Not detected")
    except requests.RequestException:
        pass


SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[96m",
    "INFO":     "\033[37m",
}
RESET = "\033[0m"


def print_results(result: ScanResult) -> None:
    print(f"\n{'=' * 65}")
    print(f"  SCAN RESULTS — {result.url}")
    print(f"{'=' * 65}")
    for f in result.findings:
        color = SEVERITY_COLOR.get(f.severity, "")
        print(f"  {color}[{f.severity:<8}]{RESET} {f.category:<22} {f.detail}")
    summary = result.summary()
    print(f"\n{'─' * 65}")
    print("  Summary: ", end="")
    for sev, count in summary.items():
        if count:
            color = SEVERITY_COLOR.get(sev, "")
            print(f"{color}{sev}: {count}{RESET}  ", end="")
    print(f"\n{'=' * 65}\n")


def main():
    parser = argparse.ArgumentParser(description="Basic web vulnerability scanner (educational)")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. https://example.com/page?id=1)")
    parser.add_argument("--no-headers", action="store_true", help="Skip header checks")
    parser.add_argument("--no-sqli",    action="store_true", help="Skip SQLi checks")
    parser.add_argument("--no-xss",     action="store_true", help="Skip XSS checks")
    parser.add_argument("--no-files",   action="store_true", help="Skip sensitive file checks")
    args = parser.parse_args()

    session = get_session()
    result = ScanResult(url=args.url)

    print(f"[*] Starting scan on: {args.url}\n")

    try:
        resp = session.get(args.url, timeout=10)
    except requests.RequestException as e:
        print(f"[!] Cannot reach target: {e}")
        return

    if not args.no_headers:
        print("[*] Checking security headers ...")
        check_headers(result, resp)

    if not args.no_sqli:
        print("[*] Testing SQL injection ...")
        check_sqli(result, session, args.url)

    if not args.no_xss:
        print("[*] Testing XSS reflection ...")
        check_xss(result, session, args.url)

    if not args.no_files:
        print("[*] Checking sensitive files ...")
        check_sensitive_files(result, session, args.url)
        check_directory_listing(result, session, args.url)

    print_results(result)


if __name__ == "__main__":
    main()
