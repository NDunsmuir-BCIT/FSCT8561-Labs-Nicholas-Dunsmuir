import csv
from urllib.parse import urlparse

import requests

from config import ALLOWED_HOSTS, TEST_SITE

PATHS = ["/", "/health", "/redirect", "/missing"]
TIMEOUT = 5
# every finding gets this label because indicators aren't proof of a vulnerability
REVIEW = "Indicator only; manual review required (not proof of exploitability)"

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
]


def validate_base_url(url):
    parsed = urlparse(url.strip())

# only localhost targets are allowed
    if parsed.scheme not in ("http", "https") or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Only http(s)://127.0.0.1 or localhost URLs are allowed.")
    if parsed.port is None:
        raise ValueError("Include the port, e.g. http://127.0.0.1:8765")

    return parsed.scheme + "://" + parsed.hostname + ":" + str(parsed.port)


def add_finding(findings, category, endpoint, observation):
    findings.append({
        "category": category,
        "endpoint": endpoint,
        "observation": observation,
        "review_status": REVIEW,
    })


def check_site(base_url):
    """Request each path. Returns (records, findings)."""
    records = []
    findings = []
# GET onlyand no redirects allowed
    for path in PATHS:
        try:
            res = requests.get(base_url + path, timeout=TIMEOUT, allow_redirects=False)
        # a down site gets recorded as a connection failure
        except requests.RequestException as err:
            records.append({"endpoint": path, "method": "GET",
                            "status_code": "CONNECTION_FAILED", "response_length": 0,
                            "content_type": "N/A", "server": "N/A"})
            add_finding(findings, "Connection failure", path,
                        "Request failed (" + type(err).__name__ + "); target may be down.")
            continue

        records.append({
            "endpoint": path,
            "method": "GET",
            "status_code": res.status_code,
            "response_length": len(res.content),
            "content_type": res.headers.get("Content-Type", "N/A"),
            "server": res.headers.get("Server", "N/A").strip(),
        })

        if path != "/":
            continue

        if base_url.startswith("http://"):
            add_finding(findings, "Transport", path,
                        "Site is served over plain HTTP, so traffic is not encrypted.")

        for header in SECURITY_HEADERS:
            if header not in res.headers:
                add_finding(findings, "Missing security header", path,
                            "Header '" + header + "' is not present in the response.")

        cookie = res.headers.get("Set-Cookie")
        if cookie:
            missing = []
            for flag in ("httponly", "secure", "samesite"):
                if flag not in cookie.lower():
                    missing.append(flag)
            if missing:
                name = cookie.split("=")[0]
                add_finding(findings, "Cookie flags", path,
                            "Cookie '" + name + "' lacks: " + ", ".join(missing) + ".")

        server = res.headers.get("Server")
        if server:
            add_finding(findings, "Information disclosure", path,
                        "Server header reveals: " + server.strip())

    return records, findings


def save_csv(filename, fieldnames, rows):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def run_checker_menu():
    print("\n--- HTTP check (client side, local test website only) ---")
    entered = input(f"Base URL [{TEST_SITE}]: ").strip()
    if entered == "":
        entered = TEST_SITE

    try:
        base_url = validate_base_url(entered)
    except ValueError as err:
        print("Check not started:", err)
        return

    print(f"\nChecking {base_url} ...\n")
    records, findings = check_site(base_url)

    print(f"{'PATH':<12}{'STATUS':<20}{'TYPE':<28}{'BYTES'}")
    print("-" * 70)
    for r in records:
        print(f"{r['endpoint']:<12}{str(r['status_code']):<20}"
              f"{r['content_type'][:26]:<28}{r['response_length']}")

    print("\nFindings (indicators, not confirmed vulnerabilities):")
    if len(findings) == 0:
        print("  None. (That does not prove the site is secure.)")
    for f in findings:
        print(f"  [{f['category']}] {f['endpoint']}: {f['observation']}")

    save_csv("http_scan_results.csv",
             ["endpoint", "method", "status_code", "response_length", "content_type", "server"],
             records)
    save_csv("http_findings.csv",
             ["category", "endpoint", "observation", "review_status"], findings)
    print("\nSaved http_scan_results.csv and http_findings.csv")