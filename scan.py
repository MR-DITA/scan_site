import requests
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time

# List of common payloads for SQLi testing
payloads = ["' OR '1'='1", "' OR 'a'='a", "'--", "'#", "' OR 1=1--", "php?id=1"]

# List to store checked links to avoid duplication
scanned_links = set()

def xss_scanner(url):
    """
    This function takes a URL as input and scans it for XSS vulnerabilities.
    """
    response = requests.get(url)
    html = response.text
    input_fields = re.findall(r'<input.*?>', html)
    vulnerabilities = []
    for input_field in input_fields:
        if is_xss_vulnerable(input_field):
            vulnerabilities.append(input_field)
    return vulnerabilities

def is_xss_vulnerable(input_field):
    if re.search(r'["<>\/\\;{}\[\]()]', input_field):
        return True
    return False

def find_internal_links(url):
    internal_links = set()
    response = requests.get(url)
    html = response.text
    links = re.findall(r'href=["\'](.*?)["\']', html)
    base_url = urlparse(url)

    for link in links:
        full_url = urljoin(url, link)
        if base_url.netloc == urlparse(full_url).netloc:
            internal_links.add(full_url)

    return internal_links

# Scan a single page of a site
def scan_sql_injection(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all("form")
        print(f"[+] Found {len(forms)} form(s) in {url}")

        for form in forms:
            form_details = get_form_details(form)
            for payload in payloads:
                is_vulnerable = submit_form(form_details, url, payload)
                if is_vulnerable:
                    print(f"[!] SQL Injection vulnerability detected on {url}")
                    print(f"[*] Payload: {payload}")
                    return True

        for payload in payloads:
            is_vulnerable = test_link_with_payload(url, payload)
            if is_vulnerable:
                print(f"[!] SQL Injection vulnerability detected on {url}")
                print(f"[*] Payload: {payload}")
                return True

        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

def get_form_details(form):
    details = {}
    action = form.attrs.get("action").lower()
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

def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        if input["type"] == "text" or input["type"] == "search":
            data[input["name"]] = payload
        else:
            data[input["name"]] = "test"

    if form_details["method"] == "post":
        res = requests.post(target_url, data=data)
    else:
        res = requests.get(target_url, params=data)

    return check_for_sql_errors(res)

def test_link_with_payload(url, payload):
    parsed_url = urlparse(url)
    if parsed_url.query:
        query = parsed_url.query
        query_with_payload = query + payload
        target_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, query_with_payload, parsed_url.fragment))

        res = requests.get(target_url)
        return check_for_sql_errors(res)
    return False

def check_for_sql_errors(response):
    errors = ["you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark", "quoted string not properly terminated"]
    for error in errors:
        if error.lower() in response.text.lower():
            return True
    return False

def get_all_links(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = []
        for link in soup.find_all("a", href=True):
            full_url = urljoin(url, link['href'])
            if url in full_url:
                links.append(full_url)
        return set(links)
    except Exception as e:
        print(f"Error fetching links from {url}: {e}")
        return set()

def scan_website_for_sqli(url):
    links = get_all_links(url)
    print(f"[+] Scanning {len(links)} pages in {url}")
    for link in links:
        scan_sql_injection(link)

def main():
    print()
    print("   ▄████████  ▄████████    ▄████████ ███▄▄▄▄      ▄████████ ████████▄    ▄█       ▀████    ▐████▀    ▄████████    ▄████████ ")
    print("  ███    ███ ███    ███   ███    ███ ███▀▀▀██▄   ███    ███ ███    ███  ███         ███▌   ████▀    ███    ███   ███    ███ ")
    print("  ███    █▀  ███    █▀    ███    ███ ███   ███   ███    █▀  ███    ███  ███          ███  ▐███      ███    █▀    ███    █▀  ")
    print("  ███        ███          ███    ███ ███   ███   ███        ███    ███  ███          ▀███▄███▀      ███          ███        ")
    print("▀███████████ ███        ▀███████████ ███   ███ ▀███████████ ███    ███  ███          ████▀██▄     ▀███████████ ▀███████████ ")
    print("         ███ ███    █▄    ███    ███ ███   ███          ███ ███    ███  ███         ▐███  ▀███             ███          ███ ")
    print("   ▄█    ███ ███    ███   ███    ███ ███   ███    ▄█    ███ ███  ▀ ███  ███▌    ▄  ▄███     ███▄     ▄█    ███    ▄█    ███ ")
    print(" ▄████████▀  ████████▀    ███    █▀   ▀█   █▀   ▄████████▀   ▀██████▀▄█ █████▄▄██ ████       ███▄  ▄████████▀   ▄████████▀  ")
    print()  # Additional space
    print("Choose vulnerability type:")
    print("[ 1 ] XSS")
    print("[ 2 ] SQL Injection")
    print("Enter number:")

    test_type = input()
    url = input("Please enter the URL to scan: ")

    if test_type == '1':
        internal_links = find_internal_links(url)
        all_vulnerabilities = []
        for link in internal_links:
            vulnerabilities = xss_scanner(link)
            if vulnerabilities:
                for vulnerability in vulnerabilities:
                    all_vulnerabilities.append((link, vulnerability, "[+]"))
            else:
                all_vulnerabilities.append((link, "No vulnerabilities found", "[***]"))

        for url, result, marker in all_vulnerabilities:
            print(f"URL: {url} - {result} {marker}")

    elif test_type == '2':
        scan_website_for_sqli(url)
    else:
        print("Invalid selection.")

if __name__ == "__main__":
    main()


