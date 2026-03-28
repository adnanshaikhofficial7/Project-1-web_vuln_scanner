import requests
import socket
from bs4 import BeautifulSoup

def scan_sql_injection(url):
    try:
        payload = "' OR '1'='1"
        r = requests.get(url, params={"id": payload}, timeout=5)
        errors = ["sql", "mysql", "syntax", "query", "warning"]
        for e in errors:
            if e in r.text.lower():
                return True
        return False
    except:
        return False

def scan_xss(url):
    try:
        payload = "<script>alert(1)</script>"
        r = requests.get(url, params={"q": payload}, timeout=5)
        return payload in r.text
    except:
        return False

def scan_open_ports(host):
    open_ports = []
    for port in [21, 22, 80, 443, 3306]:
        s = socket.socket()
        s.settimeout(1)
        try:
            s.connect((host, port))
            open_ports.append(port)
        except:
            pass
        s.close()
    return open_ports

def scan_directory_listing(url):
    try:
        r = requests.get(url, timeout=5)
        return "Index of /" in r.text
    except:
        return False

def scan_clickjacking(url):
    try:
        r = requests.get(url, timeout=5)
        headers = r.headers
        return "X-Frame-Options" not in headers
    except:
        return False

def scan_security_headers(url):
    try:
        r = requests.get(url, timeout=5)
        headers = r.headers

        required = [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "X-Frame-Options"
        ]

        missing = [h for h in required if h not in headers]
        return missing
    except:
        return []

def scan_robots(url):
    try:
        r = requests.get(url + "/robots.txt", timeout=5)
        return r.status_code == 200
    except:
        return False

def scan_server_info(url):
    try:
        r = requests.get(url, timeout=5)
        return r.headers.get("Server", "Unknown")
    except:
        return "Unknown"

def scan_csrf(url):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            if not form.find("input", {"name": "csrf"}):
                return True
        return False
    except:
        return False

def scan_https(url):
    return url.startswith("https://")

def scan_admin_panel(url):
    found = []
    paths = ["/admin", "/login", "/dashboard", "/cpanel"]

    for path in paths:
        try:
            r = requests.get(url + path, timeout=3)
            if r.status_code == 200:
                found.append(path)
        except:
            pass

    return found

def scan_exposed_files(url):
    exposed = []
    files = ["/.env", "/config.php", "/backup.zip", "/.git/config"]

    for f in files:
        try:
            r = requests.get(url + f, timeout=3)
            if r.status_code == 200:
                exposed.append(f)
        except:
            pass

    return exposed

def scan_file_upload(url):
    import requests
    paths = ["/upload", "/uploads", "/fileupload", "/upload.php"]
    found = []

    for path in paths:
        try:
            r = requests.get(url + path, timeout=3)
            if r.status_code == 200:
                found.append(path)
        except:
            pass

    return found

def scan_tech_stack(url):
    import requests
    tech = []

    try:
        r = requests.get(url, timeout=5)
        headers = r.headers
        html = r.text.lower()

        server = headers.get("Server")
        powered = headers.get("X-Powered-By")

        if server:
            tech.append(server)
        if powered:
            tech.append(powered)

        if "wp-content" in html:
            tech.append("WordPress")
        if "laravel" in html:
            tech.append("Laravel")
        if "django" in html:
            tech.append("Django")
        if "react" in html:
            tech.append("React")
        if "jquery" in html:
            tech.append("jQuery")

    except:
        pass

    return tech