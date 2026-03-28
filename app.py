from flask import Flask, render_template, request
from scanner import *

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    results = None

    if request.method == "POST":
        url = request.form["url"]
        host = url.replace("http://", "").replace("https://", "").split("/")[0]

        results = {
            "sql": scan_sql_injection(url),
            "xss": scan_xss(url),
            "ports": scan_open_ports(host),
            "dir": scan_directory_listing(url),
            "clickjacking": scan_clickjacking(url),
            "headers": scan_security_headers(url),
            "robots": scan_robots(url),
            "server": scan_server_info(url),
            "csrf": scan_csrf(url),
            "https": scan_https(url),
            "fileupload": scan_file_upload(url),
            "tech": scan_tech_stack(url),
        }

    return render_template("index.html", results=results)

if __name__ == "__main__":
    app.run(debug=True)
    