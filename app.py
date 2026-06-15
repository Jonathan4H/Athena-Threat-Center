from flask import Flask, render_template, request, redirect, url_for, flash
import requests
import time
import logging
import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

VT_BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": config.VIRUSTOTAL_API_KEY}

session = requests.Session()
session.headers.update(HEADERS)

# Static pages mapping
STATIC_PAGES = {
    "/": ("index", "home-page.html"),
    "/about-page.html": ("about", "about-page.html"),
    "/login-page.html": ("login", "login-page.html"),
    "/reset-pass.html": ("reset", "reset-pass.html"),
    "/resources-page.html": ("resources", "resources-page.html"),
    "/signup-page.html": ("signup", "signup-page.html"),
}

def make_view(template):
    def view():
        return render_template(template)
    return view

for route, (endpoint, template) in STATIC_PAGES.items():
    app.add_url_rule(route, endpoint, make_view(template))

def vt_post_file(file):
    file.stream.seek(0)
    files = {"file": (file.filename, file.stream, file.content_type)}
    return session.post(
        f"{VT_BASE_URL}/files",
        files=files,
        timeout=30
    )

def vt_get_analysis(analysis_id):
    return session.get(
        f"{VT_BASE_URL}/analyses/{analysis_id}",
        timeout=15
    )

def vt_get_behavior(sha256):
    return session.get(
        f"{VT_BASE_URL}/files/{sha256}/behaviour_summary",
        timeout=15
    )

def poll_analysis(analysis_id, max_retries=6):
    wait_time = 2

    for _ in range(max_retries):
        response = vt_get_analysis(analysis_id)

        if response.status_code != 200:
            return None, response.status_code

        data = response.json()
        status = data["data"]["attributes"]["status"]

        if status == "completed":
            return data, 200

        time.sleep(wait_time)
        wait_time *= 2  # exponential backoff

    return None, 408

def normalize_behavior_signatures(signatures):
    severity_map = {
        "IMPACT_SEVERITY_HIGH": "HIGH",
        "IMPACT_SEVERITY_MEDIUM": "MEDIUM",
        "IMPACT_SEVERITY_LOW": "LOW",
        "IMPACT_SEVERITY_INFO": "INFO"
    }

    for sig in signatures:
        sig["severity"] = severity_map.get(sig.get("severity"), "UNKNOWN")

    return signatures

@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files.get("upload")

    if not file or file.filename == "":
        flash("No file selected")
        return redirect(url_for("index"))

    try:
        upload_response = vt_post_file(file)

        if not upload_response.ok:
            flash("Upload failed")
            return redirect(url_for("index"))

        analysis_id = upload_response.json()["data"]["id"]

        analysis_data, status = poll_analysis(analysis_id)

        if status != 200:
            flash("Analysis timeout or failed")
            return redirect(url_for("index"))

        results = (
            analysis_data.get("data", {})
            .get("attributes", {})
            .get("results", {})
        )

        malicious_count = sum(
            1 for result in results.values()
            if result.get("category") == "malicious"
        )

        sha256 = (
            analysis_data.get("meta", {})
            .get("file_info", {})
            .get("sha256")
        )
        
        behavior_data = None

        if sha256:
            behavior_response = vt_get_behavior(sha256)

            if behavior_response.ok:
                behavior_data = behavior_response.json()

                signatures = (
                    behavior_data.get("data", {})
                    .get("signature_matches", [])
                )

                behavior_data["data"]["signature_matches"] = \
                    normalize_behavior_signatures(signatures)

        return render_template(
            "result.html",
            analysis_data=analysis_data,
            behavior_data=behavior_data,
            malicious_count=malicious_count
        )

    except requests.Timeout:
        logging.error("VirusTotal request timeout")
        flash("VirusTotal timeout")

    except requests.RequestException as e:
        logging.exception(f"Network error: {e}")
        flash("Network error")

    except Exception as e:
        logging.exception(f"Unexpected error: {e}")
        flash("Unexpected server error")

    return redirect(url_for("index"))

if __name__ == '__main__':
    app.run()