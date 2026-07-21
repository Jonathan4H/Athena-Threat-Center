from flask import Flask, render_template, request, redirect, url_for, flash
import requests
import time
import logging
import config
import hashlib

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

def calculate_sha256(file):
    sha256 = hashlib.sha256()

    file.stream.seek(0)

    while chunk := file.stream.read(8192):
        sha256.update(chunk)

    file.stream.seek(0)

    return sha256.hexdigest()


def vt_get_file(sha256):
    return session.get(
        f"{VT_BASE_URL}/files/{sha256}",
        timeout=15
    )

def vt_post_file(file):
    file.stream.seek(0)

    file.stream.seek(0, 2)
    size = file.stream.tell()
    file.stream.seek(0)

    files = {
        "file": (file.filename, file.stream, file.content_type)
    }

    # <=32 MB
    if size <= 32 * 1024 * 1024:
        return session.post(
            f"{VT_BASE_URL}/files",
            files=files,
            timeout=30
        )

    # >32 MB
    upload_url = session.get(
        f"{VT_BASE_URL}/files/upload_url"
    )

    upload_url.raise_for_status()

    url = upload_url.json()["data"]

    return session.post(
        url,
        files=files,
        timeout=120
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

def poll_analysis(analysis_id, timeout=180):
    start = time.time()

    while time.time() - start < timeout:
        response = vt_get_analysis(analysis_id)

        print("Status:", response.status_code)
        print("Body:", response.text)

        if response.status_code != 200:
            return None, response.status_code

        data = response.json()
        status = data["data"]["attributes"]["status"]

        print("Analysis status:", status)

        if status == "completed":
            return data, 200

        time.sleep(5)

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
        # ---------------------------------
        # Compute hash
        # ---------------------------------
        sha256 = calculate_sha256(file)
        print("SHA256:", sha256)

        # ---------------------------------
        # Does VT already know this file?
        # ---------------------------------
        file_response = vt_get_file(sha256)
        if file_response.status_code == 200:
            print("Existing report found.")
            file_data = file_response.json()
        elif file_response.status_code == 404:
            print("Uploading new sample...")
            upload_response = vt_post_file(file)

            # ----------------------------
            # Handle upload errors
            # ----------------------------
            if upload_response.status_code == 409:
                flash(
                    "This sample is already being analyzed. "
                    "Please try again shortly."
                )
                return redirect(url_for("index"))
            if not upload_response.ok:
                try:
                    message = upload_response.json()["error"]["message"]
                except Exception:
                    message = upload_response.text
                flash(message)
                return redirect(url_for("index"))

            analysis_id = upload_response.json()["data"]["id"]
            print("Analysis:", analysis_id)

            analysis = poll_analysis(analysis_id)

            if analysis is None:
                flash("VirusTotal analysis timed out.")
                return redirect(url_for("index"))
            # Retrieve final report
            file_response = vt_get_file(sha256)
            if not file_response.ok:
                flash("Could not retrieve completed report.")
                return redirect(url_for("index"))
            file_data = file_response.json()
        else:
            flash("VirusTotal lookup failed.")
            return redirect(url_for("index"))
        attributes = file_data["data"]["attributes"]
        stats = attributes["last_analysis_stats"]
        malicious_count = stats["malicious"]
        behavior_data = None
        behavior_response = vt_get_behavior(sha256)
        if behavior_response.ok:
            behavior_data = behavior_response.json()
            signatures = (
                behavior_data
                .get("data", {})
                .get("signature_matches", [])
            )
            behavior_data["data"]["signature_matches"] = \
                normalize_behavior_signatures(signatures)

        return render_template(
            "result.html",
            file_data=file_data,
            behavior_data=behavior_data,
            malicious_count=malicious_count
        )

    except requests.Timeout:
        logging.error("VirusTotal request timeout")
        flash("VirusTotal timeout")

    except requests.RequestException as e:
        import traceback
        traceback.print_exc()
        print("Network error:", repr(e))
        flash(f"Network error: {e}")
        return redirect(url_for("index"))

    except Exception as e:
        logging.exception(f"Unexpected error: {e}")
        flash("Unexpected server error")

    return redirect(url_for("index"))

if __name__ == '__main__':
    app.run()