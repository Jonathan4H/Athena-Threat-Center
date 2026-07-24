from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import current_user
from werkzeug.exceptions import RequestEntityTooLarge
import requests
import time
import logging
import config
import hashlib

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

def rate_limit_key():
    if current_user.is_authenticated:
        return f"user:{current_user.id}"
    return get_remote_address()

limiter = Limiter(
    key_func=rate_limit_key,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False, # Enable in production with HTTPS
    SESSION_COOKIE_SAMESITE="Lax",
)
csrf = CSRFProtect(app)
app.config["RATELIMIT_HEADERS_ENABLED"] = True
MAX_UPLOAD_SIZE = 650 * 1024 * 1024  # 650 MB (VirusTotal maximum)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE

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

def handle_vt_rate_limit(response):
    """
    Returns True if VirusTotal rate limit was exceeded.
    """
    if response.status_code == 429:
        logging.warning("VirusTotal rate limit exceeded.")
        flash(
            "VirusTotal rate limit exceeded. "
            "Please try again in a few minutes."
        )
        return True

    return False

def calculate_sha256(file):
    sha256 = hashlib.sha256()

    file.stream.seek(0)

    while chunk := file.stream.read(8192):
        sha256.update(chunk)

    file.stream.seek(0)

    return sha256.hexdigest()

def validate_upload(file):
    """
    Perform basic validation before hashing or uploading.
    Returns None if the file is valid,
    otherwise returns an error message.
    """

    if file is None:
        return "No file was uploaded."

    if not file.filename:
        return "Please choose a file."

    # Determine file size
    file.stream.seek(0, 2)
    size = file.stream.tell()
    file.stream.seek(0)

    if size == 0:
        return "The selected file is empty."

    if size > MAX_UPLOAD_SIZE:
        return (
            f"File exceeds the maximum allowed size "
            f"({MAX_UPLOAD_SIZE // (1024 * 1024)} MB)."
        )

    return None

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
        if response.status_code == 429:
            return None, 429

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
@limiter.limit("30 per hour")
def upload_file():
    file = request.files.get("upload")

    error = validate_upload(file)

    if error:
        flash(error)
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
        if handle_vt_rate_limit(file_response):
            return redirect(url_for("index"))
        elif file_response.status_code == 200:
            print("Existing report found.")
            file_data = file_response.json()
        elif file_response.status_code == 404:
            print("Uploading new sample...")
            upload_response = vt_post_file(file)
            if handle_vt_rate_limit(upload_response):
                return redirect(url_for("index"))

            # ----------------------------
            # Handle upload errors
            # ----------------------------
            elif upload_response.status_code == 409:
                flash(
                    "This sample is already being analyzed. "
                    "Please try again shortly."
                )
                return redirect(url_for("index"))
            elif not upload_response.ok:
                try:
                    message = upload_response.json()["error"]["message"]
                except Exception:
                    message = upload_response.text
                flash(message)
                return redirect(url_for("index"))

            analysis_id = upload_response.json()["data"]["id"]
            print("Analysis:", analysis_id)

            analysis,status = poll_analysis(analysis_id)

            if status == 429:
                flash(
                    "VirusTotal rate limit exceeded while waiting "
                    "for the analysis to complete. "
                    "Please try again later."
                )
                return redirect(url_for("index"))
            elif analysis is None:
                flash("VirusTotal analysis timed out.")
                return redirect(url_for("index"))
            # Retrieve final report
            file_response = vt_get_file(sha256)
            if handle_vt_rate_limit(file_response):
                return redirect(url_for("index"))
            elif not file_response.ok:
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
        if handle_vt_rate_limit(behavior_response):
            return redirect(url_for("index"))
        elif behavior_response.ok:
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

@app.errorhandler(429)
def ratelimit_handler():
    logging.warning(
        "Upload rate limit exceeded from IP: %s",
        get_remote_address()
    )

    flash(
        "You've reached the upload limit. "
        "Please wait before uploading another file."
    )

    return redirect(url_for("index")), 429

@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    logging.warning("CSRF validation failed: %s", error.description)

    flash(
        "Your session has expired or the request could not be verified. "
        "Please refresh the page and try again."
    )

    return redirect(url_for("index")), 400

@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(error):
    logging.warning(
        "Oversized upload rejected: %s",
        error
    )

    flash(
        f"File is too large. Maximum allowed size is "
        f"{MAX_UPLOAD_SIZE // (1024 * 1024)} MB."
    )

    return redirect(url_for("index")), 413

if __name__ == '__main__':
    app.run()