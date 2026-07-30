from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import RequestEntityTooLarge
from collections import Counter
import requests
import time
import logging
import config
import hashlib

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

limiter = Limiter(
    key_func=get_remote_address,
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

    while chunk := file.stream.read(1024 * 1024):
        sha256.update(chunk)

    file.stream.seek(0)

    return sha256.hexdigest()

def validate_upload(file):
    """
    Perform basic validation before hashing or uploading.

    Returns:
        (None, file_size) if the file is valid.
        (error_message, None) otherwise.
    """

    if file is None:
        return "No file was uploaded.", None

    if not file.filename:
        return "Please choose a file.", None

    # Determine file size once
    file.stream.seek(0, 2)
    size = file.stream.tell()

    if size == 0:
        return "The selected file is empty.", None

    return None, size

def vt_get_file(sha256):
    logging.info("Looking up %s", sha256)
    response = session.get(
        f"{VT_BASE_URL}/files/{sha256}",
        timeout=(5, 30)
    )
    logging.info(
        "Lookup finished (%d)",
        response.status_code
    )
    return response

def vt_post_file(file, file_size):
    files = {
        "file": (file.filename, file.stream, file.content_type or "application/octet-stream")
    }

    # <=32 MB
    if file_size <= 32 * 1024 * 1024:
        return session.post(
            f"{VT_BASE_URL}/files",
            files=files,
            timeout=30
        )

    # >32 MB
    upload_url = session.get(
        f"{VT_BASE_URL}/files/upload_url",
        timeout=15
    )

    if handle_vt_rate_limit(upload_url):
        return upload_url

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
    start = time.monotonic()
    delay = 3
    max_delay = 10

    while time.time() - start < timeout:
        response = vt_get_analysis(analysis_id)
        if response.status_code == 429:
            return None, 429

        if response.status_code != 200:
            return None, response.status_code

        data = response.json()
        status = data["data"]["attributes"]["status"]

        logging.debug(
            "VirusTotal analysis %s status: %s",
            analysis_id,
            status,
        )

        if status == "completed":
            logging.debug(
                "VirusTotal analysis %s completed.",
                analysis_id,
            )
            return data, 200

        logging.debug(
            "Analysis not complete. Waiting %d seconds before retrying.",
            delay,
        )

        remaining = timeout - (time.time() - start)
        time.sleep(min(delay, max(0, remaining)))

        delay = min(delay * 2, max_delay)

    logging.warning(
        "VirusTotal analysis %s timed out after %d seconds.",
        analysis_id,
        timeout,
    )

    return None, 408

def normalize_behavior_signatures(signatures):
    severity_map = {
        "IMPACT_SEVERITY_HIGH": "HIGH",
        "IMPACT_SEVERITY_MEDIUM": "MEDIUM",
        "IMPACT_SEVERITY_LOW": "LOW",
        "IMPACT_SEVERITY_INFO": "INFO"
    }

    counts = Counter()

    for sig in signatures:
        severity = severity_map.get(
            sig.get("severity"),
            "UNKNOWN",
        )

        sig["severity"] = severity
        counts[severity] += 1

    return {
        "HIGH": counts["HIGH"],
        "MEDIUM": counts["MEDIUM"],
        "LOW": counts["LOW"],
        "INFO": counts["INFO"],
        "UNKNOWN": counts["UNKNOWN"],
        "ALL": len(signatures),
    }

def build_scan_data(attributes):
    """
    Build the scan summary and grouped engine results in a single pass.
    """

    categories = [
        ("malicious", "Malicious", "🔴"),
        ("suspicious", "Suspicious", "🟠"),
        ("undetected", "Undetected", "🟢"),
        ("harmless", "Harmless", "🟢"),
        ("timeout", "Timeout", "⚪"),
        ("failure", "Failure", "🟣"),
        ("other", "Other", "🔹"),
    ]

    grouped = {
        key: {
            "title": title,
            "icon": icon,
            "css": key,
            "items": [],
        }
        for key, title, icon in categories
    }

    malicious = 0
    total = 0

    analysis_results = attributes.get("last_analysis_results", {})

    for engine, result in analysis_results.items():
        category = result.get("category", "other")

        if category not in grouped:
            category = "other"

        grouped[category]["items"].append({
            "engine": engine,
            "result": result,
        })

        total += 1

        if category == "malicious":
            malicious += 1

    threat_percent = min((malicious / 15) * 100, 100)

    if malicious == 0:
        verdict = {
            "text": "CLEAN",
            "icon": "🟢",
            "css": "clean",
        }
        threat = {
            "class": "safe",
            "label": "SAFE",
        }
    else:
        verdict = {
            "text": "MALICIOUS",
            "icon": "🔴",
            "css": "malicious",
        }

        if malicious <= 5:
            risk = ("low", "LOW RISK")
        elif malicious <= 15:
            risk = ("medium", "MEDIUM RISK")
        else:
            risk = ("high", "HIGH RISK")

        threat = {
            "class": risk[0],
            "label": risk[1],
        }

    scan_summary = {
        "malicious": malicious,
        "total": total,
        "threat_percent": threat_percent,
        "verdict": verdict,
        "threat": threat,
    }

    scan_groups = [
        grouped[key]
        for key, _, _ in categories
        if grouped[key]["items"]
    ]

    return scan_summary, scan_groups

def get_or_create_report(file, sha256, file_size):
    response = vt_get_file(sha256)

    if handle_vt_rate_limit(response):
        return None

    if response.status_code == 200:
        return response.json()

    if response.status_code == 404:
        return upload_new_sample(file, sha256, file_size)

    flash("VirusTotal lookup failed.")
    return None

def upload_new_sample(file, sha256, file_size):
    upload = vt_post_file(file, file_size)

    if handle_vt_rate_limit(upload):
        return None

    if upload.status_code == 409:
        flash("This sample is already being analyzed.")
        return None

    if not upload.ok:
        ...
        return None

    analysis_id = upload.json()["data"]["id"]

    _, status = poll_analysis(analysis_id)

    if status != 200:
        ...
        return None

    return retrieve_completed_report(sha256)

def retrieve_completed_report(
    sha256,
    retries=5,
    delay=2,
):
    for attempt in range(retries):

        response = vt_get_file(sha256)

        if handle_vt_rate_limit(response):
            return None

        if response.status_code == 200:
            return response.json()

        if response.status_code != 404:
            break

        if attempt < retries - 1:
            time.sleep(delay)

    flash("Could not retrieve the completed VirusTotal report.")
    return None

def fetch_behavior_data(sha256):
    response = vt_get_behavior(sha256)

    if handle_vt_rate_limit(response):
        return None, None

    if response.status_code == 404:
        return None, None

    if not response.ok:
        return None, None

    behavior = response.json()

    signatures = (
        behavior.get("data", {})
        .get("signature_matches", [])
    )

    counts = normalize_behavior_signatures(signatures)

    return behavior, counts

def build_result_context(file_data, sha256, filename):
    """
    Prepare all data required by result.html.

    Returns:
        dict | None
    """

    attributes = (
        file_data
        .get("data", {})
        .get("attributes")
    )

    if not attributes:
        flash("Unexpected VirusTotal response.")
        return None

    analysis_results = attributes.get("last_analysis_results")

    if not analysis_results:
        flash("VirusTotal report is incomplete.")
        return None

    size_mb = f"{attributes['size'] / (1024 * 1024):,.2f}"

    scan_summary, scan_groups = build_scan_data(attributes)

    behavior_data, severity_counts = fetch_behavior_data(sha256)

    return {
        "attributes": attributes,
        "behavior_data": behavior_data,
        "scan_summary": scan_summary,
        "severity_counts": severity_counts,
        "scan_groups": scan_groups,
        "filename": filename,
        "size_mb": size_mb,
    }

def render_scan_result(context):
    return render_template(
        "result.html",
        **context,
    )

@app.route("/upload", methods=["POST"])
@limiter.limit("30 per hour")
def upload_file():
    file = request.files.get("upload")

    error, file_size = validate_upload(file)
    if error:
        flash(error)
        return redirect(url_for("index"))

    try:
        sha256 = calculate_sha256(file)

        file_data = get_or_create_report(
            file=file,
            sha256=sha256,
            file_size=file_size,
        )

        if file_data is None:
            return redirect(url_for("index"))

        context = build_result_context(
            file_data=file_data,
            sha256=sha256,
            filename=file.filename,
        )

        if context is None:
            return redirect(url_for("index"))

        return render_scan_result(context)

    except requests.Timeout:
        logging.exception("VirusTotal timeout")
        flash("VirusTotal timeout")

    except requests.RequestException:
        logging.exception("Network error communicating with VirusTotal.")
        flash("Unable to communicate with VirusTotal. Please try again later.")

    except Exception:
        logging.exception("Unexpected error")
        flash("Unexpected server error")

    return redirect(url_for("index"))

@app.errorhandler(429)
def ratelimit_handler(error):
    logging.warning(
        "Rate limit exceeded: %s",
        error
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