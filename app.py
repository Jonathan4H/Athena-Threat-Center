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

    while chunk := file.stream.read(65536):
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
    file.stream.seek(0)

    if size == 0:
        return "The selected file is empty.", None

    return None, size

def vt_get_file(sha256):
    return session.get(
        f"{VT_BASE_URL}/files/{sha256}",
        timeout=15
    )

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
    start = time.time()

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

        time.sleep(5)

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

    return [
        {
            **sig,
            "severity": severity_map.get(
                sig.get("severity"),
                "UNKNOWN",
            ),
        }
        for sig in signatures
    ]

def get_severity_counts(signatures):
    """
    Count the number of behavior signatures for each severity.
    """
    counts = Counter(sig.get("severity", "UNKNOWN") for sig in signatures)

    return {
        "HIGH": counts.get("HIGH", 0),
        "MEDIUM": counts.get("MEDIUM", 0),
        "LOW": counts.get("LOW", 0),
        "INFO": counts.get("INFO", 0),
        "UNKNOWN": counts.get("UNKNOWN", 0),
        "ALL": len(signatures),
    }

def build_scan_summary(attributes):
    stats = attributes["last_analysis_stats"]

    malicious = stats.get("malicious", 0)
    total = sum(stats.values())

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

    elif malicious <= 5:
        verdict = {
            "text": "MALICIOUS",
            "icon": "🔴",
            "css": "malicious",
        }
        threat = {
            "class": "low",
            "label": "LOW RISK",
        }

    elif malicious <= 15:
        verdict = {
            "text": "MALICIOUS",
            "icon": "🔴",
            "css": "malicious",
        }
        threat = {
            "class": "medium",
            "label": "MEDIUM RISK",
        }

    else:
        verdict = {
            "text": "MALICIOUS",
            "icon": "🔴",
            "css": "malicious",
        }
        threat = {
            "class": "high",
            "label": "HIGH RISK",
        }

    return {
        "stats": stats,
        "malicious": malicious,
        "total": total,
        "threat_percent": threat_percent,
        "verdict": verdict,
        "threat": threat,
    }

@app.route("/upload", methods=["POST"])
@limiter.limit("30 per hour")
def upload_file():
    file = request.files.get("upload")

    error, file_size = validate_upload(file)

    if error:
        flash(error)
        return redirect(url_for("index"))

    try:
        # ---------------------------------
        # Compute hash
        # ---------------------------------
        sha256 = calculate_sha256(file)
        logging.debug("Computed SHA-256: %s", sha256)

        # ---------------------------------
        # Does VT already know this file?
        # ---------------------------------
        file_response = vt_get_file(sha256)
        if handle_vt_rate_limit(file_response):
            return redirect(url_for("index"))
        elif file_response.status_code == 200:
            logging.info("Existing VirusTotal report found for %s.", sha256)
            file_data = file_response.json()
        elif file_response.status_code == 404:
            logging.info("Uploading new sample '%s' to VirusTotal.", file.filename)
            upload_response = vt_post_file(file, file_size)
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
                    upload_json = upload_response.json()
                    message = upload_json["error"]["message"]
                except (ValueError, KeyError, TypeError):
                    message = upload_response.text
                flash(message)
                return redirect(url_for("index"))

            upload_json = upload_response.json()
            analysis_id = upload_json["data"]["id"]
            logging.debug("VirusTotal analysis ID: %s", analysis_id)

            _,status = poll_analysis(analysis_id)

            if status == 429:
                flash(
                    "VirusTotal rate limit exceeded while waiting "
                    "for the analysis to complete. "
                    "Please try again later."
                )
                return redirect(url_for("index"))
            elif status == 408:
                flash("VirusTotal analysis timed out.")
                return redirect(url_for("index"))
            elif status != 200:
                flash("VirusTotal analysis failed.")
                return redirect(url_for("index"))
            # ---------------------------------
            # Retrieve final report
            # VirusTotal may take a few seconds
            # to make the completed report available.
            # Retry on 404 before giving up.
            # ---------------------------------
            max_retries = 5
            retry_delay = 2  # seconds

            for attempt in range(max_retries):
                file_response = vt_get_file(sha256)

                if handle_vt_rate_limit(file_response):
                    return redirect(url_for("index"))

                if file_response.status_code == 200:
                    file_data = file_response.json()
                    break

                # Report not yet available despite completed analysis.
                if file_response.status_code == 404:
                    logging.info(
                        "Report not yet available for %s "
                        "(attempt %d/%d). Retrying...",
                        sha256,
                        attempt + 1,
                        max_retries,
                    )

                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        continue

                # Any other error (or retries exhausted)
                flash("Could not retrieve the completed VirusTotal report.")
                return redirect(url_for("index"))
        else:
            flash("VirusTotal lookup failed.")
            return redirect(url_for("index"))
        attributes = (
            file_data
            .get("data", {})
            .get("attributes")
        )
        if attributes is None:
            flash("Unexpected VirusTotal response.")
            return redirect(url_for("index"))
        scan_summary = build_scan_summary(attributes)
        stats = attributes.get("last_analysis_stats")
        if not stats:
            flash("VirusTotal report is incomplete.")
            return redirect(url_for("index"))
        behavior_data = None
        behavior_response = vt_get_behavior(sha256)
        if handle_vt_rate_limit(behavior_response):
            return redirect(url_for("index"))
        elif behavior_response.status_code == 404:
            behavior_data = None
        elif behavior_response.ok:
            behavior_data = behavior_response.json()
            data = behavior_data.get("data")
            severity_counts = None
            if data:
                signatures = data.get("signature_matches", [])

                normalized = normalize_behavior_signatures(signatures)
                data["signature_matches"] = normalized

                severity_counts = get_severity_counts(normalized)

        return render_template(
            "result.html",
            file_data=file_data,
            behavior_data=behavior_data,
            scan_summary=scan_summary,
            severity_counts=severity_counts
        )

    except requests.Timeout:
        logging.exception("VirusTotal timeout")
        flash("VirusTotal timeout")

    except requests.RequestException:
        logging.exception("Network error communicating with VirusTotal.")
        flash("Unable to communicate with VirusTotal. Please try again later.")
        return redirect(url_for("index"))

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