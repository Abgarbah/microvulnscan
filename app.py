import json
import os
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

import jwt
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)

from config import Config
from container_scan.dockerfile_analyzer import DockerfileAnalyzer
from database.models import ScanResult, ScanRun, User, init_db
from reports.report_generator import ReportGenerator
from risk_engine.risk_calculator import RiskCalculator
from scanner.api_scanner import APIVulnerabilityScanner
from scanner.cve_utils import CVEEnricher


class SlidingWindowRateLimiter:
    def __init__(self, max_requests, window_seconds):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.events = defaultdict(deque)

    def allow(self, key):
        now = datetime.utcnow()
        earliest = now - timedelta(seconds=self.window_seconds)
        q = self.events[key]

        while q and q[0] < earliest:
            q.popleft()

        if len(q) >= self.max_requests:
            retry_after = (q[0] + timedelta(seconds=self.window_seconds) - now).total_seconds()
            return False, max(1, int(retry_after))

        q.append(now)
        return True, 0


class VulnerabilityOrchestrator:
    def __init__(self, session_factory):
        self.api_scanner = APIVulnerabilityScanner(
            timeout=Config.DEFAULT_TIMEOUT,
            max_scan_seconds=Config.MAX_SCAN_SECONDS,
        )
        self.container_scanner = DockerfileAnalyzer(
            trivy_enabled=Config.TRIVY_ENABLED,
            trivy_command=Config.TRIVY_COMMAND,
            trivy_timeout_seconds=Config.TRIVY_TIMEOUT_SECONDS,
            trivy_max_findings=Config.TRIVY_MAX_FINDINGS,
        )
        self.cve_enricher = CVEEnricher(
            enabled=Config.NVD_ENRICH_ENABLED,
            api_key=Config.NVD_API_KEY,
            timeout_seconds=Config.NVD_TIMEOUT_SECONDS,
            min_interval_seconds=Config.NVD_MIN_INTERVAL_SECONDS,
        )
        self.risk_engine = RiskCalculator()
        self.reporter = ReportGenerator(output_dir=Config.REPORTS_DIR)
        self.session_factory = session_factory

    def run(self, base_url=None, endpoints=None, dockerfile_path=None, source="web", triggered_by="unknown"):
        api_findings = []
        container_findings = []

        if base_url and endpoints:
            api_findings = self.api_scanner.scan(base_url, endpoints[: Config.MAX_ENDPOINTS])

        if dockerfile_path:
            container_findings = self.container_scanner.scan(dockerfile_path)

        api_findings = self.cve_enricher.enrich_findings(api_findings)
        container_findings = self.cve_enricher.enrich_findings(container_findings)
        api_findings = self._deduplicate_findings(api_findings)
        container_findings = self._deduplicate_findings(container_findings)
        all_findings = self._deduplicate_findings(api_findings + container_findings)
        risk_summary = self.risk_engine.calculate(all_findings)
        scan_info = {
            "target": base_url or dockerfile_path or "Not specified",
            "scanner": "microvulnscan",
            "status": "Completed",
        }
        report_paths = self.reporter.generate(api_findings, container_findings, risk_summary, scan_info=scan_info)

        scan_run_id = self._persist(
            base_url=base_url,
            dockerfile_path=dockerfile_path,
            source=source,
            triggered_by=triggered_by,
            report_path=report_paths["json"],
            risk_summary=risk_summary,
            findings=all_findings,
        )

        return {
            "scan_run_id": scan_run_id,
            "api_findings": api_findings,
            "container_findings": container_findings,
            "risk_summary": risk_summary,
            "report_exports": report_paths,
        }

    def _deduplicate_findings(self, findings):
        unique = []
        seen = set()
        for finding in findings:
            key = (
                finding.get("target"),
                finding.get("endpoint"),
                finding.get("name") or finding.get("type"),
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique

    def _persist(self, base_url, dockerfile_path, source, triggered_by, report_path, risk_summary, findings):
        db = self.session_factory()
        try:
            scan_run = ScanRun(
                source=source,
                triggered_by=triggered_by,
                base_url=base_url,
                dockerfile_path=dockerfile_path,
                report_path=report_path,
                risk_level=risk_summary["risk_level"],
                total_score=risk_summary["total_score"],
                summary_json=json.dumps(risk_summary),
            )
            db.add(scan_run)
            db.flush()

            for finding in findings:
                db.add(
                    ScanResult(
                        scan_run_id=scan_run.id,
                        target=finding.get("target", "unknown"),
                        category=finding.get("category", "unknown"),
                        issue_type=finding.get("name") or finding.get("type", "UnknownIssue"),
                        severity=finding.get("severity", "Low"),
                        cve_id=finding.get("cve_id"),
                        cvss_score=finding.get("cvss_score"),
                        description=finding.get("description", "No description provided."),
                        payload=finding.get("payload"),
                        status_code=finding.get("status_code"),
                        status=finding.get("status"),
                    )
                )

            db.commit()
            return scan_run.id
        finally:
            db.close()


app = Flask(__name__)
app.config.from_object(Config)
os.makedirs(app.config["DOCKERFILE_UPLOAD_DIR"], exist_ok=True)
SessionLocal = init_db(app.config["SQLALCHEMY_DATABASE_URI"])
orchestrator = VulnerabilityOrchestrator(SessionLocal)
rate_limiter = SlidingWindowRateLimiter(
    max_requests=app.config["RATE_LIMIT_REQUESTS"],
    window_seconds=app.config["RATE_LIMIT_WINDOW_SECONDS"],
)


def _is_api_route():
    return request.path.startswith("/api/")


def _create_jwt(subject):
    now = datetime.utcnow()
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + timedelta(minutes=app.config["JWT_EXP_MINUTES"]),
    }
    return jwt.encode(payload, app.config["JWT_SECRET"], algorithm=app.config["JWT_ALGORITHM"])


def _decode_jwt(token):
    return jwt.decode(token, app.config["JWT_SECRET"], algorithms=[app.config["JWT_ALGORITHM"]])


def _extract_bearer_token():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header.split(" ", 1)[1].strip()

    if request.is_json:
        data = request.get_json(silent=True) or {}
        if data.get("token"):
            return data["token"]

    return request.form.get("token") or request.args.get("token") or session.get("access_token")


def require_jwt(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        token = _extract_bearer_token()
        if not token:
            if _is_api_route():
                return jsonify({"error": "Unauthorized"}), 401
            flash("Authentication required. Please sign in.", "error")
            return redirect(url_for("login"))

        try:
            g.jwt_claims = _decode_jwt(token)
        except jwt.ExpiredSignatureError:
            session.pop("access_token", None)
            if _is_api_route():
                return jsonify({"error": "Token expired"}), 401
            flash("Session expired. Please sign in again.", "error")
            return redirect(url_for("login"))
        except jwt.InvalidTokenError:
            session.pop("access_token", None)
            if _is_api_route():
                return jsonify({"error": "Invalid token"}), 401
            flash("Invalid token. Please sign in again.", "error")
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped


def rate_limit(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        client_id = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
        allowed, retry_after = rate_limiter.allow(client_id)
        if allowed:
            return view(*args, **kwargs)

        if _is_api_route():
            return jsonify({"error": "Rate limit exceeded", "retry_after_seconds": retry_after}), 429

        flash(f"Rate limit exceeded. Retry in {retry_after} seconds.", "error")
        return redirect(url_for("dashboard"))

    return wrapped


def _parse_endpoints(raw):
    if not raw:
        return []
    normalized = raw.replace("\\n", ",").replace("\n", ",")
    return [item.strip() for item in normalized.split(",") if item.strip()]


def _is_self_scan_target(base_url):
    if not base_url:
        return False
    try:
        target = urlparse(base_url)
        request_host = request.host.split(":")[0]
        target_host = (target.hostname or "").strip().lower()
        return target_host in {"127.0.0.1", "localhost", request_host.lower()}
    except Exception:
        return False


def _save_uploaded_dockerfile(file_storage):
    if not file_storage or not file_storage.filename:
        return None, None

    original_name = secure_filename(file_storage.filename) or "Dockerfile"
    lower_name = original_name.lower()
    allowed = lower_name == "dockerfile" or lower_name.endswith((".dockerfile", ".txt", ".dockerfile.txt"))
    if not allowed:
        return None, "Upload a Dockerfile, .dockerfile, or .txt file."

    data = file_storage.read(app.config["MAX_DOCKERFILE_UPLOAD_BYTES"] + 1)
    if len(data) > app.config["MAX_DOCKERFILE_UPLOAD_BYTES"]:
        max_kb = app.config["MAX_DOCKERFILE_UPLOAD_BYTES"] // 1024
        return None, f"Dockerfile upload is too large. Maximum size is {max_kb} KB."

    upload_name = f"{uuid.uuid4().hex}_{original_name}"
    upload_path = os.path.join(app.config["DOCKERFILE_UPLOAD_DIR"], upload_name)
    with open(upload_path, "wb") as uploaded:
        uploaded.write(data)

    return upload_path, None


def _derive_report_files(report_json_path):
    base_name = os.path.splitext(os.path.basename(report_json_path))[0]
    return {
        "json": f"{base_name}.json",
        "html": f"{base_name}.html",
        "pdf": f"{base_name}.pdf",
    }


def _authenticate_credentials(username, password):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if user and check_password_hash(user.password_hash, password):
            return True
    finally:
        db.close()

    return username == app.config["AUTH_USERNAME"] and password == app.config["AUTH_PASSWORD"]


@app.route("/")
def index():
    if session.get("access_token"):
        return redirect(url_for("dashboard"))
    return render_template("index.html", app_name=app.config["APP_NAME"])


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("access_token"):
            return redirect(url_for("dashboard"))
        return render_template("login.html", app_name=app.config["APP_NAME"])

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if not _authenticate_credentials(username, password):
        flash("Invalid username or password.", "error")
        return redirect(url_for("login"))

    session["access_token"] = _create_jwt(username)
    return redirect(url_for("dashboard"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        if session.get("access_token"):
            return redirect(url_for("dashboard"))
        return render_template("signup.html", app_name=app.config["APP_NAME"])

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    confirm_password = request.form.get("confirm_password") or ""

    if len(username) < 3:
        flash("Username must be at least 3 characters.", "error")
        return redirect(url_for("signup"))

    if len(password) < 8:
        flash("Password must be at least 8 characters.", "error")
        return redirect(url_for("signup"))

    if password != confirm_password:
        flash("Passwords do not match.", "error")
        return redirect(url_for("signup"))

    db = SessionLocal()
    try:
        exists = db.query(User).filter(User.username == username).first()
        if exists:
            flash("Username already exists.", "error")
            return redirect(url_for("signup"))

        db.add(User(username=username, password_hash=generate_password_hash(password)))
        db.commit()
    finally:
        db.close()

    flash("Account created. You can sign in now.", "success")
    return redirect(url_for("login"))


@app.route("/logout", methods=["POST"])
@require_jwt
def logout():
    session.pop("access_token", None)
    return redirect(url_for("login"))


@app.route("/api/token", methods=["POST"])
def issue_api_token():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not _authenticate_credentials(username, password):
        return jsonify({"error": "Invalid credentials"}), 401

    token = _create_jwt(username)
    return jsonify({"access_token": token, "token_type": "Bearer", "expires_in_minutes": app.config["JWT_EXP_MINUTES"]})


@app.route("/dashboard", methods=["GET"])
@require_jwt
def dashboard():
    return render_template("dashboard.html", app_name=app.config["APP_NAME"])


@app.route("/runs", methods=["GET"])
@require_jwt
def runs():
    db = SessionLocal()
    try:
        scan_runs = db.query(ScanRun).order_by(ScanRun.created_at.desc()).limit(20).all()
        runs_view = []
        for run in scan_runs:
            runs_view.append(
                {
                    "id": run.id,
                    "created_at": run.created_at,
                    "risk_level": run.risk_level,
                    "total_score": run.total_score,
                    "source": run.source,
                    "report_files": _derive_report_files(run.report_path),
                }
            )
    finally:
        db.close()

    return render_template("runs.html", app_name=app.config["APP_NAME"], runs=runs_view)


@app.route("/scan", methods=["POST"])
@require_jwt
@rate_limit
def run_scan_web():
    base_url = (request.form.get("base_url") or "").strip() or None
    endpoints = _parse_endpoints(request.form.get("endpoints", ""))
    uploaded_path, upload_error = _save_uploaded_dockerfile(request.files.get("dockerfile_upload"))

    if upload_error:
        flash(upload_error, "error")
        return redirect(url_for("dashboard"))
    dockerfile_path = uploaded_path

    if not base_url and not dockerfile_path:
        flash("Provide at least one scan target (base URL or Dockerfile upload).", "error")
        return redirect(url_for("dashboard"))
    if _is_self_scan_target(base_url):
        if uploaded_path:
            try:
                os.remove(uploaded_path)
            except OSError:
                pass
        flash("Self-target scan blocked. Use another API host to avoid request deadlock.", "error")
        return redirect(url_for("dashboard"))

    try:
        result = orchestrator.run(
            base_url=base_url,
            endpoints=endpoints,
            dockerfile_path=dockerfile_path,
            source="web",
            triggered_by=g.jwt_claims.get("sub", request.remote_addr or "unknown"),
        )
    finally:
        if uploaded_path:
            try:
                os.remove(uploaded_path)
            except OSError:
                pass

    return redirect(url_for("results", scan_run_id=result["scan_run_id"]))


@app.route("/api/scan", methods=["POST"])
@require_jwt
@rate_limit
def run_scan_api():
    data = request.get_json(silent=True) or {}
    base_url = (data.get("base_url") or "").strip() or None
    dockerfile_path = (data.get("dockerfile_path") or "").strip() or None
    endpoints = data.get("endpoints") or []

    if isinstance(endpoints, str):
        endpoints = _parse_endpoints(endpoints)

    if not base_url and not dockerfile_path:
        return jsonify({"error": "Provide base_url or dockerfile_path"}), 400
    if _is_self_scan_target(base_url):
        return jsonify({"error": "Self-target scan blocked. Use another API host."}), 400

    result = orchestrator.run(
        base_url=base_url,
        endpoints=endpoints,
        dockerfile_path=dockerfile_path,
        source="api",
        triggered_by=g.jwt_claims.get("sub", request.remote_addr or "unknown"),
    )
    return jsonify(result), 200


@app.route("/results/<int:scan_run_id>", methods=["GET"])
@require_jwt
def results(scan_run_id):
    db = SessionLocal()
    try:
        run = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
        if not run:
            flash("Scan run not found.", "error")
            return redirect(url_for("dashboard"))

        findings = (
            db.query(ScanResult)
            .filter(ScanResult.scan_run_id == scan_run_id)
            .order_by(ScanResult.severity.desc(), ScanResult.id.asc())
            .all()
        )
        risk_summary = json.loads(run.summary_json)
        report_files = _derive_report_files(run.report_path)
    finally:
        db.close()

    return render_template(
        "results.html",
        run=run,
        findings=findings,
        risk_summary=risk_summary,
        report_files=report_files,
    )


@app.route("/reports/<path:filename>", methods=["GET"])
@require_jwt
def download_report(filename):
    safe_name = os.path.basename(filename)
    if not safe_name.endswith((".json", ".html", ".pdf")):
        return jsonify({"error": "Unsupported report type"}), 400
    return send_from_directory(app.config["REPORTS_DIR"], safe_name, as_attachment=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
