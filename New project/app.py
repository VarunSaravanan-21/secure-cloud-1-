import hashlib
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from io import BytesIO
from urllib.parse import urlencode

from cryptography.fernet import Fernet
from flask import Flask, Response, flash, g, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "campuschain.db")
STORAGE_DIR = os.path.join(BASE_DIR, "cloud_storage")
KEY_PATH = os.path.join(BASE_DIR, "fernet.key")
STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "s3").strip().lower()
S3_BUCKET = os.getenv("S3_BUCKET", "").strip()
S3_PREFIX = os.getenv("S3_PREFIX", "reports").strip().strip("/")
S3_REGION = os.getenv("S3_REGION", "").strip()
FIREBASE_STORAGE_BUCKET = os.getenv("FIREBASE_STORAGE_BUCKET", "").strip()
FIREBASE_CRED_PATH = os.getenv("FIREBASE_CRED_PATH", os.path.join(BASE_DIR, "firebase-service-account.json")).strip()
STUDENT_ALLOWED_EXTENSIONS = {".pdf", ".doc", ".docx"}
STUDENT_MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024
STUDENT_MAX_UPLOADS_PER_DAY = 3
RESET_TOKEN_TTL_MINUTES = 30

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")
os.makedirs(STORAGE_DIR, exist_ok=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def utc_in_minutes(minutes: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()

def parse_iso(ts: str):
    try:
        return datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return None


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_positive_int(value, default=1):
    try:
        parsed = int(value)
        return parsed if parsed > 0 else default
    except (TypeError, ValueError):
        return default


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def get_fernet() -> Fernet:
    if not os.path.exists(KEY_PATH):
        with open(KEY_PATH, "wb") as f:
            f.write(Fernet.generate_key())
    with open(KEY_PATH, "rb") as f:
        return Fernet(f.read())


def get_s3_client():
    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError("boto3 is required for S3 storage. Install with: pip install boto3") from exc
    if not S3_BUCKET:
        raise RuntimeError("S3_BUCKET is not configured.")
    kwargs = {"region_name": S3_REGION} if S3_REGION else {}
    return boto3.client("s3", **kwargs)


def get_firebase_bucket():
    try:
        import firebase_admin
        from firebase_admin import credentials, storage
    except ImportError as exc:
        raise RuntimeError("firebase-admin is required for Firebase storage. Install with: pip install firebase-admin") from exc
    if not FIREBASE_STORAGE_BUCKET:
        raise RuntimeError("FIREBASE_STORAGE_BUCKET is not configured.")
    if not os.path.exists(FIREBASE_CRED_PATH):
        raise RuntimeError(f"Firebase credentials file not found: {FIREBASE_CRED_PATH}")
    if not firebase_admin._apps:
        cred = credentials.Certificate(FIREBASE_CRED_PATH)
        firebase_admin.initialize_app(cred, {"storageBucket": FIREBASE_STORAGE_BUCKET})
    return storage.bucket()


def storage_key(storage_name: str) -> str:
    return f"{S3_PREFIX}/{storage_name}" if S3_PREFIX else storage_name


def store_encrypted_blob(storage_name: str, blob: bytes):
    if STORAGE_BACKEND == "s3":
        s3 = get_s3_client()
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=storage_key(storage_name),
            Body=blob,
            ServerSideEncryption="AES256",
        )
        return
    if STORAGE_BACKEND == "firebase":
        bucket = get_firebase_bucket()
        fblob = bucket.blob(storage_key(storage_name))
        fblob.upload_from_string(blob, content_type="application/octet-stream")
        return
    with open(os.path.join(STORAGE_DIR, storage_name), "wb") as out:
        out.write(blob)


def load_encrypted_blob(storage_name: str):
    if STORAGE_BACKEND == "s3":
        s3 = get_s3_client()
        try:
            obj = s3.get_object(Bucket=S3_BUCKET, Key=storage_key(storage_name))
            return obj["Body"].read()
        except Exception:
            return None
    if STORAGE_BACKEND == "firebase":
        try:
            bucket = get_firebase_bucket()
            fblob = bucket.blob(storage_key(storage_name))
            if not fblob.exists():
                return None
            return fblob.download_as_bytes()
        except Exception:
            return None
    local_path = os.path.join(STORAGE_DIR, storage_name)
    if not os.path.exists(local_path):
        return None
    with open(local_path, "rb") as f:
        return f.read()

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)

    return wrapper


def role_required(*roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if session.get("role") not in roles:
                flash("Access denied.", "danger")
                return redirect(url_for("dashboard"))
            return func(*args, **kwargs)

        return wrapper

    return decorator


def get_student_user_ids():
    db = get_db()
    return db.execute(
        "SELECT id, name, email FROM users WHERE role = 'student' AND status = 'active' ORDER BY name ASC"
    ).fetchall()


def can_access_report(report):
    if not report:
        return False
    role = session.get("role")
    if role in ("admin", "faculty"):
        return True
    return report["owner_user_id"] == session.get("user_id")


def write_block(action: str, entity_id: int, payload_hash: str):
    db = get_db()
    last = db.execute("SELECT block_hash FROM blockchain ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = last["block_hash"] if last else "GENESIS"
    created_at = utc_now()
    raw = f"{action}|{entity_id}|{payload_hash}|{prev_hash}|{created_at}"
    block_hash = sha256_bytes(raw.encode("utf-8"))
    db.execute(
        """
        INSERT INTO blockchain (action, entity_id, payload_hash, prev_hash, block_hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (action, entity_id, payload_hash, prev_hash, block_hash, created_at),
    )


def verify_chain() -> bool:
    db = get_db()
    rows = db.execute(
        "SELECT action, entity_id, payload_hash, prev_hash, block_hash, created_at FROM blockchain ORDER BY id ASC"
    ).fetchall()
    prev = "GENESIS"
    for row in rows:
        if row["prev_hash"] != prev:
            return False
        raw = f"{row['action']}|{row['entity_id']}|{row['payload_hash']}|{row['prev_hash']}|{row['created_at']}"
        expected = sha256_bytes(raw.encode("utf-8"))
        if expected != row["block_hash"]:
            return False
        prev = row["block_hash"]
    return True


def log_event(action: str, report_id=None, details=""):
    db = get_db()
    db.execute(
        """
        INSERT INTO activity_logs (user_id, report_id, action, details, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (session.get("user_id"), report_id, action, details, utc_now()),
    )


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'faculty', 'student')),
            student_id TEXT,
            department TEXT,
            institution TEXT,
            enrollment_year INTEGER,
            status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'inactive')),
            created_at TEXT NOT NULL
                )
        """
    )

    user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()}
    if "student_id" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN student_id TEXT")
    if "department" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN department TEXT")
    if "institution" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN institution TEXT")
    if "enrollment_year" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN enrollment_year INTEGER")

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_user_id INTEGER NOT NULL,
            report_title TEXT NOT NULL,
            original_name TEXT NOT NULL,
            storage_name TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            uploaded_by INTEGER NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS recycle_bin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER NOT NULL,
            owner_user_id INTEGER NOT NULL,
            report_title TEXT NOT NULL,
            original_name TEXT NOT NULL,
            storage_name TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            deleted_by INTEGER NOT NULL,
            deleted_at TEXT NOT NULL,
            FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (deleted_by) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS blockchain (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            entity_id INTEGER NOT NULL,
            payload_hash TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            block_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            report_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )

    default_users = [
        ("System Admin", "admin@campuschain.local", "Admin@123", "admin"),
        ("Faculty One", "faculty@campuschain.local", "Faculty@123", "faculty"),
        ("Student One", "student@campuschain.local", "Student@123", "student"),
    ]
    for name, email, password, role in default_users:
        exists = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if not exists:
            db.execute(
                """
                INSERT INTO users (name, email, password_hash, role, status, created_at)
                VALUES (?, ?, ?, ?, 'active', ?)
                """,
                (name, email, generate_password_hash(password), role, utc_now()),
            )
    db.commit()
    db.close()


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT id, name, role, status, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid email or password.", "danger")
            return render_template("login.html")
        if user["status"] != "active":
            flash("Your account is inactive. Contact admin.", "danger")
            return render_template("login.html")
        session["user_id"] = user["id"]
        session["role"] = user["role"]
        session["name"] = user["name"]
        flash(f"Welcome {user['name']}.", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/dashboard")
@login_required
def dashboard():
    db = get_db()
    role = session["role"]

    reports_query = """
        SELECT r.*, u.name AS owner_name, u.student_id AS owner_student_id, u.department AS owner_department, u.institution AS owner_institution, u.enrollment_year AS owner_enrollment_year, uploader.name AS uploader_name
        FROM reports r
        JOIN users u ON u.id = r.owner_user_id
        JOIN users uploader ON uploader.id = r.uploaded_by
    """
    if role == "student":
        reports = db.execute(reports_query + " WHERE r.owner_user_id = ? ORDER BY r.id DESC", (session["user_id"],)).fetchall()
        recycle = db.execute(
            "SELECT * FROM recycle_bin WHERE owner_user_id = ? ORDER BY id DESC",
            (session["user_id"],),
        ).fetchall()
    else:
        reports = db.execute(reports_query + " ORDER BY r.id DESC").fetchall()
        recycle = db.execute("SELECT * FROM recycle_bin ORDER BY id DESC").fetchall()

    chain_ok = verify_chain()
    storage_bucket = S3_BUCKET if STORAGE_BACKEND == "s3" else FIREBASE_STORAGE_BUCKET if STORAGE_BACKEND == "firebase" else ""
    if role == "admin":
        user_q = request.args.get("user_q", "").strip()
        report_q = request.args.get("report_q", "").strip()
        block_action = request.args.get("block_action", "").strip().lower()

        users_page = parse_positive_int(request.args.get("users_page"), 1)
        reports_page = parse_positive_int(request.args.get("reports_page"), 1)
        blocks_page = parse_positive_int(request.args.get("blocks_page"), 1)
        logs_page = parse_positive_int(request.args.get("logs_page"), 1)

        users_page_size = 10
        reports_page_size = 10
        blocks_page_size = 15
        logs_page_size = 15

        users_sql = """
            SELECT u.id, u.name, u.email, u.role, u.student_id, u.department, u.institution, u.enrollment_year, u.status, u.created_at,
                COUNT(r.id) AS report_count,
                MAX(a.created_at) AS last_activity
            FROM users u
            LEFT JOIN reports r ON r.owner_user_id = u.id
            LEFT JOIN activity_logs a ON a.user_id = u.id
        """
        users_count_sql = "SELECT COUNT(*) AS n FROM users u"
        user_params = []
        if user_q:
            users_sql += " WHERE u.name LIKE ? OR u.email LIKE ? OR u.role LIKE ?"
            users_count_sql += " WHERE u.name LIKE ? OR u.email LIKE ? OR u.role LIKE ?"
            like = f"%{user_q}%"
            user_params.extend([like, like, like])
        users_total = db.execute(users_count_sql, user_params).fetchone()["n"]
        users_pages = max(1, (users_total + users_page_size - 1) // users_page_size)
        users_page = min(users_page, users_pages)
        users_offset = (users_page - 1) * users_page_size
        users_sql += " GROUP BY u.id ORDER BY u.created_at DESC LIMIT ? OFFSET ?"
        users = db.execute(users_sql, user_params + [users_page_size, users_offset]).fetchall()

        report_filter_sql = ""
        report_params = []
        if report_q:
            report_filter_sql = " WHERE r.report_title LIKE ? OR u.name LIKE ? OR uploader.name LIKE ?"
            like = f"%{report_q}%"
            report_params = [like, like, like]
        reports_total = db.execute(
            """
            SELECT COUNT(*) AS n
            FROM reports r
            JOIN users u ON u.id = r.owner_user_id
            JOIN users uploader ON uploader.id = r.uploaded_by
            """ + report_filter_sql,
            report_params,
        ).fetchone()["n"]
        reports_pages = max(1, (reports_total + reports_page_size - 1) // reports_page_size)
        reports_page = min(reports_page, reports_pages)
        reports_offset = (reports_page - 1) * reports_page_size
        report_rows = db.execute(
            reports_query + report_filter_sql + " ORDER BY r.id DESC LIMIT ? OFFSET ?",
            report_params + [reports_page_size, reports_offset],
        ).fetchall()

        logs_total = db.execute("SELECT COUNT(*) AS n FROM activity_logs").fetchone()["n"]
        logs_pages = max(1, (logs_total + logs_page_size - 1) // logs_page_size)
        logs_page = min(logs_page, logs_pages)
        logs_offset = (logs_page - 1) * logs_page_size
        logs = db.execute(
            """
            SELECT a.*, u.name FROM activity_logs a
            JOIN users u ON u.id = a.user_id
            ORDER BY a.id DESC LIMIT ? OFFSET ?
            """,
            (logs_page_size, logs_offset),
        ).fetchall()

        blocks_filter_sql = ""
        block_params = []
        if block_action:
            blocks_filter_sql = " WHERE action = ?"
            block_params.append(block_action)
        blocks_total = db.execute(
            "SELECT COUNT(*) AS n FROM blockchain" + blocks_filter_sql,
            block_params,
        ).fetchone()["n"]
        blocks_pages = max(1, (blocks_total + blocks_page_size - 1) // blocks_page_size)
        blocks_page = min(blocks_page, blocks_pages)
        blocks_offset = (blocks_page - 1) * blocks_page_size
        blocks = db.execute(
            "SELECT id, action, entity_id, payload_hash, prev_hash, block_hash, created_at FROM blockchain"
            + blocks_filter_sql
            + " ORDER BY id DESC LIMIT ? OFFSET ?",
            block_params + [blocks_page_size, blocks_offset],
        ).fetchall()

        total_users = db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        total_reports = db.execute("SELECT COUNT(*) AS n FROM reports").fetchone()["n"]
        total_blocks = db.execute("SELECT COUNT(*) AS n FROM blockchain").fetchone()["n"]

        current_args = request.args.to_dict()

        def page_url(**kwargs):
            merged = {**current_args, **{k: str(v) for k, v in kwargs.items()}}
            return url_for("dashboard") + "?" + urlencode(merged)

        return render_template(
            "dashboard_admin.html",
            reports=report_rows,
            recycle=recycle,
            users=users,
            logs=logs,
            chain_ok=chain_ok,
            students=get_student_user_ids(),
            storage_backend=STORAGE_BACKEND,
            storage_bucket=storage_bucket,
            blocks=blocks,
            user_q=user_q,
            report_q=report_q,
            block_action=block_action,
            total_users=total_users,
            total_reports=total_reports,
            total_blocks=total_blocks,
            users_page=users_page,
            users_pages=users_pages,
            reports_page=reports_page,
            reports_pages=reports_pages,
            blocks_page=blocks_page,
            blocks_pages=blocks_pages,
            logs_page=logs_page,
            logs_pages=logs_pages,
            page_url=page_url,
        )

    if role == "faculty":
        return render_template(
            "dashboard_faculty.html",
            reports=reports,
            recycle=recycle,
            chain_ok=chain_ok,
            students=get_student_user_ids(),
            storage_backend=STORAGE_BACKEND,
            storage_bucket=storage_bucket,
        )

    return render_template("dashboard_student.html", reports=reports, recycle=recycle, chain_ok=chain_ok, storage_backend=STORAGE_BACKEND, storage_bucket=storage_bucket)



@app.get("/admin/logs/export")
@login_required
@role_required("admin")
def export_logs_csv():
    db = get_db()
    rows = db.execute(
        """
        SELECT a.id, u.name, u.email, a.action, a.report_id, a.details, a.created_at
        FROM activity_logs a
        JOIN users u ON u.id = a.user_id
        ORDER BY a.id DESC
        """
    ).fetchall()
    header = "log_id,user_name,user_email,action,report_id,details,created_at"
    csv_lines = [header]
    for r in rows:
        details = (r["details"] or "").replace('"', '""')
        csv_lines.append(
            f'{r["id"]},"{r["name"]}","{r["email"]}","{r["action"]}",{r["report_id"] or ""},"{details}","{r["created_at"]}"'
        )
    csv_data = "\n".join(csv_lines)
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=activity_logs.csv"},
    )
@app.post("/admin/users/create")
@login_required
@role_required("admin")
def create_user():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    role = request.form.get("role", "")
    student_id = request.form.get("student_id", "").strip()
    department = request.form.get("department", "").strip()
    institution = request.form.get("institution", "").strip()
    enrollment_year_raw = request.form.get("enrollment_year", "").strip()
    enrollment_year = int(enrollment_year_raw) if enrollment_year_raw.isdigit() else None

    if not name or not email or not password or role not in ("faculty", "student", "admin"):
        flash("Please enter valid user details.", "danger")
        return redirect(url_for("dashboard"))

    db = get_db()
    try:
        db.execute(
            """
            INSERT INTO users (name, email, password_hash, role, student_id, department, institution, enrollment_year, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)
            """,
            (
                name,
                email,
                generate_password_hash(password),
                role,
                student_id if role == "student" else None,
                department if role == "student" else None,
                institution if role == "student" else None,
                enrollment_year if role == "student" else None,
                utc_now(),
            ),
        )
        db.commit()
        log_event("user_create", details=f"Created {role}: {email}")
        db.commit()
        flash("User created successfully.", "success")
    except sqlite3.IntegrityError:
        flash("Email already exists.", "danger")
    return redirect(url_for("dashboard"))

@app.post("/admin/users/<int:user_id>/toggle")
@login_required
@role_required("admin")
def toggle_user(user_id):
    db = get_db()
    user = db.execute("SELECT id, status, role FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("dashboard"))
    if user["id"] == session["user_id"]:
        flash("You cannot disable your own account.", "danger")
        return redirect(url_for("dashboard"))
    new_status = "inactive" if user["status"] == "active" else "active"
    db.execute("UPDATE users SET status = ? WHERE id = ?", (new_status, user_id))
    log_event("user_status_update", details=f"User #{user_id} -> {new_status}")
    db.commit()
    flash(f"User status changed to {new_status}.", "success")
    return redirect(url_for("dashboard"))


@app.post("/reports/upload")
@login_required
def upload_report():
    if "file" not in request.files:
        flash("Select a file to upload.", "danger")
        return redirect(url_for("dashboard"))
    file = request.files["file"]
    if not file.filename:
        flash("Invalid file name.", "danger")
        return redirect(url_for("dashboard"))

    role = session["role"]
    owner_user_id = session["user_id"]
    if role in ("admin", "faculty"):
        owner_user_id = int(request.form.get("student_id", 0) or 0)
        if owner_user_id <= 0:
            flash("Select a student.", "danger")
            return redirect(url_for("dashboard"))

    db = get_db()
    student = db.execute(
        "SELECT id FROM users WHERE id = ? AND role = 'student' AND status = 'active'",
        (owner_user_id,),
    ).fetchone()
    if not student:
        flash("Target student account not found.", "danger")
        return redirect(url_for("dashboard"))

    plaintext = file.read()
    if role == "student":
        _, ext = os.path.splitext(file.filename.lower())
        if ext not in STUDENT_ALLOWED_EXTENSIONS:
            flash("Students can upload only PDF, DOC, or DOCX files.", "danger")
            return redirect(url_for("dashboard"))
        if len(plaintext) > STUDENT_MAX_FILE_SIZE_BYTES:
            flash("Student upload limit is 5 MB per file.", "danger")
            return redirect(url_for("dashboard"))
        day_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        uploads_today = db.execute(
            """
            SELECT COUNT(*) AS total
            FROM reports
            WHERE uploaded_by = ? AND uploaded_at >= ?
            """,
            (session["user_id"], day_start),
        ).fetchone()["total"]
        if uploads_today >= STUDENT_MAX_UPLOADS_PER_DAY:
            flash("Student daily limit reached (3 uploads per day).", "danger")
            return redirect(url_for("dashboard"))
    encrypted = get_fernet().encrypt(plaintext)
    storage_name = f"{uuid.uuid4().hex}_{file.filename}.enc"
    try:
        store_encrypted_blob(storage_name, encrypted)
    except Exception as exc:
        flash(f"Storage error: {exc}", "danger")
        return redirect(url_for("dashboard"))

    report_title = request.form.get("report_title", "").strip() or file.filename
    file_hash = sha256_bytes(plaintext)
    cur = db.execute(
        """
        INSERT INTO reports (owner_user_id, report_title, original_name, storage_name, file_hash, uploaded_by, uploaded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (owner_user_id, report_title, file.filename, storage_name, file_hash, session["user_id"], utc_now()),
    )
    report_id = cur.lastrowid
    write_block("upload", report_id, file_hash)
    log_event("upload", report_id=report_id, details=report_title)
    db.commit()
    flash("Report uploaded and committed to blockchain.", "success")
    return redirect(url_for("dashboard"))


@app.get("/reports/<int:report_id>/download")
@login_required
def download_report(report_id):
    db = get_db()
    report = db.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    if not can_access_report(report):
        flash("Report not accessible.", "danger")
        return redirect(url_for("dashboard"))
    encrypted = load_encrypted_blob(report["storage_name"])
    if not encrypted:
        flash("Stored file missing.", "danger")
        return redirect(url_for("dashboard"))
    decrypted = get_fernet().decrypt(encrypted)
    log_event("download", report_id=report_id, details=report["report_title"])
    db.commit()
    return send_file(
        BytesIO(decrypted),
        as_attachment=True,
        download_name=report["original_name"],
        mimetype="application/octet-stream",
    )


@app.post("/reports/<int:report_id>/verify")
@login_required
def verify_report(report_id):
    db = get_db()
    report = db.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    if not can_access_report(report):
        flash("Report not accessible.", "danger")
        return redirect(url_for("dashboard"))
    encrypted = load_encrypted_blob(report["storage_name"])
    if not encrypted:
        flash("Stored file missing.", "danger")
        return redirect(url_for("dashboard"))
    decrypted = get_fernet().decrypt(encrypted)
    current_hash = sha256_bytes(decrypted)
    is_same = current_hash == report["file_hash"]
    chain_ok = verify_chain()
    status = "verified" if is_same and chain_ok else "verification failed"
    log_event("verify", report_id=report_id, details=status)
    db.commit()
    flash(f"Verification result: {status}.", "success" if is_same and chain_ok else "danger")
    return redirect(url_for("dashboard"))


@app.post("/reports/<int:report_id>/delete")
@login_required
def delete_report(report_id):
    db = get_db()
    report = db.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    if not can_access_report(report):
        flash("Report not accessible.", "danger")
        return redirect(url_for("dashboard"))
    if session["role"] == "student" and report["uploaded_by"] != session["user_id"]:
        flash("Students can delete only reports they uploaded themselves.", "danger")
        return redirect(url_for("dashboard"))

    db.execute(
        """
        INSERT INTO recycle_bin (report_id, owner_user_id, report_title, original_name, storage_name, file_hash, deleted_by, deleted_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            report["id"],
            report["owner_user_id"],
            report["report_title"],
            report["original_name"],
            report["storage_name"],
            report["file_hash"],
            session["user_id"],
            utc_now(),
        ),
    )
    db.execute("DELETE FROM reports WHERE id = ?", (report_id,))
    write_block("delete", report_id, report["file_hash"])
    log_event("delete", report_id=report_id, details=report["report_title"])
    db.commit()
    flash("Report moved to recovery bin.", "success")
    return redirect(url_for("dashboard"))


@app.post("/reports/recover/<int:bin_id>")
@login_required
def recover_report(bin_id):
    db = get_db()
    item = db.execute("SELECT * FROM recycle_bin WHERE id = ?", (bin_id,)).fetchone()
    if not item:
        flash("Recovery item not found.", "danger")
        return redirect(url_for("dashboard"))
    if session["role"] == "student" and item["owner_user_id"] != session["user_id"]:
        flash("Access denied.", "danger")
        return redirect(url_for("dashboard"))
    cur = db.execute(
        """
        INSERT INTO reports (owner_user_id, report_title, original_name, storage_name, file_hash, uploaded_by, uploaded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            item["owner_user_id"],
            item["report_title"],
            item["original_name"],
            item["storage_name"],
            item["file_hash"],
            session["user_id"],
            utc_now(),
        ),
    )
    new_report_id = cur.lastrowid
    db.execute("DELETE FROM recycle_bin WHERE id = ?", (bin_id,))
    write_block("recover", new_report_id, item["file_hash"])
    log_event("recover", report_id=new_report_id, details=item["report_title"])
    db.commit()
    flash("Report recovered successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    reset_token = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        db = get_db()
        user = db.execute(
            "SELECT id, status FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if user and user["status"] == "active":
            reset_token = uuid.uuid4().hex
            db.execute(
                """
                INSERT INTO password_resets (user_id, token, expires_at, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (user["id"], reset_token, utc_in_minutes(RESET_TOKEN_TTL_MINUTES), utc_now()),
            )
            db.commit()
        flash("If the account exists and is active, a reset token was generated.", "success")
    return render_template("forgot_password.html", reset_token=reset_token)


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    token = request.values.get("token", "").strip()
    if request.method == "POST":
        new_password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        if len(new_password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template("reset_password.html", token=token)
        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html", token=token)
        db = get_db()
        reset = db.execute(
            """
            SELECT id, user_id, expires_at, used_at
            FROM password_resets
            WHERE token = ?
            """,
            (token,),
        ).fetchone()
        if not reset:
            flash("Invalid reset token.", "danger")
            return render_template("reset_password.html", token=token)
        if reset["used_at"]:
            flash("Reset token already used.", "danger")
            return render_template("reset_password.html", token=token)
        expires_at = parse_iso(reset["expires_at"])
        if not expires_at or expires_at < datetime.now(timezone.utc):
            flash("Reset token has expired.", "danger")
            return render_template("reset_password.html", token=token)
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), reset["user_id"]),
        )
        db.execute(
            "UPDATE password_resets SET used_at = ? WHERE id = ?",
            (utc_now(), reset["id"]),
        )
        db.commit()
        flash("Password reset successful. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html", token=token)
@app.get("/health")
def health():
    return {"status": "ok", "blockchain_valid": verify_chain(), "storage_backend": STORAGE_BACKEND}


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)































































