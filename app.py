import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, g, redirect, render_template, request, session, url_for, flash, send_from_directory

# Basic Flask setup
app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-change-me"
app.config["DATABASE"] = os.path.join(os.path.dirname(__file__), "grievances.db")
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
app.config["ALLOWED_EXTENSIONS"] = {"png", "jpg", "jpeg", "gif"}
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS grievances (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            image_path TEXT,
            votes INTEGER DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'In Progress',
            created_at TEXT NOT NULL,
            FOREIGN KEY(student_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            grievance_id INTEGER NOT NULL,
            staff_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(grievance_id, staff_id),
            FOREIGN KEY(grievance_id) REFERENCES grievances(id),
            FOREIGN KEY(staff_id) REFERENCES users(id)
        );
        """
    )
    db.commit()

    # add status column for existing databases (best-effort)
    try:
        db.execute("ALTER TABLE grievances ADD COLUMN status TEXT NOT NULL DEFAULT 'In Progress'")
        db.commit()
    except sqlite3.OperationalError:
        # column likely exists
        pass

    # seed minimal users
    default_users = [
        ("admin", "admin123", "admin"),
        ("staff1", "staff123", "staff"),
        ("student1", "student123", "student"),
    ]
    for username, password, role in default_users:
        try:
            db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
        except sqlite3.IntegrityError:
            pass
    db.commit()


def login_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                flash("You are not authorized to access that page.", "danger")
                return redirect(url_for("dashboard"))
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def categorize_grievance(title: str, description: str) -> str:
    """
    Lightweight keyword-based classifier to mimic AI category detection.
    """
    text = f"{title} {description}".lower()
    if any(k in text for k in ["exam", "grade", "classroom", "class", "result", "lecture"]):
        return "Academic"
    if any(k in text for k in ["hostel", "room", "dorm"]):
        return "Hostel"
    if any(k in text for k in ["canteen", "mess", "cafeteria"]):
        return "Canteen"
    if any(k in text for k in ["food", "meal", "hygiene"]):
        return "Foods"
    if any(k in text for k in ["fee", "fees", "scholarship", "payment", "finance", "bill"]):
        return "Finance"
    if any(k in text for k in ["facility", "facilities", "infrastructure", "maintenance", "wifi", "water"]):
        return "Facilities"
    if any(k in text for k in ["safety", "security", "bully", "harass"]):
        return "Safety"
    return "General"


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?", (username, password)
        ).fetchone()
        if user:
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["username"] = user["username"]
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.", "danger")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role")
        if role not in {"student", "staff"}:
            flash("Choose student or staff.", "warning")
            return render_template("register.html")
        if not username or not password:
            flash("Username and password required.", "warning")
            return render_template("register.html")
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, password, role),
            )
            db.commit()
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already taken.", "danger")
    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if "role" not in session:
        return redirect(url_for("login"))
    role = session["role"]
    db = get_db()
    if role == "student":
        grievances = db.execute(
            "SELECT g.*, u.username as student_name FROM grievances g JOIN users u ON g.student_id = u.id ORDER BY g.created_at DESC"
        ).fetchall()
        return render_template("student_dashboard.html", grievances=grievances)
    if role == "staff":
        grievances = db.execute(
            "SELECT * FROM grievances ORDER BY created_at DESC"
        ).fetchall()
        voted_ids = {
            row["grievance_id"]
            for row in db.execute(
                "SELECT grievance_id FROM votes WHERE staff_id = ?", (session["user_id"],)
            ).fetchall()
        }
        return render_template("staff_dashboard.html", grievances=grievances, voted_ids=voted_ids)
    if role == "admin":
        grievances = db.execute(
            "SELECT g.*, u.username as student_name FROM grievances g JOIN users u ON g.student_id = u.id ORDER BY g.votes DESC, g.created_at DESC"
        ).fetchall()
        counts = db.execute(
            "SELECT category, COUNT(*) as total FROM grievances GROUP BY category"
        ).fetchall()
        status_counts = db.execute(
            "SELECT status, COUNT(*) as total FROM grievances GROUP BY status"
        ).fetchall()
        return render_template("admin_dashboard.html", grievances=grievances, counts=counts, status_counts=status_counts)
    flash("Unknown role.", "danger")
    return redirect(url_for("logout"))


@app.route("/grievances/new", methods=["GET", "POST"])
@login_required(role="student")
def create_grievance():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        if not title or not description:
            flash("Title and description are required.", "warning")
            return render_template("create_grievance.html")

        bad_words = ["badword", "stupid", "idiot", "fool", "nonsense"]
        combined_text = f"{title} {description}".lower()
        if any(b in combined_text for b in bad_words):
            flash("Please avoid offensive language in your grievance.", "warning")
            return render_template("create_grievance.html")

        image_path = None
        file = request.files.get("image")
        if file and file.filename and allowed_file(file.filename):
            filename = f"{datetime.utcnow().timestamp()}_{file.filename}"
            saved_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(saved_path)
            image_path = filename

        category = categorize_grievance(title, description)
        db = get_db()
        db.execute(
            """
            INSERT INTO grievances (student_id, title, description, category, image_path, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session["user_id"],
                title,
                description,
                category,
                image_path,
                "In Progress",
                datetime.utcnow().isoformat(),
            ),
        )
        db.commit()
        flash(f"Grievance submitted under '{category}'.", "success")
        return redirect(url_for("dashboard"))

    return render_template("create_grievance.html")


@app.route("/grievances/<int:grievance_id>/vote", methods=["POST"])
@login_required(role="staff")
def vote_grievance(grievance_id: int):
    db = get_db()
    already = db.execute(
        "SELECT 1 FROM votes WHERE grievance_id = ? AND staff_id = ?", (grievance_id, session["user_id"])
    ).fetchone()
    if already:
        flash("You already voted for this grievance.", "info")
        return redirect(url_for("dashboard"))

    db.execute(
        "INSERT INTO votes (grievance_id, staff_id, created_at) VALUES (?, ?, ?)",
        (grievance_id, session["user_id"], datetime.utcnow().isoformat()),
    )
    db.execute("UPDATE grievances SET votes = votes + 1 WHERE id = ?", (grievance_id,))
    db.commit()
    flash("Vote recorded.", "success")
    return redirect(url_for("dashboard"))


@app.route("/grievances/<int:grievance_id>/status", methods=["POST"])
@login_required(role="admin")
def update_status(grievance_id: int):
    new_status = request.form.get("status")
    if new_status not in {"In Progress", "Completed"}:
        flash("Invalid status.", "warning")
        return redirect(url_for("dashboard"))
    db = get_db()
    db.execute("UPDATE grievances SET status = ? WHERE id = ?", (new_status, grievance_id))
    db.commit()
    flash("Status updated.", "success")
    return redirect(url_for("dashboard"))


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=True)

