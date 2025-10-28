from datetime import timedelta, datetime
from functools import wraps
import sqlite3
import os

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import CSRFProtect
from wtforms import Form   # used only to keep CSRF integration simple
# Optional: zero-shot model (heavy). If unavailable we'll fallback to heuristics.
try:
    from transformers import pipeline
except Exception:
    pipeline = None

# ---------------- APP CONFIG ----------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "change_this_secret_in_prod_!23")
# session lifetime
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
# Cookie security flags (set to True in production with HTTPS)
app.config['SESSION_COOKIE_SECURE'] = False  # set True behind HTTPS
app.config['REMEMBER_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

csrf = CSRFProtect(app)  # enables CSRF protection for all POST/PUT/DELETE forms

DB_PATH = "complaints.db"

# ---------------- DATABASE / INIT ----------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # complaints table
    c.execute("""
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_name TEXT,
            complaint TEXT,
            priority TEXT,
            status TEXT,
            admin_message TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # users table (password hashed)
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('user','admin'))
        )
    """)
    # Insert sample users if none exist
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  ("admin", generate_password_hash("admin123"), "admin"))
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  ("venkat", generate_password_hash("venkat123"), "user"))
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  ("user1", generate_password_hash("user123"), "user"))
        print("Inserted sample users: admin/admin123, venkat/venkat123, user1/user123")
    conn.commit()
    conn.close()

init_db()

# ---------------- AI / PRIORITY LOGIC ----------------
# Try to load zero-shot (heavy). If missing or fails, fallback to heuristics.
zero_shot = None
if pipeline is not None:
    try:
        zero_shot = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
    except Exception as e:
        print("Zero-shot model not loaded (will use heuristics):", e)
        zero_shot = None

CATEGORIES = [
    "Electrical hazard", "Plumbing emergency", "Appliance not working",
    "Furniture problem", "Noise disturbance", "Cleanliness / hygiene",
    "General maintenance"
]

def heuristic_priority(text_lower: str) -> str:
    if any(k in text_lower for k in ["fire", "short circuit", "shock", "sparks", "danger", "gas leak", "major leak"]):
        return "High"
    if any(k in text_lower for k in ["not working", "stopped", "broken", "doesn't work", "fault", "no power", "fan not working", "ac not working"]):
        return "Medium"
    if any(k in text_lower for k in ["noise", "squeak", "dirty", "smell", "mess"]):
        return "Low"
    return "Low"

@app.route('/about-devs')
def about_devs():
    return render_template('about_devs.html')


def ai_assign_priority(text: str) -> str:
    text = (text or "").strip()
    tl = text.lower()
    if zero_shot:
        try:
            res = zero_shot(text, CATEGORIES, multi_label=False)
            top_label = res["labels"][0]
            top_score = float(res["scores"][0])
            if top_label in ["Electrical hazard", "Plumbing emergency"]:
                pr = "High"
            elif top_label in ["Appliance not working", "Furniture problem"]:
                pr = "Medium"
            elif top_label in ["Noise disturbance", "Cleanliness / hygiene"]:
                pr = "Low"
            else:
                pr = "Medium"
            if top_score < 0.5:
                return heuristic_priority(tl)
            return pr
        except Exception as e:
            print("zero_shot error:", e)
            return heuristic_priority(tl)
    else:
        return heuristic_priority(tl)

# ---------------- HELPERS & DECORATORS ----------------
def get_db_conn():
    return sqlite3.connect(DB_PATH)

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to continue.", "error")
            return redirect(url_for('login'))
        # session timeout handled by Flask's permanent sessions and PERMANENT_SESSION_LIFETIME
        return func(*args, **kwargs)
    return wrapper

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash("Admin access required.", "error")
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return wrapper

# regenerate session (clear and reassign) for session fixation mitigation
def regenerate_session(user_id, username, role):
    session.clear()
    session.permanent = True
    session['user_id'] = user_id
    session['username'] = username
    session['role'] = role
    session['login_time'] = datetime.utcnow().isoformat()

# make csrf_token available in templates (if needed)
from flask_wtf.csrf import generate_csrf
@app.context_processor
def inject_csrf():
    return dict(csrf_token=generate_csrf)

# ---------------- ROUTES ----------------
@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If already logged in, redirect appropriately
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('adminpanel'))
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = get_db_conn()
        c = conn.cursor()
        c.execute("SELECT id, password, role FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()

        if row and check_password_hash(row[1], password):
            regenerate_session(row[0], username, row[2])
            flash("Login successful.", "success")
            if row[2] == 'admin':
                return redirect(url_for('adminpanel'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.", "error")
            return render_template('login.html')
    return render_template('login.html')

@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for('login'))

# ---------------- USER DASHBOARD (hidden username) ----------------
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    # Only users (not admin) should use dashboard; admins can still be allowed if desired
    if session.get('role') == 'admin':
        # Admins redirected to admin panel
        return redirect(url_for('adminpanel'))

    username = session.get('username')
    if request.method == 'POST':
        complaint_text = request.form.get('complaint', '').strip()
        if not complaint_text:
            flash("Complaint cannot be empty.", "error")
            return redirect(url_for('dashboard'))

        priority = ai_assign_priority(complaint_text)
        status = 'Pending'
        admin_message = 'Waiting for admin review.'
        conn = get_db_conn()
        c = conn.cursor()
        c.execute("INSERT INTO complaints (user_name, complaint, priority, status, admin_message) VALUES (?, ?, ?, ?, ?)",
                  (username, complaint_text, priority, status, admin_message))
        conn.commit()
        conn.close()
        flash("Complaint submitted (priority: %s)." % priority, "success")
        return redirect(url_for('dashboard'))

    # GET - show user's complaints
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("SELECT id, complaint, priority, status, admin_message, created_at FROM complaints WHERE user_name = ? ORDER BY id DESC", (session.get('username'),))
    complaints = c.fetchall()
    conn.close()
    return render_template('dashboard.html', username=session.get('username'), complaints=complaints)

# ---------------- ADMIN PANEL ----------------
@app.route('/adminpanel', methods=['GET'])
@admin_required
def adminpanel():
    # filtering (search username only per prior choice)
    search_username = request.args.get('search_username', '').strip()
    filter_priority = request.args.get('filter_priority', 'All')
    filter_status = request.args.get('filter_status', 'All')

    sql = "SELECT id, user_name, complaint, priority, status, admin_message, created_at FROM complaints"
    conditions = []
    params = []
    if search_username:
        conditions.append("user_name LIKE ?")
        params.append(f"%{search_username}%")
    if filter_priority and filter_priority != 'All':
        conditions.append("priority = ?")
        params.append(filter_priority)
    if filter_status and filter_status != 'All':
        conditions.append("status = ?")
        params.append(filter_status)
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY id DESC"

    conn = get_db_conn()
    c = conn.cursor()
    c.execute(sql, params)
    complaints = c.fetchall()
    conn.close()

    priority_options = ["All", "High", "Medium", "Low"]
    status_options = ["All", "Pending", "In Progress", "Resolved"]
    return render_template('adminpanel.html', complaints=complaints,
                           search_username=search_username,
                           filter_priority=filter_priority,
                           filter_status=filter_status,
                           priority_options=priority_options,
                           status_options=status_options)

# admin update
@app.route('/adminpanel/update', methods=['POST'])
@admin_required
def admin_update():
    complaint_id = request.form.get('complaint_id')
    new_status = request.form.get('status')
    new_message = request.form.get('admin_message', '')
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("UPDATE complaints SET status = ?, admin_message = ? WHERE id = ?", (new_status, new_message, complaint_id))
    conn.commit()
    conn.close()
    flash("Complaint updated.", "success")
    return redirect(url_for('adminpanel'))

# admin delete
@app.route('/adminpanel/delete/<int:complaint_id>', methods=['POST'])
@admin_required
def admin_delete(complaint_id):
    conn = get_db_conn()
    c = conn.cursor()
    c.execute("DELETE FROM complaints WHERE id = ?", (complaint_id,))
    conn.commit()
    conn.close()
    flash("Complaint deleted.", "success")
    return redirect(url_for('adminpanel'))

# admin add user
@app.route('/adminpanel/add-user', methods=['GET', 'POST'])
@admin_required
def admin_add_user():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'user')
        if not username or not password or role not in ('user', 'admin'):
            flash("Invalid input.", "error")
            return redirect(url_for('admin_add_user'))
        hashed = generate_password_hash(password)
        try:
            conn = get_db_conn()
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed, role))
            conn.commit()
            conn.close()
            flash("User created: %s (%s)" % (username, role), "success")
            return redirect(url_for('adminpanel'))
        except sqlite3.IntegrityError:
            flash("Username already exists.", "error")
            return redirect(url_for('admin_add_user'))
    return render_template('add_user.html')

# ---------------- BEFORE REQUEST: extra protections ----------------
@app.before_request
def before_request():
    # Block non-HTTPS in production by checking app.config; this is advisory:
    if app.config.get('SESSION_COOKIE_SECURE'):
        # In production you should enforce HTTPS at server level (nginx)
        pass

    # If session exists, you can enforce session age limit manually if needed
    if 'login_time' in session:
        try:
            login_time = datetime.fromisoformat(session['login_time'])
            if datetime.utcnow() - login_time > app.config['PERMANENT_SESSION_LIFETIME']:
                session.clear()
                flash("Session expired, please log in again.", "error")
                return redirect(url_for('login'))
        except Exception:
            # ignore parsing errors
            pass

# ---------------- RUN ----------------
if __name__ == '__main__':
    # For local dev: do not set SESSION_COOKIE_SECURE True (HTTPS not enabled)
    # In production, set app.config['SESSION_COOKIE_SECURE'] = True and run behind HTTPS.
    app.run(debug=True)
