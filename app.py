import os
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from db import get_db_connection

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "pawcare_hub_secret_key_change_in_prod")

UPLOAD_FOLDER = os.path.join("static", "uploads", "forum")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def seed_default_admin():
    """Creates a default admin account if no admin exists in the users table."""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
        admin = cursor.fetchone()
        if not admin:
            hashed_pw = generate_password_hash("admin123")
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, role, full_name)
                VALUES (%s, %s, %s, %s)
                """,
                ("admin", hashed_pw, "admin", "PawCare Admin")
            )
            conn.commit()
    finally:
        cursor.close()
        conn.close()


def _in_range(dt_val, cutoff):
    if not dt_val:
        return False
    if isinstance(dt_val, str):
        try:
            dt_val = datetime.fromisoformat(dt_val)
        except ValueError:
            return False
    return dt_val >= cutoff


def get_period_analytics(cursor):
    """Calculates lost/found pets, sheltered strays, items sold, and funds & donations for week, month, and year."""
    now = datetime.now()
    week_ago = now - timedelta(days=7)
    month_ago = now - timedelta(days=30)
    year_ago = now - timedelta(days=365)

    def empty_bucket():
        return {
            "lost_found": 0,
            "sheltered_strays": 0,
            "items_sold": 0,
            "donations_count": 0,
            "donations_total": 0.0,
            "funds_total": 0.0,
        }

    stats = {
        "week": empty_bucket(),
        "month": empty_bucket(),
        "year": empty_bucket(),
    }

    cursor.execute("SELECT post_type, species, status, created_at FROM forum_posts")
    forum_rows = cursor.fetchall()

    cursor.execute("SELECT quantity, created_at FROM orders")
    order_rows = cursor.fetchall()

    cursor.execute("SELECT amount, status, created_at FROM donations")
    donation_rows = cursor.fetchall()

    cursor.execute("SELECT tx_type, amount, created_at FROM fund_transactions")
    fund_rows = cursor.fetchall()

    for row in forum_rows:
        ptype = (row.get("post_type") or "").lower()
        species = (row.get("species") or "").lower()
        status = (row.get("status") or "").lower()
        created = row.get("created_at")

        is_lost_found = ("lost" in ptype) or ("found" in ptype)
        is_sheltered_stray = (
            ("stray" in ptype or "stray" in status or "sheltered" in status)
            and ("dog" in species or "cat" in species or "stray" in ptype)
        )

        for key, cutoff in [("week", week_ago), ("month", month_ago), ("year", year_ago)]:
            if _in_range(created, cutoff):
                if is_lost_found:
                    stats[key]["lost_found"] += 1
                if is_sheltered_stray:
                    stats[key]["sheltered_strays"] += 1

    for order in order_rows:
        qty = int(order.get("quantity") or 0)
        created = order.get("created_at")
        for key, cutoff in [("week", week_ago), ("month", month_ago), ("year", year_ago)]:
            if _in_range(created, cutoff):
                stats[key]["items_sold"] += qty

    for don in donation_rows:
        status = (don.get("status") or "").lower()
        if status in ("rejected", "cancelled", "failed"):
            continue
        amt = float(don.get("amount") or 0)
        created = don.get("created_at")
        for key, cutoff in [("week", week_ago), ("month", month_ago), ("year", year_ago)]:
            if _in_range(created, cutoff):
                stats[key]["donations_count"] += 1
                stats[key]["donations_total"] += amt

    for tx in fund_rows:
        tx_type = (tx.get("tx_type") or "").lower()
        amt = float(tx.get("amount") or 0)
        created = tx.get("created_at")
        signed_amt = -abs(amt) if any(w in tx_type for w in ("expense", "out", "withdraw", "deduct")) else abs(amt)
        for key, cutoff in [("week", week_ago), ("month", month_ago), ("year", year_ago)]:
            if _in_range(created, cutoff):
                stats[key]["funds_total"] += signed_amt

    for key in stats:
        stats[key]["donations_total"] = round(stats[key]["donations_total"], 2)
        stats[key]["funds_total"] = round(stats[key]["funds_total"], 2)

    return stats


# --- Role & Login Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first to access PawCare Hub.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            flash("Access denied: Admin privileges required.", "error")
            return redirect(url_for("client_dashboard"))
        return f(*args, **kwargs)
    return decorated_function


# --- Auth Routes ---
@app.route("/")
def index():
    if "user_id" in session:
        if session.get("role") == "admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("client_dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not full_name or not username or not password:
            flash("All fields are required.", "error")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("register"))

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                flash("That username is already taken. Please choose another.", "error")
                return redirect(url_for("register"))

            hashed_pw = generate_password_hash(password)
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, role, full_name)
                VALUES (%s, %s, 'client', %s)
                """,
                (username, hashed_pw, full_name)
            )
            conn.commit()
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for("login"))
        finally:
            cursor.close()
            conn.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()

            if user and check_password_hash(user["password_hash"], password):
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["full_name"] = user["full_name"]
                session["role"] = user["role"]

                flash(f"Welcome back, {user['full_name']}!", "success")
                if user["role"] == "admin":
                    return redirect(url_for("admin_dashboard"))
                return redirect(url_for("client_dashboard"))

            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))
        finally:
            cursor.close()
            conn.close()

    return render_template("login.html")


@app.route("/client")
@login_required
def client_dashboard():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    return render_template(
        "client_dashboard.html",
        full_name=session.get("full_name"),
        username=session.get("username")
    )


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# --- Admin Home & Navigation Tabs ---
@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        analytics = get_period_analytics(cursor)

        cursor.execute(
            """
            SELECT post_id, post_type, client_name, contact_info, pet_name,
                   species, location, reason_or_details, photo_path, status, created_at
            FROM forum_posts
            ORDER BY created_at DESC, post_id DESC
            LIMIT 8
            """
        )
        recent_posts = cursor.fetchall()

        cursor.execute("SELECT id, username, role, full_name FROM users ORDER BY id DESC")
        all_users = cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

    return render_template(
        "admin_dashboard.html",
        active_tab="dashboard",
        full_name=session.get("full_name"),
        analytics=analytics,
        recent_posts=recent_posts,
        users=all_users
    )


@app.route("/admin/forum", methods=["GET", "POST"])
@admin_required
def admin_forum():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        if request.method == "POST":
            action = request.form.get("action", "create")

            if action == "create":
                post_type = request.form.get("post_type", "Lost Pet").strip()
                client_name = request.form.get("client_name", "").strip() or session.get("full_name", "Admin")
                contact_info = request.form.get("contact_info", "").strip()
                pet_name = request.form.get("pet_name", "").strip()
                species = request.form.get("species", "Dog").strip()
                location = request.form.get("location", "").strip()
                reason_or_details = request.form.get("reason_or_details", "").strip()
                status = request.form.get("status", "Open").strip()

                photo_path = ""
                photo_file = request.files.get("photo_file")
                if photo_file and photo_file.filename and allowed_file(photo_file.filename):
                    safe_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{secure_filename(photo_file.filename)}"
                    save_dest = os.path.join(UPLOAD_FOLDER, safe_name)
                    photo_file.save(save_dest)
                    photo_path = f"uploads/forum/{safe_name}"

                if not reason_or_details or not location:
                    flash("Location and details are required to post a report.", "error")
                    return redirect(url_for("admin_forum"))

                cursor.execute(
                    """
                    INSERT INTO forum_posts
                        (post_type, client_name, contact_info, pet_name, species, location, reason_or_details, photo_path, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (post_type, client_name, contact_info, pet_name, species, location, reason_or_details, photo_path, status)
                )
                conn.commit()
                flash(f"Added {post_type} post to the forum.", "success")

            elif action == "update_status":
                post_id = request.form.get("post_id")
                new_status = request.form.get("status", "Open").strip()
                if post_id:
                    cursor.execute(
                        "UPDATE forum_posts SET status = %s WHERE post_id = %s",
                        (new_status, post_id)
                    )
                    conn.commit()
                    flash(f"Updated post #{post_id} status to '{new_status}'.", "success")

            elif action == "delete":
                post_id = request.form.get("post_id")
                if post_id:
                    cursor.execute("DELETE FROM forum_posts WHERE post_id = %s", (post_id,))
                    conn.commit()
                    flash(f"Removed forum post #{post_id}.", "success")

            return redirect(url_for("admin_forum"))

        # GET: Filter & Search
        filter_type = request.args.get("type", "all").strip()
        filter_status = request.args.get("status", "all").strip()
        search_q = request.args.get("q", "").strip()

        sql = """
            SELECT post_id, post_type, client_name, contact_info, pet_name,
                   species, location, reason_or_details, photo_path, status, created_at
            FROM forum_posts
            WHERE 1=1
        """
        params = []

        if filter_type != "all":
            sql += " AND LOWER(post_type) LIKE %s"
            params.append(f"%{filter_type.lower()}%")

        if filter_status != "all":
            sql += " AND LOWER(status) LIKE %s"
            params.append(f"%{filter_status.lower()}%")

        if search_q:
            sql += """
                AND (
                    LOWER(pet_name) LIKE %s
                    OR LOWER(location) LIKE %s
                    OR LOWER(client_name) LIKE %s
                    OR LOWER(reason_or_details) LIKE %s
                )
            """
            like_q = f"%{search_q.lower()}%"
            params.extend([like_q, like_q, like_q, like_q])

        sql += " ORDER BY created_at DESC, post_id DESC"
        cursor.execute(sql, tuple(params))
        posts = cursor.fetchall()

        # Summary counts for Forum header badges
        cursor.execute("SELECT post_type, status FROM forum_posts")
        all_forum = cursor.fetchall()
        counts = {
            "total": len(all_forum),
            "lost": sum(1 for r in all_forum if "lost" in (r.get("post_type") or "").lower()),
            "found": sum(1 for r in all_forum if "found" in (r.get("post_type") or "").lower()),
            "stray": sum(1 for r in all_forum if "stray" in (r.get("post_type") or "").lower()),
            "sheltered": sum(1 for r in all_forum if "shelter" in (r.get("status") or "").lower()),
        }
    finally:
        cursor.close()
        conn.close()

    return render_template(
        "admin_forum.html",
        active_tab="forum",
        full_name=session.get("full_name"),
        posts=posts,
        counts=counts,
        filter_type=filter_type,
        filter_status=filter_status,
        search_q=search_q
    )


@app.route("/admin/funds", methods=["GET", "POST"])
@admin_required
def admin_funds():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        if request.method == "POST":
            entry_kind = request.form.get("entry_kind", "donation")
            if entry_kind == "donation":
                donor_name = request.form.get("donor_name", "").strip()
                payment_method = request.form.get("payment_method", "GCash").strip()
                reference_no = request.form.get("reference_no", "").strip()
                amount = request.form.get("amount", "0").strip()
                support_target = request.form.get("support_target", "Shelter & Strays").strip()
                note = request.form.get("note", "").strip()
                if donor_name and amount:
                    cursor.execute(
                        """
                        INSERT INTO donations (donor_name, payment_method, reference_no, amount, support_target, note, status)
                        VALUES (%s, %s, %s, %s, %s, %s, 'Verified')
                        """,
                        (donor_name, payment_method, reference_no, amount, support_target, note)
                    )
                    conn.commit()
                    flash(f"Logged donation from {donor_name}.", "success")
            elif entry_kind == "fund_tx":
                tx_type = request.form.get("tx_type", "Allocation").strip()
                amount = request.form.get("amount", "0").strip()
                description = request.form.get("description", "").strip()
                if amount:
                    cursor.execute(
                        """
                        INSERT INTO fund_transactions (tx_type, amount, description)
                        VALUES (%s, %s, %s)
                        """,
                        (tx_type, amount, description)
                    )
                    conn.commit()
                    flash("Recorded fund transaction.", "success")
            return redirect(url_for("admin_funds"))

        cursor.execute("SELECT * FROM donations ORDER BY created_at DESC, donation_id DESC")
        donations = cursor.fetchall()

        cursor.execute("SELECT * FROM fund_transactions ORDER BY created_at DESC, tx_id DESC")
        transactions = cursor.fetchall()

        analytics = get_period_analytics(cursor)
    finally:
        cursor.close()
        conn.close()

    return render_template(
        "admin_funds.html",
        active_tab="funds",
        full_name=session.get("full_name"),
        donations=donations,
        transactions=transactions,
        analytics=analytics
    )


@app.route("/admin/reports")
@admin_required
def admin_reports():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        analytics = get_period_analytics(cursor)
    finally:
        cursor.close()
        conn.close()

    return render_template(
        "admin_reports.html",
        active_tab="reports",
        full_name=session.get("full_name"),
        analytics=analytics
    )


@app.route("/admin/analytics")
@admin_required
def admin_analytics():
    return redirect(url_for("admin_reports"))


# --- Placeholder Routes for Remaining Quick Action Tabs ---
@app.route("/admin/registry")
@admin_required
def admin_registry():
    flash("Pet Registry & Stray Complaints tab is coming next!", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/inventory")
@admin_required
def admin_inventory():
    flash("Inventory & Market tab is coming next!", "success")
    return redirect(url_for("admin_dashboard"))


if __name__ == "__main__":
    seed_default_admin()
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "true").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)