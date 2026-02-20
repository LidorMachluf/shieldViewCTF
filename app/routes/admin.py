from flask import Blueprint, render_template, request, redirect, url_for, g

from app.db import query_db
from app.session import get_current_user
from app.config import FLAGS

admin_bp = Blueprint("admin", __name__)


def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect(url_for("auth.login"))
        g.current_user = user
        # VULNERABILITY H1: Role checked from cookie, which is manipulable
        # Candidate can change role in base64 cookie from "user" to "admin"
        if user.get("role") != "admin":
            return render_template("error.html", message="Access denied. Admin privileges required.", code=403), 403

        # Check if cookie role matches DB role (for audit detection)
        db_user = query_db("SELECT role FROM users WHERE id = ?", (user["user_id"],), one=True)
        if db_user and db_user["role"] != user.get("role"):
            g.cookie_tampered = True
            g.tampered_role = user.get("role")
        return f(*args, **kwargs)
    return decorated


@admin_bp.route("/admin/users")
@admin_required
def user_management():
    users = query_db("SELECT * FROM users WHERE is_seed = 1 ORDER BY created_at DESC")
    return render_template(
        "admin_users.html",
        users=users,
        user=g.current_user,
        admin_flag=FLAGS["cookie_tamper"],
    )
