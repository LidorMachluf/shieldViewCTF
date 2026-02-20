from flask import Blueprint, render_template, request, redirect, url_for, g, flash

from app.db import query_db, execute_db
from app.session import get_current_user, set_session_cookie
from app.config import FLAGS

profile_bp = Blueprint("profile", __name__)


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect(url_for("auth.login"))
        g.current_user = user
        return f(*args, **kwargs)
    return decorated


@profile_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    # VULNERABILITY H7: IDOR on profile via user_id param
    # If user_id is in the query string, show that user's profile instead
    user_id = request.args.get("user_id", g.current_user["user_id"])

    if request.method == "POST":
        new_name = request.form.get("display_name", "").strip()
        if new_name and len(new_name) <= 100:
            # This update is safe — scoped to own user_id from session (parameterized)
            execute_db(
                "UPDATE users SET display_name = ? WHERE id = ?",
                (new_name, g.current_user["user_id"]),
            )
            # Update session cookie with new name
            response = redirect(url_for("profile.profile"))
            response = set_session_cookie(
                response,
                user_id=g.current_user["user_id"],
                email=g.current_user["email"],
                role=g.current_user["role"],
                display_name=new_name,
            )
            return response

    profile_user = query_db("SELECT * FROM users WHERE id = ?", (user_id,), one=True)

    if not profile_user:
        return render_template("error.html", message="User not found.", code=404), 404

    is_own_profile = str(user_id) == str(g.current_user["user_id"])

    # Candidate isolation: only allow viewing own profile or seed user profiles
    # This prevents candidates from discovering other candidates' emails
    if not is_own_profile and not profile_user["is_seed"]:
        return render_template("error.html", message="User not found.", code=404), 404

    # Show profile IDOR flag when viewing the admin's profile via IDOR
    profile_flag = FLAGS["profile_idor"] if (not is_own_profile and profile_user["role"] == "admin") else None

    return render_template(
        "profile.html",
        profile_user=profile_user,
        is_own_profile=is_own_profile,
        user=g.current_user,
        profile_flag=profile_flag,
    )
