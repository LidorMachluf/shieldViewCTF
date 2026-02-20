import sqlite3
from flask import Blueprint, render_template, request, redirect, url_for, flash

from app.db import execute_vulnerable, execute_db, query_db
from app.session import set_session_cookie, clear_session_cookie, get_current_user
from app.webhook import log_event

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        user = get_current_user()
        if user:
            return redirect(url_for("alerts.dashboard"))
        return render_template("login.html")

    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    next_url = request.form.get("next", "") or request.args.get("next", "")

    if not email:
        return render_template("login.html", error="Email is required.")

    # VULNERABILITY 1: SQL Injection on password field
    # The password is concatenated directly into the query string
    query = f"SELECT * FROM users WHERE email='{email}' AND password='{password}'"

    try:
        results = execute_vulnerable(query)
    except sqlite3.OperationalError as e:
        # VULNERABILITY H4: Verbose SQL errors leaked to user
        error_msg = f"Authentication error: {str(e)}"
        return render_template("login.html", error=error_msg)
    except Exception:
        return render_template("login.html", error="Login failed. Please try again.")

    if results:
        # Candidate isolation: filter out other candidates' rows
        # Only keep seed users and the current candidate's own row
        results = [row for row in results if row["is_seed"] or row["email"] == email]

        # Check if the provided email matches any returned row (legitimate login)
        matched_user = None
        for row in results:
            if row["email"] == email:
                matched_user = row
                break

        if matched_user:
            # Legitimate login — email matched a returned row
            user = matched_user
            log_event({
                "event_type": "login_success",
                "candidate_email": user["email"],
                "ip_address": request.remote_addr,
            })
        else:
            # SQLi bypass — query returned rows but none match the candidate's email
            # Auto-create candidate user with their email, then log them in as 'user' role
            log_event({
                "event_type": "sqli_success",
                "candidate_email": email,
                "detail": f"SQLi payload returned {len(results)} row(s), none matching email. Auto-creating user.",
                "ip_address": request.remote_addr,
            })

            if "@" in email:
                display_name = email.split("@")[0].replace(".", " ").title()
                try:
                    execute_db(
                        "INSERT OR IGNORE INTO users (email, password, display_name, role, is_seed) VALUES (?, NULL, ?, 'user', 0)",
                        (email, display_name),
                    )
                except Exception:
                    pass

            user = query_db("SELECT * FROM users WHERE email = ?", (email,), one=True)
            if not user:
                return render_template("login.html", error="Login failed. Please try again.")

        # VULNERABILITY H9: Open Redirect — next_url is not validated
        redirect_to = next_url if next_url else url_for("alerts.dashboard")
        response = redirect(redirect_to)
        response = set_session_cookie(
            response,
            user_id=user["id"],
            email=user["email"],
            role=user["role"],
            display_name=user["display_name"],
        )
        try:
            execute_db("UPDATE users SET last_login = datetime('now') WHERE id = ?", (user["id"],))
        except Exception:
            pass
        return response

    # No results at all — try auto-creating user if email looks valid
    if "@" in email:
        try:
            display_name = email.split("@")[0].replace(".", " ").title()
            execute_db(
                "INSERT OR IGNORE INTO users (email, password, display_name, role, is_seed) VALUES (?, NULL, ?, 'user', 0)",
                (email, display_name),
            )
            new_user = query_db("SELECT * FROM users WHERE email = ?", (email,), one=True)
            if new_user:
                redirect_to = next_url if next_url else url_for("alerts.dashboard")
                response = redirect(redirect_to)
                response = set_session_cookie(
                    response,
                    user_id=new_user["id"],
                    email=new_user["email"],
                    role=new_user["role"],
                    display_name=new_user["display_name"],
                )
                execute_db("UPDATE users SET last_login = datetime('now') WHERE id = ?", (new_user["id"],))
                return response
        except Exception:
            pass

    return render_template("login.html", error="Invalid credentials. Please check your email and password.")


@auth_bp.route("/logout")
def logout():
    response = redirect(url_for("auth.login"))
    response = clear_session_cookie(response)
    return response
