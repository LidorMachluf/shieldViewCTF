from flask import Blueprint, render_template, request, redirect, url_for, g
from markupsafe import Markup

from app.db import query_db, execute_db
from app.session import get_current_user
from app.config import FLAGS

incidents_bp = Blueprint("incidents", __name__)


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


@incidents_bp.route("/incidents")
@login_required
def incident_list():
    reports = query_db(
        "SELECT * FROM incident_reports ORDER BY created_at DESC"
    )
    return render_template(
        "incidents.html",
        reports=reports,
        user=g.current_user,
        stored_xss_flag=FLAGS["stored_xss"],
    )


@incidents_bp.route("/incidents/<int:report_id>")
@login_required
def incident_detail(report_id):
    report = query_db(
        "SELECT * FROM incident_reports WHERE id = ?",
        (report_id,),
        one=True,
    )
    if not report:
        return render_template("error.html", message="Report not found.", code=404), 404

    # VULNERABILITY H11: Stored XSS — report content rendered as raw HTML
    # The content field is wrapped in Markup() so any HTML/JS stored in it executes
    safe_content = Markup(report["content"])

    return render_template(
        "incident_detail.html",
        report=report,
        safe_content=safe_content,
        user=g.current_user,
    )


@incidents_bp.route("/incidents/new", methods=["GET", "POST"])
@login_required
def incident_create():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        alert_id = request.form.get("alert_id", type=int)
        status = request.form.get("status", "open")

        if not title or not content:
            return render_template(
                "incident_form.html",
                error="Title and content are required.",
                user=g.current_user,
            )

        execute_db(
            """INSERT INTO incident_reports (title, content, alert_id, created_by, author_name, status)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (title, content, alert_id, g.current_user["user_id"],
             g.current_user["display_name"], status),
        )

        return redirect(url_for("incidents.incident_list"))

    return render_template(
        "incident_form.html",
        user=g.current_user,
    )
