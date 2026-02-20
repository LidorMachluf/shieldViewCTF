import math
from flask import Blueprint, render_template, request, redirect, url_for, g

from app.db import query_db
from app.session import get_current_user
from app.config import DEFAULT_TEAM_ANALYST_ID

alerts_bp = Blueprint("alerts", __name__)


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


@alerts_bp.route("/")
@alerts_bp.route("/dashboard")
@login_required
def dashboard():
    page = request.args.get("page", 1, type=int)
    per_page = 10
    sort = request.args.get("sort", "id")
    order = request.args.get("order", "asc")

    allowed_sorts = {"id", "created_at", "severity", "title", "asset_hostname", "source_ip"}
    if sort not in allowed_sorts:
        sort = "id"
    if order not in ("asc", "desc"):
        order = "desc"

    # Dashboard only shows alerts assigned to the candidate's team (analyst1)
    # The other 20 alerts (analyst2 + admin) are hidden — discoverable only via IDOR
    team_id = DEFAULT_TEAM_ANALYST_ID

    total = query_db("SELECT COUNT(*) as cnt FROM alerts WHERE assigned_to = ?", (team_id,), one=True)["cnt"]
    total_pages = math.ceil(total / per_page) if total > 0 else 1
    page = max(1, min(page, total_pages))
    offset = (page - 1) * per_page

    alerts = query_db(
        f"SELECT * FROM alerts WHERE assigned_to = ? ORDER BY {sort} {order} LIMIT ? OFFSET ?",
        (team_id, per_page, offset),
    )

    # Severity counts for stat cards (scoped to team alerts only)
    stats = {
        "high": query_db("SELECT COUNT(*) as cnt FROM alerts WHERE assigned_to = ? AND severity = 'HIGH'", (team_id,), one=True)["cnt"],
        "medium": query_db("SELECT COUNT(*) as cnt FROM alerts WHERE assigned_to = ? AND severity = 'MEDIUM'", (team_id,), one=True)["cnt"],
        "low": query_db("SELECT COUNT(*) as cnt FROM alerts WHERE assigned_to = ? AND severity = 'LOW'", (team_id,), one=True)["cnt"],
    }

    return render_template(
        "dashboard.html",
        alerts=alerts,
        page=page,
        total_pages=total_pages,
        total=total,
        sort=sort,
        order=order,
        stats=stats,
        user=g.current_user,
    )


@alerts_bp.route("/alerts/<int:alert_id>")
@login_required
def alert_detail(alert_id):
    # VULNERABILITY 2: IDOR — no ownership check.
    # Any authenticated user can view any alert regardless of assignment.
    alert = query_db("SELECT a.*, u.email as assigned_email FROM alerts a LEFT JOIN users u ON a.assigned_to = u.id WHERE a.id = ?", (alert_id,), one=True)

    if not alert:
        return render_template("error.html", message="Alert not found.", code=404), 404

    # Store alert owner for audit detection
    g.alert_owner_email = alert["assigned_email"]

    return render_template(
        "alert_detail.html",
        alert=alert,
        user=g.current_user,
    )
