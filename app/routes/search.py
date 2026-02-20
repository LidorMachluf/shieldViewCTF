from flask import Blueprint, render_template, request, redirect, url_for, g
from markupsafe import Markup

from app.db import query_db
from app.session import get_current_user
from app.config import FLAGS

search_bp = Blueprint("search", __name__)


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


@search_bp.route("/search")
@login_required
def search():
    query = request.args.get("q", "")
    results = []

    if query:
        results = query_db(
            "SELECT * FROM alerts WHERE title LIKE ? OR description LIKE ? ORDER BY created_at DESC LIMIT 50",
            (f"%{query}%", f"%{query}%"),
        )

    # VULNERABILITY 3: Reflected XSS
    # The search query is passed to the template and rendered with |safe filter
    # This allows script injection via the q parameter
    display_query = Markup(query)

    return render_template(
        "search.html",
        query=display_query,
        raw_query=query,
        results=results,
        result_count=len(results),
        user=g.current_user,
        xss_flag=FLAGS["xss"],
    )
