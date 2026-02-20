import re
import json
from flask import request, g
from app.session import get_current_user
from app.webhook import log_event


SQLI_PATTERNS = re.compile(r"('|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b|--|;|1=1|1='1)", re.IGNORECASE)
XSS_PATTERNS = re.compile(r"(<script|onerror|onload|javascript:|<img|<svg|<iframe|alert\(|document\.cookie)", re.IGNORECASE)


def detect_sqli(value):
    if not value:
        return False
    return bool(SQLI_PATTERNS.search(value))


def detect_xss(value):
    if not value:
        return False
    return bool(XSS_PATTERNS.search(value))


def audit_before_request():
    g.audit_user = get_current_user()


def audit_after_request(response):
    user = getattr(g, 'audit_user', None)
    candidate_email = user.get("email", "anonymous") if user else "anonymous"
    session_id = request.cookies.get("shieldview_session", "")[:20]

    base_event = {
        "event_type": "http_request",
        "candidate_email": candidate_email,
        "session_id": session_id,
        "method": request.method,
        "path": request.path,
        "query_params": dict(request.args),
        "status_code": response.status_code,
        "ip_address": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", ""),
    }

    log_event(base_event)

    # Detect special events
    _detect_special_events(candidate_email, session_id, response)

    return response


def _detect_special_events(candidate_email, session_id, response):
    base = {
        "candidate_email": candidate_email,
        "session_id": session_id,
        "ip_address": request.remote_addr,
    }

    # SQLi detection on login
    if request.path == "/login" and request.method == "POST":
        password = request.form.get("password", "")
        if detect_sqli(password):
            log_event({
                **base,
                "event_type": "sqli_attempt",
                "detail": json.dumps({"password_input": password, "login_succeeded": response.status_code in (200, 302)}),
            })

    # XSS detection on search
    if request.path == "/search":
        query = request.args.get("q", "")
        if detect_xss(query):
            log_event({
                **base,
                "event_type": "xss_attempt",
                "detail": json.dumps({"search_query": query}),
            })

    # IDOR detection on alerts
    if request.path.startswith("/alerts/"):
        alert_owner = getattr(g, 'alert_owner_email', None)
        if alert_owner and alert_owner != candidate_email:
            log_event({
                **base,
                "event_type": "idor_attempt",
                "detail": json.dumps({"path": request.path, "alert_owner": alert_owner, "accessed_by": candidate_email}),
            })

    # Cookie tamper detection
    if hasattr(g, 'cookie_tampered') and g.cookie_tampered:
        log_event({
            **base,
            "event_type": "cookie_tamper",
            "detail": json.dumps({"tampered_role": getattr(g, 'tampered_role', 'unknown')}),
        })

    # Debug endpoint access
    if request.path == "/api/debug":
        log_event({
            **base,
            "event_type": "debug_access",
        })

    # Admin panel access
    if request.path.startswith("/admin"):
        log_event({
            **base,
            "event_type": "admin_access",
        })

    # Profile IDOR
    if request.path == "/profile" and request.args.get("user_id"):
        user = get_current_user()
        requested_id = request.args.get("user_id")
        if user and str(user.get("user_id")) != str(requested_id):
            log_event({
                **base,
                "event_type": "profile_idor",
                "detail": json.dumps({"requested_user_id": requested_id, "current_user_id": user.get("user_id")}),
            })
