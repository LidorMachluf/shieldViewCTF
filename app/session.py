import base64
import json

from flask import request, make_response

COOKIE_NAME = "shieldview_session"


def create_session_cookie(user_id, email, role, display_name):
    """Create a base64-encoded JSON session cookie. Intentionally manipulable (H1 vuln)."""
    payload = {
        "user_id": user_id,
        "email": email,
        "role": role,
        "display_name": display_name,
    }
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    return encoded


def read_session_cookie():
    """Read and decode the session cookie. Returns dict or None."""
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        return None
    try:
        decoded = base64.b64decode(cookie).decode()
        payload = json.loads(decoded)
        if "user_id" in payload and "email" in payload and "role" in payload:
            return payload
        return None
    except Exception:
        return None


def set_session_cookie(response, user_id, email, role, display_name):
    """Set the session cookie on a response. No HttpOnly, no Secure flags (H6 vuln)."""
    cookie_value = create_session_cookie(user_id, email, role, display_name)
    response.set_cookie(
        COOKIE_NAME,
        cookie_value,
        max_age=60 * 60 * 24,  # 24 hours
        path="/",
        httponly=False,   # Intentional: H6 vuln — accessible via document.cookie
        secure=False,     # Intentional: no Secure flag
        samesite="Lax",
    )
    return response


def clear_session_cookie(response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return response


def get_current_user():
    """Get current user from session cookie. Returns dict or None."""
    return read_session_cookie()
