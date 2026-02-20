import sys
import os
from flask import Blueprint, jsonify, request, Response

from app.db import query_db
from app.config import DATABASE_PATH, LOGS_DIR, FLAGS

api_bp = Blueprint("api", __name__)


@api_bp.route("/api/debug")
def debug():
    """VULNERABILITY H2: Exposed debug endpoint. No authentication required.
    Returns server config, DB info, user list, and route map."""
    users = query_db("SELECT id, email, role, display_name, last_login, created_at FROM users WHERE is_seed = 1")
    user_list = [dict(u) for u in users]

    return jsonify({
        "server": {
            "python_version": sys.version,
            "platform": sys.platform,
            "database_path": DATABASE_PATH,
            "pid": os.getpid(),
            "working_directory": os.getcwd(),
        },
        "users": user_list,
        "environment": {
            "FLASK_ENV": os.environ.get("FLASK_ENV", "not set"),
            "DEBUG": os.environ.get("FLASK_DEBUG", "not set"),
        },
        "internal_flag": FLAGS["debug_endpoint"],
    })


@api_bp.route("/api/logs")
def get_log_file():
    """VULNERABILITY H10: Path Traversal. The 'file' parameter is joined directly
    with the logs directory without sanitization. Using ../flag.txt reads the hidden flag."""
    filename = request.args.get("file", "")
    if not filename:
        # List available log files
        try:
            files = os.listdir(LOGS_DIR)
            return jsonify({"logs_directory": "/api/logs?file=<filename>", "available_files": sorted(files)})
        except Exception:
            return jsonify({"error": "Log directory not found"}), 404

    # VULNERABLE: no path sanitization — allows ../../../etc/passwd or ../flag.txt
    filepath = os.path.join(LOGS_DIR, filename)

    try:
        with open(filepath, "r") as f:
            content = f.read()
        return Response(content, mimetype="text/plain")
    except FileNotFoundError:
        return jsonify({"error": f"Log file '{filename}' not found"}), 404
    except PermissionError:
        return jsonify({"error": "Permission denied"}), 403
    except Exception as e:
        return jsonify({"error": str(e)}), 500
