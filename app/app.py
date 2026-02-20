import os
from flask import Flask

from app.config import SECRET_KEY, MAX_CONTENT_LENGTH, DATA_DIR
from app.db import init_db
from app.seed import seed_database
from app.webhook import start_flush_thread
from app.audit import audit_before_request, audit_after_request


def create_app():
    app = Flask(__name__)
    app.secret_key = SECRET_KEY
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

    os.makedirs(DATA_DIR, exist_ok=True)

    # Initialize database and seed if needed
    init_db()
    seed_database()

    # Start webhook flush thread
    start_flush_thread()

    # Register audit middleware
    app.before_request(audit_before_request)
    app.after_request(audit_after_request)

    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.alerts import alerts_bp
    from app.routes.search import search_bp
    from app.routes.profile import profile_bp
    from app.routes.api import api_bp
    from app.routes.admin import admin_bp
    from app.routes.incidents import incidents_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(search_bp)
    app.register_blueprint(profile_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(incidents_bp)

    # Error handlers
    @app.errorhandler(404)
    def not_found(e):
        from flask import render_template
        return render_template("error.html", message="Page not found.", code=404), 404

    @app.errorhandler(500)
    def server_error(e):
        from flask import render_template
        return render_template("error.html", message="Internal server error.", code=500), 500

    return app


if __name__ == "__main__":
    application = create_app()
    application.run(debug=False, host="0.0.0.0", port=5000)
