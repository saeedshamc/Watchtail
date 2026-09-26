"""HTTP routes for the dashboard and API."""


def register_blueprints(app):
    from .dashboard import bp as dashboard_bp
    from .health import bp as health_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(dashboard_bp)
