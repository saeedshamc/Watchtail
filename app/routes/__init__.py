"""HTTP routes for the dashboard and API."""


def register_blueprints(app):
    from .health import bp as health_bp

    app.register_blueprint(health_bp)
