"""HTTP routes for the dashboard and API."""


def register_blueprints(app):
    from .auth import bp as auth_bp
    from .dashboard import bp as dashboard_bp
    from .events import bp as events_bp
    from .health import bp as health_bp
    from .ip_detail import bp as ip_detail_bp
    from .reviews import bp as reviews_bp
    from .sources import bp as sources_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(sources_bp)
    app.register_blueprint(reviews_bp)
    app.register_blueprint(ip_detail_bp)
