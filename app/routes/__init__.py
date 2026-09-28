"""HTTP routes for the dashboard and API."""


def register_blueprints(app):
    from .api_v1 import bp as api_v1_bp
    from .annotations import bp as annotations_bp
    from .auth import bp as auth_bp
    from .dashboard import bp as dashboard_bp
    from .events import bp as events_bp
    from .health import bp as health_bp
    from .ingest import bp as ingest_bp
    from .ip_detail import bp as ip_detail_bp
    from .locale import bp as locale_bp
    from .metrics import bp as metrics_bp
    from .respond import bp as respond_bp
    from .reviews import bp as reviews_bp
    from .settings import bp as settings_bp
    from .suppressions import bp as suppressions_bp
    from .sources import bp as sources_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(sources_bp)
    app.register_blueprint(reviews_bp)
    app.register_blueprint(annotations_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(suppressions_bp)
    app.register_blueprint(respond_bp)
    app.register_blueprint(ip_detail_bp)
    app.register_blueprint(api_v1_bp)
    app.register_blueprint(ingest_bp)
    app.register_blueprint(metrics_bp)
    app.register_blueprint(locale_bp)
