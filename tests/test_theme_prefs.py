"""Theme and timezone display preferences (R13).

Session-backed prefs: the header toggle flips data-theme on <body>,
the settings page picks a fixed UTC offset, and display_ts renders
naive-UTC database timestamps in that offset. Viewers may toggle their
own theme; the timezone form mirrors the app-wide write policy.
"""

import datetime as dt

import pytest

import app as watchtail_app
from app.database import dispose_engine, session_scope
from app.models import Event
from app import prefs


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()


@pytest.fixture
def client(memory_app):
    client = memory_app.test_client()
    client.post("/login", data={"username": "admin", "password": "test-password"})
    return client


def test_default_theme_is_dark(client):
    html = client.get("/").get_data(as_text=True)
    assert 'data-theme="dark"' in html


def test_theme_toggle_flips_body_attr(client):
    client.get("/prefs/theme/light")
    html = client.get("/").get_data(as_text=True)
    assert 'data-theme="light"' in html

    client.get("/prefs/theme/dark")
    html = client.get("/").get_data(as_text=True)
    assert 'data-theme="dark"' in html


def test_theme_persists_across_requests(client):
    client.get("/prefs/theme/light")
    assert 'data-theme="light"' in client.get("/events").get_data(as_text=True)


def test_invalid_theme_is_ignored(client):
    client.get("/prefs/theme/neon")
    html = client.get("/").get_data(as_text=True)
    assert 'data-theme="dark"' in html


def test_logout_resets_prefs_like_language(client):
    """Prefs live in the session, so logout clears them (same as lang)."""
    client.get("/prefs/theme/light")
    client.post("/logout")
    client.post("/login", data={"username": "admin", "password": "test-password"})
    html = client.get("/").get_data(as_text=True)
    assert 'data-theme="dark"' in html


def _seed_viewer():
    from werkzeug.security import generate_password_hash

    from app.models import AdminUser

    with session_scope() as session:
        session.add(
            AdminUser(
                username="viewer",
                password_hash=generate_password_hash("viewer-pass"),
                role="viewer",
            )
        )


def test_viewer_can_toggle_theme(memory_app):
    _seed_viewer()
    client = memory_app.test_client()
    client.post("/login", data={"username": "viewer", "password": "viewer-pass"})
    client.get("/prefs/theme/light")
    html = client.get("/").get_data(as_text=True)
    assert 'data-theme="light"' in html


def test_default_tz_label_is_utc(client):
    html = client.get("/events").get_data(as_text=True)
    assert "time (UTC)" in html


def test_tz_choice_relabels_and_shifts_timestamps(client):
    recent = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) - dt.timedelta(
        minutes=5
    )
    with session_scope() as session:
        session.add(Event(ts=recent, kind="http_access", ip="203.0.113.9"))
    client.post("/prefs/tz", data={"tz": "180"}, follow_redirects=True)
    html = client.get("/events").get_data(as_text=True)
    assert "time (UTC+03:00)" in html
    expected = (recent + dt.timedelta(minutes=180)).strftime("%Y-%m-%d %H:%M:%S")
    assert expected in html
    assert recent.strftime("%Y-%m-%d %H:%M:%S") not in html


def test_tz_negative_offset_renders_without_plus(client):
    client.post("/prefs/tz", data={"tz": "-300"}, follow_redirects=True)
    html = client.get("/events").get_data(as_text=True)
    assert "time (UTC-05:00)" in html


def test_tz_choice_persists_across_requests(client):
    client.post("/prefs/tz", data={"tz": "210"}, follow_redirects=True)
    html = client.get("/").get_data(as_text=True)
    assert "UTC+03:30" in html


def test_invalid_tz_value_is_rejected(client):
    client.post("/prefs/tz", data={"tz": "7777"}, follow_redirects=True)
    html = client.get("/events").get_data(as_text=True)
    assert "time (UTC)" in html


def test_tz_form_requires_admin(memory_app):
    _seed_viewer()
    vclient = memory_app.test_client()
    vclient.post("/login", data={"username": "viewer", "password": "viewer-pass"})
    response = vclient.post("/prefs/tz", data={"tz": "180"}, follow_redirects=True)
    assert "requires an admin account" in response.get_data(as_text=True)
    html = vclient.get("/events").get_data(as_text=True)
    assert "time (UTC)" in html


def test_settings_page_lists_tz_choices(client):
    html = client.get("/settings").get_data(as_text=True)
    assert "UTC+03:30" in html
    assert "UTC-05:00" in html


def test_display_ts_formats_naive_utc(memory_app):
    from flask import session as flask_session

    with memory_app.test_request_context("/"):
        flask_session["tz"] = 330  # UTC+05:30 (India)
        stamp = dt.datetime(2026, 1, 2, 23, 30, 0)
        assert prefs.display_ts(stamp) == "2026-01-03 05:00:00"
        assert prefs.display_ts(stamp, "%H:%M") == "05:00"


def test_display_ts_passes_through_placeholders(memory_app):
    with memory_app.test_request_context("/"):
        assert prefs.display_ts(None) is None
        assert prefs.display_ts("2026-01-02T03:04:05Z") == "2026-01-02T03:04:05Z"


def test_offset_label_and_parse_helpers():
    assert prefs.tz_offset_label(0) == "UTC"
    assert prefs.tz_offset_label(330) == "UTC+05:30"
    assert prefs.tz_offset_label(-480) == "UTC-08:00"
    assert prefs.parse_offset("UTC+03:30") == 210
    assert prefs.parse_offset("-05:00") == -300
    assert prefs.parse_offset("bogus") is None


def test_live_event_rows_shifted_via_body_attrs(client):
    """The realtime JS reads the viewer's offset from body data attrs."""
    client.post("/prefs/tz", data={"tz": "180"}, follow_redirects=True)
    html = client.get("/").get_data(as_text=True)
    assert 'data-tz-offset="180"' in html
    assert 'data-tz-label="UTC+03:00"' in html
