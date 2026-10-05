"""Tests for reverse DNS enrichment and alert clustering."""

import datetime as dt
import socket
from unittest.mock import patch

import pytest

import app as watchtail_app
from app import rdns
from app.clustering import cluster_alerts
from app.database import dispose_engine
from app.models import Alert


@pytest.fixture(autouse=True)
def memory_app():
    application = watchtail_app.create_app(database_url="sqlite:///:memory:")
    yield application
    dispose_engine()
    rdns.clear_cache()
    rdns.configure(True)


class TestRdns:
    def test_resolves_host_via_gethostbyaddr(self):
        rdns.clear_cache()
        with patch("socket.gethostbyaddr", return_value=("evil.example.com", [], ["1.2.3.4"])):
            assert rdns.lookup("203.0.113.99") == "evil.example.com"

    def test_trailing_dot_stripped(self):
        rdns.clear_cache()
        with patch("socket.gethostbyaddr", return_value=("host.example.com.", [], [])):
            assert rdns.lookup("203.0.113.100") == "host.example.com"

    def test_failure_returns_none_and_is_cached(self):
        rdns.clear_cache()
        calls = []

        def boom(ip):
            calls.append(ip)
            raise socket.herror(1, "unknown host")

        with patch("socket.gethostbyaddr", side_effect=boom):
            assert rdns.lookup("203.0.113.101") is None
            assert rdns.lookup("203.0.113.101") is None
        assert len(calls) == 1  # second call served from the failure cache

    def test_disabled_short_circuits(self):
        rdns.configure(False)
        with patch("socket.gethostbyaddr") as mock:
            assert rdns.lookup("203.0.113.102") is None
            mock.assert_not_called()
        rdns.configure(True)

    def test_cache_ttl_expiry(self, monkeypatch):
        rdns.clear_cache()
        with patch("socket.gethostbyaddr", return_value=("a.example.com", [], [])):
            assert rdns.lookup("203.0.113.103") == "a.example.com"

        # Expire the cache entry by rewinding its stored time.
        with rdns._lock:
            for key in rdns._cache:
                stored, host = rdns._cache[key]
                rdns._cache[key] = (stored - rdns.CACHE_TTL_SECONDS - 1, host)

        with patch("socket.gethostbyaddr", return_value=("b.example.com", [], [])) as mock:
            assert rdns.lookup("203.0.113.103") == "b.example.com"
            assert mock.call_count == 1


class TestClustering:
    def _alert(self, ip, minute, detector="ssh_bruteforce", severity="high"):
        return Alert(
            detector=detector, ip=ip, severity=severity, message="m",
            ts=dt.datetime(2026, 9, 28, 12, minute, 0),
        )

    def test_groups_same_ip_within_window(self):
        alerts = [
            self._alert("1.2.3.4", 0),
            self._alert("1.2.3.4", 5, detector="path_scan"),
            self._alert("5.6.7.8", 2),
        ]
        clusters = cluster_alerts(alerts)
        by_ip = {c["ip"]: c for c in clusters}
        assert set(by_ip) == {"1.2.3.4", "5.6.7.8"}
        assert by_ip["1.2.3.4"]["count"] == 2
        assert by_ip["1.2.3.4"]["detectors"] == ["path_scan", "ssh_bruteforce"]
        assert by_ip["1.2.3.4"]["max_severity"] == "high"

    def test_time_gap_splits_clusters(self):
        alerts = [
            self._alert("1.2.3.4", 0),
            self._alert("1.2.3.4", 40),  # beyond 600s proximity from :00
        ]
        clusters = cluster_alerts(alerts)
        same_ip = [c for c in clusters if c["ip"] == "1.2.3.4"]
        assert len(same_ip) == 2

    def test_sorted_by_most_recent(self):
        alerts = [
            self._alert("1.2.3.4", 0),
            self._alert("5.6.7.8", 30),
        ]
        clusters = cluster_alerts(alerts)
        assert clusters[0]["ip"] == "5.6.7.8"

    def test_max_severity_rolls_up(self):
        alerts = [
            self._alert("1.2.3.4", 0, severity="low"),
            self._alert("1.2.3.4", 1, severity="critical"),
        ]
        clusters = cluster_alerts(alerts)
        assert clusters[0]["max_severity"] == "critical"
        assert clusters[0]["severities"] == ["critical", "low"]

    def test_empty_input(self):
        assert cluster_alerts([]) == []
