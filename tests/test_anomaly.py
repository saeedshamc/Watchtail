"""Tests for the anomaly baseline engine."""

import datetime as dt

import pytest

from app.anomaly import BaselineEngine


def hours_ago(n):
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) - dt.timedelta(hours=n)


def test_no_anomaly_without_history():
    engine = BaselineEngine()
    assert engine.check_spike("http_access", dt.datetime.now(), 5000) is False
    assert engine.snapshot("http_access", dt.datetime.now()) is None


def test_history_builds_snapshot():
    engine = BaselineEngine()
    now = dt.datetime.now()
    # Four days of history for this hour bucket; the oldest day's
    # count closes when the next day's first line lands.
    for days_ago in (4, 3, 2, 1):
        day = now - dt.timedelta(days=days_ago)
        for _ in range(10):
            engine.observe("http_access", day, source_id=1)
    snap = engine.snapshot("http_access", now)
    assert snap is not None
    assert snap["samples"] >= 3


def test_spike_detected_far_above_baseline():
    engine = BaselineEngine()
    now = dt.datetime.now()
    # Four previous days each had 10 events in this hour bucket.
    for days_ago in (4, 3, 2, 1):
        day = now - dt.timedelta(days=days_ago)
        for _ in range(10):
            engine.observe("http_access", day, source_id=1)
    # Today's running count: normal (similar to history).
    engine.observe("http_access", now, source_id=1)
    assert engine.check_spike("http_access", now, 11) is False
    # A huge jump: spike.
    assert engine.check_spike("http_access", now, 500) is True


def test_tiny_baselines_never_spike():
    engine = BaselineEngine()
    now = dt.datetime.now()
    for days_ago in (2, 1):
        day = now - dt.timedelta(days=days_ago)
        for _ in range(3):
            engine.observe("http_access", day, source_id=1)
    assert engine.check_spike("http_access", now, 10_000) is False


def test_silence_detected_when_overdue():
    engine = BaselineEngine()
    now = dt.datetime.now()
    # Regular one-minute lines for a while, then nothing.
    for i in range(30, 1, -1):
        engine.observe("http_access", now - dt.timedelta(minutes=i), source_id=7)
    assert engine.check_silence("http_access", 7, now=now - dt.timedelta(minutes=2)) is False
    assert engine.check_silence("http_access", 7, now=now + dt.timedelta(minutes=40)) is True


def test_silence_ignores_unknown_sources():
    engine = BaselineEngine()
    assert engine.check_silence("http_access", 999) is False


def test_silence_candidates_lists_offenders():
    engine = BaselineEngine()
    now = dt.datetime.now()
    for i in range(30, 1, -1):
        engine.observe("http_access", now - dt.timedelta(minutes=i), source_id=5)
    engine.observe("http_access", now, source_id=6)  # fresh source stays quiet

    candidates = engine.silence_candidates(now=now + dt.timedelta(hours=1))
    ids = {c["source_id"] for c in candidates}
    assert 5 in ids
    assert 6 not in ids
