"""Baseline learning and anomaly detection.

An EWMA (exponentially weighted moving average) per event kind keeps a
lightweight memory of normal traffic, bucketed by hour of day so the
"normal" for 3am is not polluted by the 10am peak. Two anomalies are
worth alerting on:

* **spike** — far more activity than the baseline predicts;
* **silence** — a source that stopped producing lines entirely, which
  for a log stream usually means the machine or its logging broke (or
  someone with root decided the trail should end).
"""

import math
import threading
from datetime import timedelta

from .models import utcnow

ALPHA = 0.1  # EWMA smoothing: newer observations matter, old ones linger
SPIKE_SIGMA = 4.0
MIN_BASELINE_FOR_SPIKE = 5  # below this many expected events, skip spikes
SILENCE_MULTIPLIER = 6  # baseline interval * 6 with no data = suspect
SILENCE_MIN_MINUTES = 20


def _bucket_key(ts) -> tuple:
    return (ts.hour,)  # hour of day only; weekday/weekend nuance is a
    # refinement the sample counts rarely support in small deployments


class KindBaseline:
    """EWMA + variance tracker for one event kind."""

    def __init__(self):
        self._by_bucket: dict[tuple, list[float]] = {}
        self._last_seen = None

    def observe(self, ts) -> None:
        bucket = self._by_bucket.setdefault(_bucket_key(ts), [0.0, 0.0])
        # Interval-based EWMA: track counts per minute between events.
        bucket[0] += 1
        self._last_seen = max(self._last_seen, ts) if self._last_seen else ts

    def expected_per_hour(self, ts) -> float:
        mean, variance = self._by_bucket.get(_bucket_key(ts), [0.0, 0.0])
        if mean <= 0:
            return 0.0
        return mean

    def stats(self, ts) -> tuple[float, float]:
        """(mean, stddev) historical counts for this time bucket."""
        return tuple(self._by_bucket.get(_bucket_key(ts), [0.0, 0.0]))


class BaselineEngine:
    """Owns baselines for every kind and detects anomalies on demand.

    History is kept as daily totals per (weekend, hour) bucket: each
    observed hour closes a sample, so after a few days the engine
    knows that "9am on a weekday means ~400 lines". Thread-safe:
    tailer threads observe() while the scheduler checks for anomalies.
    """

    def __init__(self, spike_sigma=SPIKE_SIGMA, silence_multiplier=SILENCE_MULTIPLIER):
        self.spike_sigma = spike_sigma
        self.silence_multiplier = silence_multiplier
        # kind -> bucket -> {"samples": [daily totals], "open_day": date, "running": count}
        self._kinds: dict[str, dict] = {}
        # kind -> source_id -> {"last_ts", "interval_ewma"}
        self._sources: dict[str, dict] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _day_key(ts):
        return ts.date()

    def observe(self, kind: str, ts, source_id=None) -> None:
        with self._lock:
            kind_state = self._kinds.setdefault(kind, {})
            bucket = kind_state.setdefault(
                _bucket_key(ts), {"samples": [], "open_day": None, "running": 0}
            )
            day = self._day_key(ts)
            if bucket["open_day"] is not None and day != bucket["open_day"]:
                # The previous day's hour is now closed history.
                bucket["samples"].append(bucket["running"])
                bucket["running"] = 0
            bucket["open_day"] = day
            bucket["running"] += 1

            if source_id is not None:
                src = self._sources.setdefault(kind, {}).setdefault(
                    source_id, {"last_ts": None, "interval_ewma": None}
                )
                last = src["last_ts"]
                if last is not None:
                    delta = (ts - last).total_seconds()
                    if delta > 0:
                        prev = src["interval_ewma"] or delta
                        src["interval_ewma"] = (1 - ALPHA) * prev + ALPHA * delta
                src["last_ts"] = ts

    def _stats(self, kind: str, ts) -> tuple[int, float, float]:
        """(sample_count, mean, stddev) of closed daily samples."""
        kind_state = self._kinds.get(kind) or {}
        bucket = kind_state.get(_bucket_key(ts))
        if not bucket:
            return 0, 0.0, 0.0
        samples = list(bucket["samples"])
        # Include today's still-open count as a partial sample.
        if bucket["open_day"] == self._day_key(ts):
            samples.append(bucket["running"])
        if not samples:
            return 0, 0.0, 0.0
        n = len(samples)
        mean = sum(samples) / n
        var = sum((s - mean) ** 2 for s in samples) / n
        return n, mean, math.sqrt(var)

    def snapshot(self, kind: str, ts) -> dict | None:
        """Current expectations for a kind at time ``ts``."""
        n, mean, std = self._stats(kind, ts)
        if n < 3:
            return None  # not enough history to judge
        return {"samples": n, "mean": mean, "stddev": std}

    def check_spike(self, kind: str, ts, current_count: int) -> bool:
        """True when ``current_count`` jumps beyond spike_sigma."""
        snap = self.snapshot(kind, ts)
        if snap is None:
            return False
        if snap["mean"] < MIN_BASELINE_FOR_SPIKE:
            return False
        threshold = snap["mean"] + self.spike_sigma * max(snap["stddev"], math.sqrt(snap["mean"]))
        return current_count > threshold

    def check_silence(self, kind: str, source_id, now=None) -> bool:
        """True when a source is overdue by a wide margin."""
        with self._lock:
            src = (self._sources.get(kind) or {}).get(source_id)
            if not src or src["last_ts"] is None or src["interval_ewma"] is None:
                return False
            expected_interval = src["interval_ewma"]
            last_ts = src["last_ts"]
        now = now or utcnow()
        elapsed = (now - last_ts).total_seconds()
        return elapsed > max(
            expected_interval * self.silence_multiplier, SILENCE_MIN_MINUTES * 60
        )

    def silence_candidates(self, kinds=None, now=None) -> list[dict]:
        """Sources currently suspiciously silent."""
        now = now or utcnow()
        results = []
        with self._lock:
            for kind, sources in self._sources.items():
                if kinds and kind not in kinds:
                    continue
                for source_id, src in sources.items():
                    if src["last_ts"] is None or src["interval_ewma"] is None:
                        continue
                    elapsed = (now - src["last_ts"]).total_seconds()
                    expected_interval = src["interval_ewma"]
                    if elapsed > max(expected_interval * self.silence_multiplier, SILENCE_MIN_MINUTES * 60):
                        results.append(
                            {
                                "kind": kind,
                                "source_id": source_id,
                                "last_seen": src["last_ts"],
                                "elapsed_seconds": elapsed,
                                "expected_interval": expected_interval,
                            }
                        )
        return results
