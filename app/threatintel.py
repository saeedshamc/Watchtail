"""Local threat intelligence: blocklists of known-bad IP ranges.

Operators point watchtail.yml at one or more blocklist files (FireHOL
netsets, AbuseIPDB CSV exports, or a plain one-IP-per-line text).
Ranges live in memory as parsed networks; every new event's IP is
matched against them so a known attacker is flagged as ``critical``
the moment it reappears — before any detector threshold is reached.
"""

import csv
import ipaddress
import logging
import os
import threading

logger = logging.getLogger("watchtail")


class Blocklist:
    """A set of networks with fast membership checks."""

    def __init__(self, name):
        self.name = name
        self._v4: list[ipaddress.IPv4Network] = []
        self._v6: list[ipaddress.IPv6Network] = []
        self._exact: set[str] = set()

    def add(self, entry: str):
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            return
        # Plain addresses stay in the exact set; CIDR becomes a network.
        if "/" not in entry:
            try:
                ipaddress.ip_address(entry)
            except ValueError:
                logger.warning(
                    "blocklist %s: skipping bad entry %r", self.name, entry
                )
                return
            self._exact.add(entry)
            return
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            logger.warning("blocklist %s: skipping bad entry %r", self.name, entry)
            return
        if net.version == 4:
            self._v4.append(net)
        else:
            self._v6.append(net)

    def contains(self, ip: str) -> bool:
        if ip in self._exact:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        nets = self._v4 if addr.version == 4 else self._v6
        return any(addr in net for net in nets)

    def __len__(self):
        return len(self._exact) + len(self._v4) + len(self._v6)


class BlocklistStore:
    """All configured blocklists plus a lookup cache for repeated hits."""

    def __init__(self):
        self._lists: list[Blocklist] = []
        self._cache: dict[str, str | None] = {}
        self._lock = threading.Lock()

    def load_file(self, path: str, name=None) -> int:
        """Load one blocklist file; returns the number of entries."""
        blocklist = Blocklist(name or os.path.basename(path))
        if not os.path.exists(path):
            logger.warning("blocklist file missing: %s", path)
            return 0
        count = 0
        with open(path, encoding="utf-8", errors="replace") as fh:
            sample = fh.read(4096)
            fh.seek(0)
            if "," in sample and "IP" in sample.upper():
                # AbuseIPDB-style CSV: find the address column by header.
                reader = csv.DictReader(fh)
                column = next(
                    (c for c in (reader.fieldnames or [])
                     if c and c.lower() in ("ip", "ipaddress", "ip_address", "address")),
                    None,
                )
                if column:
                    for row in reader:
                        value = (row.get(column) or "").strip()
                        if value:
                            blocklist.add(value)
                            count += 1
            else:
                for line in fh:
                    before = len(blocklist)
                    blocklist.add(line.split()[0] if line.split() else line)
                    if len(blocklist) > before:
                        count += 1
        if count:
            with self._lock:
                self._lists.append(blocklist)
                self._cache.clear()
        logger.info("blocklist %s loaded with %d entries", blocklist.name, count)
        return count

    def lookup(self, ip: str) -> str | None:
        """Name of the first matching blocklist, or None."""
        with self._lock:
            if ip in self._cache:
                return self._cache[ip]
        hit = None
        for blocklist in self._lists:
            if blocklist.contains(ip):
                hit = blocklist.name
                break
        with self._lock:
            self._cache[ip] = hit
        return hit

    @property
    def size(self):
        return sum(len(blocklist) for blocklist in self._lists)


_store: BlocklistStore | None = None
_store_lock = threading.Lock()


def get_store() -> BlocklistStore:
    global _store
    with _store_lock:
        if _store is None:
            _store = BlocklistStore()
        return _store


def reset_store():
    """Drop the process-wide store (used by tests and config reload)."""
    global _store
    with _store_lock:
        _store = None


def load_from_settings(settings) -> int:
    """(Re)load every blocklist declared in settings.threatintel."""
    config = getattr(settings, "threatintel", None) or {}
    reset_store()
    store = get_store()
    total = 0
    for entry in config.get("blocklists", []):
        path = entry.get("path") if isinstance(entry, dict) else entry
        name = entry.get("name") if isinstance(entry, dict) else None
        if path:
            total += store.load_file(path, name)
    return total
