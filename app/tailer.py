"""Background workers that follow log files and emit parsed records.

One :class:`TailWorker` thread per log source reads appended lines and
hands parsed records to a callback. The worker knows nothing about the
database or the detector engine; callers wire that up via the callback,
which keeps the follow logic testable in isolation.

Instead of holding a file handle open, each poll opens the path, reads
from the remembered byte offset and closes it again. That keeps the
worker friendly to logrotate and to Windows, where open handles block
renames. Rotation is detected with inode/device comparison (both
logrotate's create and rename produce a new file) and truncation by a
shrinking size; the trade-off is that lines appended to the old file in
the instant before a rotation can be missed. Partial trailing lines are
buffered until a newline arrives.
"""

import logging
import os
import threading

logger = logging.getLogger("watchtail")


class TailWorker(threading.Thread):
    """Follows a single log file and emits parsed records."""

    def __init__(
        self,
        source,
        parser,
        on_record,
        poll_interval=1.0,
        stop_event=None,
        persist_position=None,
    ):
        super().__init__(name=f"tail-{source.type}-{source.id}", daemon=True)
        self.source = source
        self.parser = parser
        self.on_record = on_record
        self.poll_interval = poll_interval
        self.stop_event = stop_event or threading.Event()
        self.persist_position = persist_position
        self.position = int(getattr(source, "last_position", 0) or 0)
        self._buffer = ""
        self._identity = None
        self._last_persisted = 0
        self._stats = {"parsed": 0, "skipped": 0, "bytes": 0}

    # -- lifecycle ---------------------------------------------------

    def run(self):
        logger.info("tailing %s (%s)", self.source.path, self.source.type)
        while not self.stop_event.is_set():
            try:
                self._poll_once()
            except Exception:
                logger.exception("tailer for %s failed; retrying", self.source.path)
            self.stop_event.wait(self.poll_interval)

    def stop(self):
        self.stop_event.set()

    # -- following ---------------------------------------------------

    def _poll_once(self):
        try:
            path_stat = os.stat(self.source.path)
        except OSError:
            # File may not exist yet (fresh container, rotated away);
            # keep waiting rather than crashing.
            return

        identity = (path_stat.st_ino, path_stat.st_dev)
        if self._identity is not None and identity != self._identity:
            # New file at the same path: start over from its beginning.
            self.position = 0
            self._buffer = ""
            logger.info("log rotated; reading %s from the start", self.source.path)
        self._identity = identity

        if path_stat.st_size < self.position:
            self.position = 0
            self._buffer = ""
            logger.info("log truncated; reading %s from the start", self.source.path)
        if path_stat.st_size == self.position:
            self._persist()
            return

        try:
            with open(self.source.path, "r", encoding="utf-8", errors="replace") as handle:
                handle.seek(self.position)
                self._read_available(handle)
        except OSError:
            logger.exception("could not read %s", self.source.path)
            return
        self._persist()

    def _read_available(self, handle):
        chunk = handle.read()
        if not chunk:
            return
        data = self._buffer + chunk
        lines = data.split("\n")
        self._buffer = lines.pop()
        for line in lines:
            self._handle_line(line.rstrip("\r"))
        # The buffer re-supplies the partial prefix on the next poll,
        # so the in-process position is simply the file end. Only the
        # persisted offset subtracts buffered bytes, so a restarted
        # worker re-reads the partial line it no longer remembers.
        self.position = handle.tell()
        self._stats["bytes"] += len(chunk.encode("utf-8", "replace"))

    def _handle_line(self, line):
        if not line.strip():
            return
        try:
            record = self.parser.parse(line)
        except Exception:
            logger.exception("parser %s failed on line: %r", self.parser.name, line[:200])
            record = None
        if record is None:
            self._stats["skipped"] += 1
            return
        self._stats["parsed"] += 1
        try:
            self.on_record(record, line)
        except Exception:
            logger.exception("record callback failed for %s", self.source.path)

    def _persist(self):
        if self.persist_position is None:
            return
        safe_offset = self.position - len(self._buffer.encode("utf-8", "replace"))
        if safe_offset == self._last_persisted:
            return
        try:
            self.persist_position(self.source.id, safe_offset)
            self._last_persisted = safe_offset
        except Exception:
            logger.exception("could not persist tail position for %s", self.source.path)

    @property
    def stats(self):
        return dict(self._stats)


class TailManager:
    """Owns one worker per enabled source and reconciles changes."""

    def __init__(self, parser_factory, on_record, poll_interval=1.0,
                 persist_position=None):
        self.parser_factory = parser_factory
        self.on_record = on_record
        self.poll_interval = poll_interval
        self.persist_position = persist_position
        self._workers: dict[int, TailWorker] = {}
        self._lock = threading.Lock()

    def sync(self, sources):
        """Start/stop workers so they match the given source rows.

        Sources with an unknown type are skipped (nothing to parse them
        with) and disabled rows are stopped.
        """
        with self._lock:
            wanted = {}
            for source in sources:
                if not source.enabled:
                    continue
                if self.parser_factory(source.type) is None:
                    logger.warning("no parser for source type %r; skipping %s",
                                   source.type, source.path)
                    continue
                wanted[source.id] = source

            for source_id in list(self._workers):
                if source_id not in wanted:
                    self._workers.pop(source_id).stop()

            for source_id, source in wanted.items():
                worker = self._workers.get(source_id)
                if worker is None or not worker.is_alive():
                    self._workers[source_id] = TailWorker(
                        source,
                        self.parser_factory(source.type),
                        self.on_record,
                        poll_interval=self.poll_interval,
                        persist_position=self.persist_position,
                    )
                    self._workers[source_id].start()

    def stop_all(self):
        with self._lock:
            workers = list(self._workers.values())
            self._workers.clear()
        for worker in workers:
            worker.stop()
        for worker in workers:
            worker.join(timeout=5)

    def running_ids(self):
        with self._lock:
            return set(self._workers)
