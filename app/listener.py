"""Network listeners for sources that arrive over UDP or TCP.

Sources whose path looks like ``udp://0.0.0.0:5140`` or
``tcp://0.0.0.0:5140`` are not files: they are sockets that receive
syslog (or any line-based) traffic. Each listener source gets a
:class:`ListenerWorker` thread that accepts datagrams or connections,
splits the payload into lines and feeds every line through the source's
parser and the same ``on_record`` callback the file tailers use, so the
pipeline, detectors, alerts and notifiers behave identically.

Malformed payloads are counted and dropped; a broken TCP connection
only closes that one client socket.
"""

import logging
import socket
import threading

logger = logging.getLogger("watchtail")

MAX_DATAGRAM_BYTES = 65535
MAX_LINE_LENGTH = 16384


def parse_endpoint(path: str):
    """Split ``udp://host:port`` / ``tcp://host:port`` into its parts.

    Returns ``(proto, host, port)`` or ``None`` when the path is not an
    endpoint spec.
    """
    text = (path or "").strip()
    proto, sep, rest = text.partition("://")
    if not sep or proto.lower() not in ("udp", "tcp"):
        return None
    host, _, port_text = rest.rpartition(":")
    try:
        port = int(port_text)
    except ValueError:
        return None
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not 0 < port < 65536 or not host:
        return None
    return proto.lower(), host, port


def is_listener_source(source) -> bool:
    """True when the source row describes a network endpoint."""
    return parse_endpoint(getattr(source, "path", "")) is not None


class ListenerWorker(threading.Thread):
    """Binds an endpoint and feeds received lines to on_record."""

    def __init__(self, source, parser, on_record, stop_event=None):
        super().__init__(name=f"listen-{source.type}-{source.id}", daemon=True)
        self.source = source
        self.parser = parser
        self._on_record = on_record
        # Raw-worker callbacks receive (record, raw); wiring through
        # this adapter mirrors TailManager and keeps the signature the
        # pipeline expects: (record, raw, source).
        self.on_record = lambda record, raw: on_record(record, raw, source)
        self.stop_event = stop_event or threading.Event()
        self._sock = None
        self._stats = {"parsed": 0, "skipped": 0, "bytes": 0}

    # -- lifecycle ---------------------------------------------------

    def run(self):
        endpoint = parse_endpoint(self.source.path)
        if endpoint is None:
            logger.error("invalid listener endpoint %r", self.source.path)
            return
        proto, host, port = endpoint
        try:
            self._sock = self._bind(proto, host, port)
        except OSError:
            logger.exception(
                "could not bind %s://%s:%d; listener disabled", proto, host, port
            )
            return
        logger.info("listening on %s://%s:%d (%s)", proto, host, port, self.source.type)
        try:
            if proto == "udp":
                self._serve_udp()
            else:
                self._serve_tcp()
        except Exception:
            if not self.stop_event.is_set():
                logger.exception("listener %s failed", self.source.path)
        finally:
            self._close()

    def stop(self):
        self.stop_event.set()
        self._close()

    def _close(self):
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def _bind(self, proto, host, port) -> socket.socket:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        if proto == "tcp":
            sock.listen(8)
        sock.settimeout(0.5)  # lets stop() interrupt the accept/recv loop
        return sock

    # -- serving -----------------------------------------------------

    def _serve_udp(self):
        while not self.stop_event.is_set():
            try:
                payload, addr = self._sock.recvfrom(MAX_DATAGRAM_BYTES)
            except socket.timeout:
                continue
            except OSError:
                break
            self._stats["bytes"] += len(payload)
            self._handle_payload(payload.decode("utf-8", "replace"), addr)

    def _serve_tcp(self):
        while not self.stop_event.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._serve_connection(conn, addr)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def _serve_connection(self, conn, addr):
        conn.settimeout(2.0)
        buffer = b""
        while not self.stop_event.is_set():
            try:
                chunk = conn.recv(4096)
            except (socket.timeout, OSError):
                break
            if not chunk:
                break
            self._stats["bytes"] += len(chunk)
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = self._split_line(buffer)
                self._handle_payload(line, addr)

    @staticmethod
    def _split_line(buffer):
        line, _, rest = buffer.partition(b"\n")
        return line, rest

    def _handle_payload(self, text, addr):
        if isinstance(text, bytes):
            text = text.decode("utf-8", "replace")
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if len(line) > MAX_LINE_LENGTH:
                self._stats["skipped"] += 1
                continue
            self._handle_line(line, addr)

    def _handle_line(self, line, addr):
        try:
            record = self.parser.parse(line)
        except Exception:
            logger.exception(
                "parser %s failed on line: %r", self.parser.name, line[:200]
            )
            record = None
        if record is None:
            self._stats["skipped"] += 1
            return
        # Unparsed IPs fall back to the sender address so detectors and
        # scoring still work for syslog senders that omit hostnames.
        if not record.ip and addr is not None:
            record.ip = addr[0]
        self._stats["parsed"] += 1
        try:
            self.on_record(record, line)
        except Exception:
            logger.exception("record callback failed for %s", self.source.path)

    @property
    def stats(self):
        return dict(self._stats)


class ListenerRegistry:
    """Owns one ListenerWorker per enabled endpoint source.

    Mirrors TailManager's contract (``sync`` / ``stop_all`` /
    ``running_ids``) so the manager glue in run.py can drive both
    worker families with one code path.
    """

    def __init__(self, parser_factory, on_record):
        self.parser_factory = parser_factory
        self.on_record = on_record
        self._workers: dict[int, ListenerWorker] = {}
        self._lock = threading.Lock()

    def sync(self, sources):
        with self._lock:
            wanted = {}
            for source in sources:
                if not source.enabled or not is_listener_source(source):
                    continue
                if self.parser_factory(source.type) is None:
                    continue
                wanted[source.id] = source

            for source_id in list(self._workers):
                if source_id not in wanted:
                    self._workers.pop(source_id).stop()

            for source_id, source in wanted.items():
                worker = self._workers.get(source_id)
                if worker is None or not worker.is_alive():
                    def callback(record, raw, _source=source):
                        self.on_record(record, raw, _source)

                    worker = ListenerWorker(
                        source,
                        self.parser_factory(source.type),
                        callback,
                    )
                    self._workers[source_id] = worker
                    worker.start()

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
