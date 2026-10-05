"""Remote log tailing over SSH.

``ssh://`` sources (``ssh://user@host/var/log/auth.log``) stream a
remote file through an SSH exec channel: the worker opens one
connection, runs ``tail -n <backlog> -F <path>`` (GNU tail's ``-F``
follows rotations on the remote side) and feeds every received line
through the source parser and the pipeline exactly like a local file
tailer.

Authentication uses the user's local SSH agent or default keys; the
config form ``ssh://user@host/path`` maps to paramiko's
``look_for_keys=True`` behaviour with an optional ``password``.
Connections are retried with a backoff so a rebooting host does not
kill the worker.
"""

import logging
import threading
import time
from urllib.parse import unquote, urlparse

logger = logging.getLogger("watchtail")

RECONNECT_BASE_SECONDS = 2.0
RECONNECT_MAX_SECONDS = 60.0


def parse_ssh_target(path: str):
    """Split ``ssh://user@host:2222/var/log/auth.log`` into its parts.

    Returns ``(user, host, port, file_path)`` or ``None`` when the path
    is not an ssh spec. The default remote user is ``root``; port
    defaults to 22.
    """
    text = (path or "").strip()
    if not text.lower().startswith("ssh://"):
        return None
    parsed = urlparse(text)
    host = parsed.hostname
    file_path = unquote(parsed.path or "")
    if not host or not file_path:
        return None
    return (
        parsed.username or "root",
        host,
        parsed.port or 22,
        file_path,
    )


def is_ssh_source(source) -> bool:
    return parse_ssh_target(getattr(source, "path", "")) is not None


class SshTailWorker(threading.Thread):
    """Follows a remote file over an SSH exec channel."""

    def __init__(self, source, parser, on_record, stop_event=None,
                 backlog_lines=100, connect_factory=None):
        super().__init__(name=f"ssh-tail-{source.type}-{source.id}", daemon=True)
        self.source = source
        self.parser = parser
        self._on_record = on_record
        self.on_record = lambda record, raw: on_record(record, raw, source)
        self.stop_event = stop_event or threading.Event()
        self.backlog_lines = int(getattr(source, "last_position", 0) or backlog_lines)
        # Tests inject a fake transport factory here.
        self._connect = connect_factory or self._connect_paramiko
        self._stats = {"parsed": 0, "skipped": 0, "bytes": 0}

    # -- connection --------------------------------------------------

    def _connect_paramiko(self):
        import paramiko

        target = parse_ssh_target(self.source.path)
        user, host, port, _path = target
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=host,
            port=port,
            username=user,
            look_for_keys=True,
            allow_agent=True,
            timeout=10.0,
            banner_timeout=10.0,
        )
        return client

    def _open_stream(self, client):
        target = parse_ssh_target(self.source.path)
        _user, _host, _port, file_path = target
        command = f"tail -n {self.backlog_lines} -F -- {file_path!r}"
        _stdin, stdout, _stderr = client.exec_command(command, get_pty=False)
        return stdout

    # -- lifecycle ---------------------------------------------------

    def run(self):
        target = parse_ssh_target(self.source.path)
        if target is None:
            logger.error("invalid ssh source path %r", self.source.path)
            return
        backoff = RECONNECT_BASE_SECONDS
        while not self.stop_event.is_set():
            client = None
            try:
                client = self._connect()
                stream = self._open_stream(client)
                logger.info(
                    "ssh tail connected (%s)", self.source.path
                )
                backoff = RECONNECT_BASE_SECONDS
                self._read_stream(stream)
            except Exception:
                if not self.stop_event.is_set():
                    logger.exception(
                        "ssh tail for %s failed; reconnecting", self.source.path
                    )
            finally:
                if client is not None:
                    try:
                        client.close()
                    except Exception:
                        pass
            if self.stop_event.is_set():
                break
            self.stop_event.wait(backoff)
            backoff = min(backoff * 2, RECONNECT_MAX_SECONDS)

    def stop(self):
        self.stop_event.set()

    def _read_stream(self, stream):
        buffer = b""
        while not self.stop_event.is_set():
            if stream.channel is not None and stream.channel.exit_status_ready():
                break
            if stream.channel is not None and stream.channel.recv_ready():
                chunk = stream.channel.recv(4096)
            else:
                time.sleep(0.2)
                continue
            if not chunk:
                continue
            self._stats["bytes"] += len(chunk)
            buffer += chunk
            while b"\n" in buffer:
                line, _, buffer = buffer.partition(b"\n")
                self._handle_line(line.decode("utf-8", "replace").rstrip("\r"))

    def _handle_line(self, line):
        if not line.strip():
            return
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
        self._stats["parsed"] += 1
        try:
            self.on_record(record, line)
        except Exception:
            logger.exception("record callback failed for %s", self.source.path)

    @property
    def stats(self):
        return dict(self._stats)


class SshTailRegistry:
    """Owns one SshTailWorker per enabled ssh:// source.

    Mirrors the TailManager/ListenerRegistry contract so run.py can
    reconcile all three worker families identically.
    """

    def __init__(self, parser_factory, on_record, connect_factory=None):
        self.parser_factory = parser_factory
        self.on_record = on_record
        self._connect_factory = connect_factory
        self._workers: dict[int, SshTailWorker] = {}
        self._lock = threading.Lock()

    def sync(self, sources):
        with self._lock:
            wanted = {}
            for source in sources:
                if not source.enabled or not is_ssh_source(source):
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
                    worker = SshTailWorker(
                        source,
                        self.parser_factory(source.type),
                        self.on_record,
                        connect_factory=self._connect_factory,
                    )
                    self._workers[source_id] = worker
                    worker.start()

    def stop_all(self):
        with self._lock:
            workers = list(self._workers.values())
            self._workers.clear()
        for worker in workers:
            worker.stop()

    def running_ids(self):
        with self._lock:
            return set(self._workers)
