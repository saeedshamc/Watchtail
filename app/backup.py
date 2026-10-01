"""Database backup and restore.

Backups copy every table's rows into a gzip-compressed JSON archive
(table -> list of row dicts). Restore drops and recreates the schema,
then reinserts the rows inside one transaction per table. The format is
deliberately plain so archives stay inspectable and portable between
machines (e.g. SQLite dev box -> PostgreSQL server).
"""

import datetime as dt
import gzip
import json

from sqlalchemy import text

from .database import create_all, drop_all, get_engine, session_scope
from .models import Base

ARCHIVE_FORMAT = "watchtail-backup"


def backup_to_path(path: str) -> dict:
    """Dump all tables into a gzipped JSON archive; returns the stats."""
    engine = get_engine()
    payload = {
        "format": ARCHIVE_FORMAT,
        "version": 1,
        "tables": {},
    }
    inspector = __import__("sqlalchemy").inspect(engine)
    for table in Base.metadata.sorted_tables:
        if not inspector.has_table(table.name):
            payload["tables"][table.name] = []
            continue
        with engine.connect() as conn:
            rows = conn.execute(text(f'SELECT * FROM "{table.name}"')).mappings().all()
        payload["tables"][table.name] = [
            {key: _jsonify(value) for key, value in dict(row).items()} for row in rows
        ]

    with open(path, "wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as archive:
            archive.write(json.dumps(payload, default=str).encode("utf-8"))

    return {
        "path": path,
        "tables": {
            name: len(rows) for name, rows in payload["tables"].items()
        },
    }


def _jsonify(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if hasattr(value, "isoformat"):  # datetimes
        return value.isoformat()
    if isinstance(value, (list, dict)):
        return value
    return str(value)


def restore_from_path(path: str) -> dict:
    """Restore a backup archive into the configured database."""
    with open(path, "rb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="rb") as archive:
            payload = json.loads(archive.read().decode("utf-8"))

    if payload.get("format") != ARCHIVE_FORMAT:
        raise ValueError(f"{path!r} is not a watchtail backup archive")

    engine = get_engine()
    table_names = set(payload.get("tables") or {})
    restored = {}

    # Rebuild the schema so row counts land exactly as archived.
    with engine.connect() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            if inspector_has_table(conn, table.name):
                conn.execute(text(f'DROP TABLE IF EXISTS "{table.name}"'))
        conn.commit()
    drop_all()
    create_all()

    for table in Base.metadata.sorted_tables:
        rows = payload["tables"].get(table.name) or []
        if not rows:
            restored[table.name] = 0
            continue
        with session_scope() as session:
            for row in rows:
                decoded = {
                    key: _decode_value(table, key, value)
                    for key, value in row.items()
                    if key in table.columns
                }
                session.execute(table.insert().values(**decoded))
        restored[table.name] = len(rows)
    return restored


def inspector_has_table(conn, name: str) -> bool:
    from sqlalchemy import inspect

    return inspect(conn).has_table(name)


def _decode_value(table, key, value):
    """Convert archived JSON scalars back into column-appropriate types."""
    if value is None:
        return None
    column = table.columns[key]
    python_type = None
    try:
        python_type = column.type.python_type
    except NotImplementedError:
        python_type = None

    if python_type is dt.datetime:
        try:
            return dt.datetime.fromisoformat(value)
        except (TypeError, ValueError):
            return value
    if python_type is dt.date:
        try:
            return dt.date.fromisoformat(value)
        except (TypeError, ValueError):
            return value
    if python_type is bool:
        if isinstance(value, bool):
            return value
        return str(value).lower() in ("1", "true", "t", "yes")
    if python_type is int and not isinstance(value, bool):
        try:
            return int(value)
        except (TypeError, ValueError):
            return value
    if python_type is float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return value
    if isinstance(value, (list, dict)):
        # JSON columns (tags, meta) survive the archive natively.
        return value
    if isinstance(value, str) and value[:1] in ("[", "{"):
        # JSON stored as text: decode it back so list/dict columns
        # round-trip as structures, not strings.
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value
