"""Lightweight, idempotent schema migrations.

SQLite ALTER TABLE support is narrow (ADD COLUMN only), which is
exactly what the annotation features need. Migrations run at app
startup inside the factory; each is a no-op once applied, so startups
stay cheap and safe to repeat.
"""

import logging

from sqlalchemy import text

from .database import get_engine

logger = logging.getLogger("watchtail")

# (table, column, DDL) triples applied in order when missing.
COLUMN_MIGRATIONS = [
    (
        "ip_status",
        "operator_note",
        "ALTER TABLE ip_status ADD COLUMN operator_note TEXT",
    ),
    (
        "ip_status",
        "tags",
        "ALTER TABLE ip_status ADD COLUMN tags JSON DEFAULT '[]'",
    ),
]


def run_migrations():
    """Add columns that do not exist yet; log once per new column."""
    engine = get_engine()
    applied = []
    with engine.connect() as conn:
        for table, column, ddl in COLUMN_MIGRATIONS:
            exists = conn.execute(
                text(
                    "SELECT 1 FROM pragma_table_info(:table) WHERE name = :column"
                ),
                {"table": table, "column": column},
            ).first()
            if exists is None:
                conn.execute(text(ddl))
                applied.append(f"{table}.{column}")
        conn.commit()
    if applied:
        logger.info("applied migrations: %s", ", ".join(applied))
    return applied
