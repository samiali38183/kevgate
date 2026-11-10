"""SQLite persistence behind a small repository class.

One connection guarded by a lock. That is enough for a single-replica
service with modest write volume and keeps ":memory:" databases (tests)
working. WAL mode lets readers proceed while a write is committing.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime

from kevgate.models import Finding

# Append-only. Each entry is one schema version; PRAGMA user_version records progress.
MIGRATIONS: tuple[tuple[str, ...], ...] = (
    (
        """
        CREATE TABLE IF NOT EXISTS findings (
            cve        TEXT    NOT NULL,
            asset      TEXT    NOT NULL,
            acr        INTEGER NOT NULL CHECK (acr BETWEEN 1 AND 8),
            cvss       REAL    NOT NULL CHECK (cvss BETWEEN 0 AND 10),
            epss       REAL    NOT NULL CHECK (epss BETWEEN 0 AND 1),
            days_open  INTEGER NOT NULL CHECK (days_open >= 0),
            first_seen TEXT    NOT NULL,
            last_seen  TEXT    NOT NULL,
            PRIMARY KEY (cve, asset)
        ) WITHOUT ROWID
        """,
        "CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings (asset)",
    ),
)

_UPSERT = """
INSERT INTO findings (cve, asset, acr, cvss, epss, days_open, first_seen, last_seen)
VALUES (:cve, :asset, :acr, :cvss, :epss, :days_open, :now, :now)
ON CONFLICT (cve, asset) DO UPDATE SET
    acr = excluded.acr,
    cvss = excluded.cvss,
    epss = excluded.epss,
    days_open = excluded.days_open,
    last_seen = excluded.last_seen
"""

# Complete literal statements (no string building), so every query is visibly constant.
_SELECT_ALL = "SELECT cve, asset, acr, cvss, epss, days_open FROM findings"
_SELECT_BY_ASSET = "SELECT cve, asset, acr, cvss, epss, days_open FROM findings WHERE asset = ?"
_SELECT_BY_CVE = (
    "SELECT cve, asset, acr, cvss, epss, days_open FROM findings WHERE cve = ? ORDER BY asset"
)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _row_to_finding(row: sqlite3.Row) -> Finding:
    return Finding(
        cve=row["cve"],
        asset=row["asset"],
        acr=row["acr"],
        cvss=float(row["cvss"]),
        epss=float(row["epss"]),
        days_open=row["days_open"],
    )


class FindingRepository:
    """All SQL lives here. Every query is parameterised."""

    def __init__(self, path: str) -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA busy_timeout = 5000")
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA synchronous = NORMAL")
        self.migrate()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    @property
    def schema_version(self) -> int:
        with self._lock:
            return int(self._conn.execute("PRAGMA user_version").fetchone()[0])

    def migrate(self) -> int:
        """Apply pending migrations. Returns the resulting schema version."""
        with self._tx() as conn:
            current = int(conn.execute("PRAGMA user_version").fetchone()[0])
            for version, statements in enumerate(MIGRATIONS[current:], start=current + 1):
                for stmt in statements:
                    conn.execute(stmt)
                # PRAGMA does not accept bound parameters; version is an int we control.
                conn.execute(f"PRAGMA user_version = {int(version)}")
        return len(MIGRATIONS)

    def upsert_many(self, findings: Sequence[Finding]) -> int:
        """Insert or update on (cve, asset), all or nothing. Returns rows written."""
        now = _now()
        params = [{**f.model_dump(), "now": now} for f in findings]
        with self._tx() as conn:
            conn.executemany(_UPSERT, params)
        return len(params)

    def list_findings(self, asset: str | None = None) -> list[Finding]:
        with self._lock:
            if asset is None:
                rows = self._conn.execute(_SELECT_ALL).fetchall()
            else:
                rows = self._conn.execute(
                    _SELECT_BY_ASSET,
                    (asset,),
                ).fetchall()
        return [_row_to_finding(r) for r in rows]

    def get_by_cve(self, cve: str) -> list[Finding]:
        with self._lock:
            rows = self._conn.execute(
                _SELECT_BY_CVE,
                (cve.upper(),),
            ).fetchall()
        return [_row_to_finding(r) for r in rows]

    def delete(self, cve: str, asset: str) -> int:
        with self._tx() as conn:
            cur = conn.execute(
                "DELETE FROM findings WHERE cve = ? AND asset = ?", (cve.upper(), asset)
            )
            return cur.rowcount

    def count(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0])

    def ping(self) -> bool:
        """True if the database answers a trivial query."""
        try:
            with self._lock:
                self._conn.execute("SELECT 1").fetchone()
        except sqlite3.Error:
            return False
        return True

    def close(self) -> None:
        with self._lock:
            self._conn.close()
