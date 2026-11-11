"""/readyz depth: writable storage with headroom, a rolled-back write, a cheap integrity probe."""

from __future__ import annotations

import os
import shutil
import sqlite3
from collections import namedtuple
from pathlib import Path
from typing import Any

import pytest
from conftest import KEV_PATH, app_state
from fastapi.testclient import TestClient

from kevgate import db as db_module
from kevgate.app import create_app
from kevgate.config import Settings
from kevgate.db import FindingRepository
from kevgate.models import Finding


def _rows(n: int) -> list[Finding]:
    return [
        Finding(cve=f"CVE-2021-{i:05d}", asset="a", acr=4, cvss=5.0, epss=0.1, days_open=1)
        for i in range(n)
    ]


class SpyConn:
    """Delegates to a real connection; counts quick_check runs and can inject an error."""

    def __init__(self, real: sqlite3.Connection, error: Exception | None = None) -> None:
        self._real = real
        self.quick_checks = 0
        self.error = error

    def execute(self, sql: str, *args: Any) -> sqlite3.Cursor:
        if sql.startswith("PRAGMA quick_check"):
            self.quick_checks += 1
            if self.error is not None:
                raise self.error
        return self._real.execute(sql, *args)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


@pytest.fixture
def repo(tmp_path: Path) -> FindingRepository:
    r = FindingRepository(str(tmp_path / "k.db"))
    yield r  # type: ignore[misc]
    r.close()


# ---- storage -------------------------------------------------------------------------


def test_storage_ok_for_writable_directory(repo: FindingRepository) -> None:
    assert repo.storage_ok() is True


def test_storage_ok_always_true_in_memory() -> None:
    assert FindingRepository(":memory:").storage_ok() is True


def test_storage_fails_when_directory_not_writable(
    repo: FindingRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "access", lambda *_a, **_k: False)
    assert repo.storage_ok() is False


def test_storage_fails_when_disk_nearly_full(
    repo: FindingRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(shutil, "disk_usage", lambda _p: usage(100, 100 - 10, 10))
    assert repo.storage_ok() is False
    monkeypatch.setattr(shutil, "disk_usage", lambda _p: usage(10**9, 0, db_module.MIN_FREE_BYTES))
    assert repo.storage_ok() is True


def test_storage_fails_when_directory_vanishes(
    repo: FindingRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(_p: object) -> None:
        raise FileNotFoundError

    monkeypatch.setattr(shutil, "disk_usage", boom)
    assert repo.storage_ok() is False


# ---- write probe ---------------------------------------------------------------------


def test_write_probe_succeeds_and_commits_nothing(repo: FindingRepository) -> None:
    before = repo.schema_version
    assert repo.write_probe() is True
    assert repo.schema_version == before
    assert repo.count() == 0
    # The write lock was released: a real write still works right after.
    assert repo.upsert_many(_rows(1)) == 1


def test_write_probe_fails_when_another_connection_holds_the_write_lock(
    tmp_path: Path,
) -> None:
    path = str(tmp_path / "k.db")
    repo = FindingRepository(path)
    repo._conn.execute("PRAGMA busy_timeout = 0")
    other = sqlite3.connect(path, isolation_level=None)
    other.execute("BEGIN IMMEDIATE")
    try:
        assert repo.write_probe() is False
    finally:
        other.execute("ROLLBACK")
        other.close()
    assert repo.write_probe() is True
    repo.close()


def test_write_probe_false_after_close(repo: FindingRepository) -> None:
    repo.close()
    assert repo.write_probe() is False


# ---- integrity probe -----------------------------------------------------------------


def test_integrity_ok_on_healthy_database(repo: FindingRepository) -> None:
    repo.upsert_many(_rows(50))
    assert repo.integrity_ok() is True


def test_integrity_detects_corruption(tmp_path: Path) -> None:
    path = tmp_path / "k.db"
    r = FindingRepository(str(path))
    r.upsert_many(_rows(1000))
    r.close()
    size = path.stat().st_size
    assert size > 3 * 4096
    with path.open("r+b") as fh:
        fh.seek(4096 * 2)
        fh.write(b"\xff" * 4096)
    r2 = FindingRepository(str(path))
    try:
        assert r2.integrity_ok() is False
    finally:
        r2.close()


def test_integrity_verdict_is_cached_then_refreshed(
    repo: FindingRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [1000.0]
    monkeypatch.setattr(repo, "_clock", lambda: now[0])
    spy = SpyConn(repo._conn)
    repo._conn = spy  # type: ignore[assignment]
    assert repo.integrity_ok() is True
    assert repo.integrity_ok() is True
    assert spy.quick_checks == 1
    now[0] += db_module.INTEGRITY_TTL_SECONDS + 1
    assert repo.integrity_ok() is True
    assert spy.quick_checks == 2


def test_integrity_over_budget_is_inconclusive_not_failed_and_not_cached(
    repo: FindingRepository,
) -> None:
    repo.upsert_many(_rows(1000))
    assert repo.integrity_ok(budget=-1.0) is True
    assert repo._integrity_checked_at is None  # next probe tries again


def test_integrity_sqlite_error_is_a_failure(repo: FindingRepository) -> None:
    repo._conn = SpyConn(repo._conn, sqlite3.OperationalError("disk I/O error"))  # type: ignore[assignment]
    assert repo.integrity_ok() is False
    repo._conn = SpyConn(repo._conn, sqlite3.DatabaseError("malformed"))  # type: ignore[assignment]
    assert repo.integrity_ok() is False


# ---- /readyz -------------------------------------------------------------------------


def test_readyz_ok_with_real_database_file(tmp_path: Path) -> None:
    c = TestClient(create_app(settings=Settings(db_path=str(tmp_path / "k.db"), kev_path=KEV_PATH)))
    r = c.get("/readyz")
    assert r.status_code == 200
    assert r.json()["checks"] == {"db": "ok", "storage": "ok", "kev": "ok"}


@pytest.mark.parametrize(
    ("method", "failed_check"),
    [("storage_ok", "storage"), ("write_probe", "db"), ("integrity_ok", "db")],
)
def test_readyz_503_when_a_probe_fails(
    open_client: TestClient, monkeypatch: pytest.MonkeyPatch, method: str, failed_check: str
) -> None:
    monkeypatch.setattr(app_state(open_client).repo, method, lambda *_a, **_k: False)
    r = open_client.get("/readyz")
    assert r.status_code == 503
    checks = r.json()["checks"]
    assert checks[failed_check] == "fail"
    assert open_client.get("/healthz").status_code == 200  # liveness is unaffected
