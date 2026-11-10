from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from kevgate.db import MIGRATIONS, FindingRepository
from kevgate.models import Finding


def f(cve: str = "CVE-2021-44228", asset: str = "web-01", **kw: object) -> Finding:
    base: dict[str, object] = {"acr": 4, "cvss": 5.0, "epss": 0.5, "days_open": 1}
    base.update(kw)
    return Finding.model_validate({"cve": cve, "asset": asset, **base})


@pytest.fixture
def repo() -> FindingRepository:
    return FindingRepository(":memory:")


def test_migrations_set_user_version(repo: FindingRepository) -> None:
    assert repo.schema_version == len(MIGRATIONS)
    # Running again is a no-op.
    assert repo.migrate() == len(MIGRATIONS)
    assert repo.schema_version == len(MIGRATIONS)


def test_upsert_is_idempotent(repo: FindingRepository) -> None:
    assert repo.upsert_many([f()]) == 1
    assert repo.upsert_many([f()]) == 1
    assert repo.count() == 1


def test_upsert_updates_fields_on_conflict(repo: FindingRepository) -> None:
    repo.upsert_many([f(cvss=5.0, days_open=1)])
    repo.upsert_many([f(cvss=9.8, days_open=30)])
    (stored,) = repo.list_findings()
    assert stored.cvss == 9.8 and stored.days_open == 30


def test_upsert_keeps_first_seen(tmp_path: Path) -> None:
    db = tmp_path / "k.db"
    repo = FindingRepository(str(db))
    repo.upsert_many([f()])
    conn = sqlite3.connect(db)
    conn.execute("UPDATE findings SET first_seen = '2020-01-01T00:00:00+00:00'")
    conn.commit()
    conn.close()
    repo.upsert_many([f(cvss=9.0)])
    conn = sqlite3.connect(db)
    first, last = conn.execute("SELECT first_seen, last_seen FROM findings").fetchone()
    conn.close()
    repo.close()
    assert first == "2020-01-01T00:00:00+00:00" and last > first


def test_same_cve_different_assets_are_distinct(repo: FindingRepository) -> None:
    repo.upsert_many([f(asset="a"), f(asset="b"), f("CVE-2024-3400", asset="a")])
    assert repo.count() == 3
    assert [x.asset for x in repo.get_by_cve("cve-2021-44228")] == ["a", "b"]
    assert {x.cve for x in repo.list_findings("a")} == {"CVE-2021-44228", "CVE-2024-3400"}


def test_batch_is_atomic(repo: FindingRepository) -> None:
    good = f()
    # Bypass model validation to simulate a row the CHECK constraint rejects.
    bad = Finding.model_construct(
        cve="CVE-2024-3400", asset="a", acr=99, cvss=1.0, epss=0.1, days_open=1
    )
    with pytest.raises(sqlite3.IntegrityError):
        repo.upsert_many([good, bad])
    assert repo.count() == 0


def test_delete(repo: FindingRepository) -> None:
    repo.upsert_many([f(asset="a"), f(asset="b")])
    assert repo.delete("cve-2021-44228", "a") == 1
    assert repo.delete("CVE-2021-44228", "a") == 0
    assert repo.count() == 1


def test_sql_injection_in_asset_is_inert(repo: FindingRepository) -> None:
    repo.upsert_many([f(asset="x' OR '1'='1")])
    assert repo.list_findings("anything' OR '1'='1") == []
    assert len(repo.list_findings("x' OR '1'='1")) == 1


def test_ping_false_after_close(repo: FindingRepository) -> None:
    assert repo.ping() is True
    repo.close()
    assert repo.ping() is False


def test_file_db_uses_wal(tmp_path: Path) -> None:
    repo = FindingRepository(str(tmp_path / "k.db"))
    conn = sqlite3.connect(tmp_path / "k.db")
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    conn.close()
    repo.close()


def test_unopenable_path_raises(tmp_path: Path) -> None:
    with pytest.raises(sqlite3.OperationalError):
        FindingRepository(str(tmp_path / "missing-dir" / "k.db"))
