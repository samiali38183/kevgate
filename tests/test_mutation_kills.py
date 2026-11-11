"""Tests that pin behaviour a coverage number cannot see.

Each test below fails against one specific deliberate defect (a "mutant"):
early-exit key comparison, ``==`` instead of ``hmac.compare_digest``,
``BEGIN`` instead of ``BEGIN IMMEDIATE``, a body counter that keeps only the
last chunk, CSV merge taking the minimum CVSS, and an upsert that skips epss.
"""

from __future__ import annotations

import asyncio
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from starlette.exceptions import HTTPException
from starlette.types import Message, Scope

from kevgate import auth
from kevgate.auth import KeyStore, format_key_line, generate_key
from kevgate.auth import Scope as KeyScope
from kevgate.csv_import import parse_csv
from kevgate.db import FindingRepository
from kevgate.middleware import BodySizeLimitMiddleware
from kevgate.models import Finding


def _finding(**kw: Any) -> Finding:
    base: dict[str, Any] = {
        "cve": "CVE-2021-44228",
        "asset": "a",
        "acr": 5,
        "cvss": 5.0,
        "epss": 0.1,
        "days_open": 1,
    }
    base.update(kw)
    return Finding(**base)


def test_upsert_updates_epss(tmp_path: Path) -> None:
    repo = FindingRepository(str(tmp_path / "k.db"))
    repo.upsert_many([_finding(epss=0.1)])
    repo.upsert_many([_finding(epss=0.9)])
    assert repo.list_findings()[0].epss == 0.9
    repo.close()


def test_csv_duplicate_rows_keep_highest_cvss() -> None:
    text = "Host,CVE,CVSS\nweb,CVE-2021-44228,5.0\nweb,CVE-2021-44228,9.0\n"
    res = parse_csv(text, now=datetime(2026, 1, 1, tzinfo=UTC))
    assert [x.cvss for x in res.findings] == [9.0]


def test_transaction_takes_the_write_lock_immediately(tmp_path: Path) -> None:
    path = str(tmp_path / "k.db")
    repo = FindingRepository(path)
    other = sqlite3.connect(path, timeout=0, isolation_level=None)
    with repo._tx(), pytest.raises(sqlite3.OperationalError):
        other.execute("BEGIN IMMEDIATE")
    other.close()
    repo.close()


def test_authenticate_compares_every_key_with_compare_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    real = auth.hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        calls.append(1)
        return real(a, b)

    monkeypatch.setattr(auth.hmac, "compare_digest", spy)
    keys = [generate_key() for _ in range(3)]
    store = KeyStore.parse(
        [format_key_line(f"k{i}", [KeyScope.ADMIN], k) for i, k in enumerate(keys)]
    )
    found = store.authenticate(keys[0])  # the FIRST key matches
    assert found is not None
    assert found.key_id == "k0"
    assert len(calls) == 3  # no early exit, and compare_digest (not ==) is used


def _run_body_limit(chunks: list[bytes], max_bytes: int = 1000) -> int:
    """Drive the middleware directly: TestClient delivers a body as one message."""
    seen: dict[str, int] = {}

    async def app(scope: Scope, receive: Any, send: Any) -> None:
        total = 0
        while True:
            m = await receive()
            total += len(m.get("body", b""))
            if not m.get("more_body", False):
                break
        seen["total"] = total

    mw = BodySizeLimitMiddleware(app, max_bytes=max_bytes)
    msgs: list[Message] = [
        {"type": "http.request", "body": c, "more_body": i < len(chunks) - 1}
        for i, c in enumerate(chunks)
    ]

    async def receive() -> Message:
        return msgs.pop(0)

    async def send(_: Message) -> None:
        return None

    scope: Scope = {"type": "http", "headers": [], "method": "POST", "path": "/"}
    try:
        asyncio.run(mw(scope, receive, send))
    except HTTPException as exc:
        return exc.status_code
    return seen["total"]


def test_many_small_chunks_over_limit_is_413() -> None:
    assert _run_body_limit([b"x" * 400] * 3) == 413


def test_chunks_under_limit_pass_through() -> None:
    assert _run_body_limit([b"x" * 400] * 2) == 800
