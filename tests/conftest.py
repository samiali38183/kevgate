from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient

from kevgate.app import AppState, create_app
from kevgate.auth import Scope, format_key_line, generate_key
from kevgate.config import Settings

ROOT = Path(__file__).resolve().parents[1]
KEV_PATH = str(ROOT / "data" / "kev_sample.json")
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def finding(cve: str = "CVE-2021-44228", **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "cve": cve,
        "asset": "web-01",
        "acr": 5,
        "cvss": 9.0,
        "epss": 0.5,
        "days_open": 10,
    }
    base.update(kw)
    return base


def app_state(c: TestClient) -> AppState:
    return cast(AppState, c.app.state.kevgate)  # type: ignore[attr-defined]


@dataclass(frozen=True)
class Keys:
    """Real keys generated per test run; only their hashes go to the key file."""

    path: str
    writer: str
    reader: str
    admin: str
    both: str


@pytest.fixture
def keys(tmp_path: Path) -> Keys:
    writer, reader, admin, both = (generate_key() for _ in range(4))
    lines = [
        "# test key file",
        format_key_line("writer", [Scope.FINDINGS_WRITE], writer),
        format_key_line("reader", [Scope.QUEUE_READ], reader),
        format_key_line("admin", [Scope.ADMIN], admin),
        "",
        format_key_line("both", [Scope.FINDINGS_WRITE, Scope.QUEUE_READ], both),
    ]
    path = tmp_path / "keys.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return Keys(str(path), writer, reader, admin, both)


def bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


AppFactory = Callable[..., TestClient]


@pytest.fixture
def make_client(keys: Keys) -> AppFactory:
    def _make(*, auth: bool = True, **overrides: Any) -> TestClient:
        settings = Settings(
            db_path=":memory:",
            kev_path=KEV_PATH,
            api_keys_file=keys.path if auth else None,
            **overrides,
        )
        return TestClient(create_app(settings=settings))

    return _make


@pytest.fixture
def client(make_client: AppFactory) -> TestClient:
    """Authenticated app (auth enabled)."""
    return make_client()


@pytest.fixture
def open_client(make_client: AppFactory) -> TestClient:
    """Dev app with auth disabled."""
    return make_client(auth=False)
