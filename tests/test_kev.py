from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from kevgate.kev import (
    KevFeedError,
    fetch_kev_feed,
    parse_kev_feed,
    refresh_kev,
    write_atomic,
)
from kevgate.scoring import load_kev

FEED = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.11.07",
    "count": 2,
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "dateAdded": "2021-12-10"},
        {"cveID": "cve-2024-3400", "vendorProject": "Palo Alto Networks"},
    ],
}


class FakeResponse(io.BytesIO):
    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def opener_returning(body: bytes) -> Any:
    calls: list[Any] = []

    def _open(request: Any, timeout: float) -> FakeResponse:
        calls.append((request, timeout))
        return FakeResponse(body)

    _open.calls = calls  # type: ignore[attr-defined]
    return _open


def test_parse_ignores_extra_fields_and_uppercases() -> None:
    assert parse_kev_feed(json.dumps(FEED)) == {"CVE-2021-44228", "CVE-2024-3400"}


@pytest.mark.parametrize(
    "doc",
    [
        "not json",
        "[]",
        '{"vulnerabilities": "nope"}',
        '{"vulnerabilities": [{"cveID": "CVE-21-1"}]}',
        '{"vulnerabilities": [{"vendor": "x"}]}',
        '{"count": 3, "vulnerabilities": [{"cveID": "CVE-2021-44228"}]}',
    ],
)
def test_parse_rejects_bad_feeds(doc: str) -> None:
    with pytest.raises(KevFeedError):
        parse_kev_feed(doc)


def test_load_kev_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        load_kev(str(tmp_path / "nope.json"))


def test_fetch_sends_timeout_and_user_agent() -> None:
    opener = opener_returning(b"{}")
    assert fetch_kev_feed("https://example.test/kev.json", timeout=7, opener=opener) == b"{}"
    request, timeout = opener.calls[0]
    assert timeout == 7
    assert request.get_header("User-agent") == "kevgate-kev-refresh"


def test_fetch_refuses_plain_http() -> None:
    with pytest.raises(KevFeedError, match="non-HTTPS"):
        fetch_kev_feed("http://example.test/kev.json", opener=opener_returning(b"{}"))


def test_fetch_enforces_size_cap() -> None:
    with pytest.raises(KevFeedError, match="larger than"):
        fetch_kev_feed("https://x.test/", max_bytes=10, opener=opener_returning(b"x" * 11))


def test_fetch_wraps_network_errors() -> None:
    def failing(request: Any, timeout: float) -> FakeResponse:
        raise TimeoutError("timed out")

    with pytest.raises(KevFeedError, match="failed to fetch"):
        fetch_kev_feed("https://x.test/", opener=failing)


def test_refresh_writes_validated_file(tmp_path: Path) -> None:
    out = tmp_path / "kev.json"
    n = refresh_kev(
        str(out), url="https://x.test/", opener=opener_returning(json.dumps(FEED).encode())
    )
    assert n == 2
    assert load_kev(str(out)) == {"CVE-2021-44228", "CVE-2024-3400"}
    assert list(tmp_path.iterdir()) == [out]  # no temp files left behind


def test_refresh_keeps_old_file_on_invalid_feed(tmp_path: Path) -> None:
    out = tmp_path / "kev.json"
    out.write_text(json.dumps(FEED), encoding="utf-8")
    with pytest.raises(KevFeedError):
        refresh_kev(
            str(out), url="https://x.test/", opener=opener_returning(b'{"vulnerabilities": 1}')
        )
    assert len(load_kev(str(out))) == 2


def test_refresh_min_entries(tmp_path: Path) -> None:
    with pytest.raises(KevFeedError, match="at least"):
        refresh_kev(
            str(tmp_path / "kev.json"),
            url="https://x.test/",
            min_entries=1000,
            opener=opener_returning(json.dumps(FEED).encode()),
        )


def test_write_atomic_cleans_up_on_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken_replace(self: Path, target: Path) -> Path:
        raise OSError("disk full")

    monkeypatch.setattr(Path, "replace", broken_replace)
    with pytest.raises(OSError, match="disk full"):
        write_atomic(str(tmp_path / "kev.json"), b"{}")
    assert list(tmp_path.iterdir()) == []
