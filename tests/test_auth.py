from __future__ import annotations

from pathlib import Path

import pytest

from kevgate.auth import (
    ANONYMOUS,
    KEY_PREFIX,
    KeyFileError,
    KeyStore,
    Principal,
    Scope,
    format_key_line,
    generate_key,
    hash_key,
    parse_bearer,
)


def test_generated_keys_are_unique_and_high_entropy() -> None:
    keys = {generate_key() for _ in range(100)}
    assert len(keys) == 100
    assert all(k.startswith(KEY_PREFIX) and len(k) >= 40 for k in keys)


def test_key_line_round_trip() -> None:
    key = generate_key()
    line = format_key_line("ci", [Scope.QUEUE_READ, Scope.FINDINGS_WRITE], key)
    assert line == f"ci:findings:write,queue:read:{hash_key(key)}"
    assert key not in line
    store = KeyStore.parse([line])
    principal = store.authenticate(key)
    assert principal == Principal("ci", frozenset({Scope.QUEUE_READ, Scope.FINDINGS_WRITE}))
    assert store.authenticate(key + "x") is None


def test_hash_is_case_insensitive_in_file() -> None:
    key = generate_key()
    store = KeyStore.parse([f"k:admin:{hash_key(key).upper()}"])
    assert store.authenticate(key) is not None


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ("only-two:admin", "expected"),
        ("bad id!:admin:" + "0" * 64, "invalid key_id"),
        ("k:admin:abc", "64 hex"),
        ("k:superuser:" + "0" * 64, "unknown scope"),
        ("k::" + "0" * 64, "unknown scope"),
    ],
)
def test_key_file_rejects_malformed_lines(line: str, message: str) -> None:
    with pytest.raises(KeyFileError, match=message):
        KeyStore.parse([line])


def test_duplicate_key_ids_rejected() -> None:
    line = "k:admin:" + "0" * 64
    with pytest.raises(KeyFileError, match="duplicate"):
        KeyStore.parse([line, line])


def test_unreadable_key_file(tmp_path: Path) -> None:
    with pytest.raises(KeyFileError, match="cannot read"):
        KeyStore.from_file(str(tmp_path / "nope"))


def test_format_key_line_validation() -> None:
    with pytest.raises(ValueError):
        format_key_line("has:colon", [Scope.ADMIN], "k")
    with pytest.raises(ValueError):
        format_key_line("ok", [], "k")


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (None, None),
        ("", None),
        ("Bearer abc", "abc"),
        ("bearer abc", "abc"),
        ("Bearer   abc  ", "abc"),
        ("Basic abc", None),
        ("Bearer", None),
        ("Bearer " + "a" * 257, None),
    ],
)
def test_parse_bearer(header: str | None, expected: str | None) -> None:
    assert parse_bearer(header) == expected


def test_scopes() -> None:
    reader = Principal("r", frozenset({Scope.QUEUE_READ}))
    assert reader.allows(Scope.QUEUE_READ)
    assert not reader.allows(Scope.FINDINGS_WRITE)
    assert not reader.allows(Scope.ADMIN)
    admin = Principal("a", frozenset({Scope.ADMIN}))
    assert all(admin.allows(s) for s in Scope)
    assert all(ANONYMOUS.allows(s) for s in Scope)


def test_authenticate_checks_every_key() -> None:
    """The match loop must not stop at the first hit (constant work per request)."""
    keys = [generate_key() for _ in range(3)]
    store = KeyStore.parse([format_key_line(f"k{i}", [Scope.ADMIN], k) for i, k in enumerate(keys)])
    assert len(store) == 3
    for i, k in enumerate(keys):
        found = store.authenticate(k)
        assert found is not None and found.key_id == f"k{i}"
