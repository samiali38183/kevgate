"""Auth-failure observability: pre-created counters, client address in logs, failure limiter."""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from conftest import AppFactory, Keys, bearer
from fastapi.testclient import TestClient
from starlette.types import Receive, Scope, Send

from kevgate.clientip import parse_networks, resolve_client_address
from kevgate.config import ConfigError, Settings
from kevgate.ratelimit import TokenBucketLimiter


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


# ---- pre-created counters (alert gap) ------------------------------------------------


def test_labelled_counters_exist_at_zero_on_startup(client: TestClient) -> None:
    text = client.get("/metrics").text
    for reason in ("missing", "invalid", "forbidden"):
        assert f'kevgate_auth_failures_total{{reason="{reason}"}} 0.0' in text
    assert "kevgate_rate_limited_total 0.0" in text
    assert "kevgate_auth_throttled_total 0.0" in text


def test_first_forbidden_event_moves_series_from_zero(client: TestClient, keys: Keys) -> None:
    client.post("/findings", json=[], headers=bearer(keys.reader))
    text = client.get("/metrics").text
    assert 'kevgate_auth_failures_total{reason="forbidden"} 1.0' in text
    assert 'kevgate_auth_failures_total{reason="invalid"} 0.0' in text


# ---- limiter primitives --------------------------------------------------------------


def test_peek_does_not_spend_tokens() -> None:
    lim = TokenBucketLimiter(2, clock=Clock())
    for _ in range(10):
        assert lim.peek("a").allowed
    assert len(lim) == 0


def test_charge_drains_then_peek_blocks_then_refills() -> None:
    clock = Clock()
    lim = TokenBucketLimiter(2, clock=clock)
    lim.charge("a")
    assert lim.peek("a").allowed
    lim.charge("a")
    blocked = lim.peek("a")
    assert not blocked.allowed
    assert blocked.retry_after == 30
    lim.charge("a")  # never below zero
    clock.now = 30.0
    assert lim.peek("a").allowed
    assert lim.peek("other").allowed


def test_charge_evicts_when_full() -> None:
    lim = TokenBucketLimiter(2, clock=Clock(), max_buckets=2)
    lim.charge("a")
    lim.charge("b")
    lim.charge("c")
    assert len(lim) <= 2


# ---- client address ------------------------------------------------------------------

TRUSTED = parse_networks(["10.0.0.0/8", "fd00::/8"])


@pytest.mark.parametrize(
    ("peer", "xff", "expected"),
    [
        ("203.0.113.9", "1.2.3.4", "203.0.113.9"),  # untrusted peer: header ignored
        ("10.0.0.5", None, "10.0.0.5"),
        ("10.0.0.5", "198.51.100.7", "198.51.100.7"),
        ("10.0.0.5", "6.6.6.6, 198.51.100.7", "198.51.100.7"),  # spoofed left entry ignored
        ("10.0.0.5", "198.51.100.7, 10.0.0.9", "198.51.100.7"),  # trusted hop skipped
        ("10.0.0.5", "10.0.0.8, 10.0.0.9", "10.0.0.5"),  # only proxies listed
        ("10.0.0.5", "not-an-ip", "10.0.0.5"),
        ("fd00::1", "2001:db8::1", "2001:db8::1"),
        ("not-an-ip", "1.2.3.4", "not-an-ip"),
        (None, "1.2.3.4", "unknown"),
    ],
)
def test_resolve_client_address(peer: str | None, xff: str | None, expected: str) -> None:
    assert resolve_client_address(peer, xff, TRUSTED) == expected


def test_forwarded_for_ignored_without_trusted_proxies() -> None:
    assert resolve_client_address("10.0.0.5", "1.2.3.4", ()) == "10.0.0.5"


def test_ipv4_peer_not_matched_against_ipv6_network() -> None:
    nets = parse_networks(["fd00::/8"])
    assert resolve_client_address("10.0.0.5", "1.2.3.4", nets) == "10.0.0.5"


# ---- config --------------------------------------------------------------------------


def test_config_defaults_and_parsing() -> None:
    s = Settings.from_env({})
    assert s.auth_fail_limit_per_min == 20
    assert s.trusted_proxies == ()
    s = Settings.from_env(
        {"KEVGATE_AUTH_FAIL_LIMIT_PER_MIN": "5", "KEVGATE_TRUSTED_PROXIES": "10.0.0.0/8, 192.0.2.1"}
    )
    assert s.auth_fail_limit_per_min == 5
    assert s.trusted_proxies == ("10.0.0.0/8", "192.0.2.1")


@pytest.mark.parametrize(
    "env",
    [
        {"KEVGATE_AUTH_FAIL_LIMIT_PER_MIN": "x"},
        {"KEVGATE_AUTH_FAIL_LIMIT_PER_MIN": "0"},
        {"KEVGATE_TRUSTED_PROXIES": "10.0.0.0/8,banana"},
    ],
)
def test_config_rejects_bad_values(env: dict[str, str]) -> None:
    with pytest.raises(ConfigError):
        Settings.from_env(env)


# ---- API behaviour -------------------------------------------------------------------


def _auth_records(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    return [
        r.fields  # type: ignore[attr-defined]
        for r in caplog.records
        if r.name == "kevgate.auth"
    ]


def test_failures_log_client_address_and_never_the_key(
    client: TestClient, keys: Keys, caplog: pytest.LogCaptureFixture
) -> None:
    bad = "kvg_" + "x" * 43
    with caplog.at_level(logging.WARNING, logger="kevgate.auth"):
        assert client.get("/queue").status_code == 401
        assert client.get("/queue", headers=bearer(bad)).status_code == 401
        assert client.post("/findings", json=[], headers=bearer(keys.reader)).status_code == 403
    recs = _auth_records(caplog)
    assert [(r["status"], r["reason"]) for r in recs] == [
        (401, "missing"),
        (401, "invalid"),
        (403, "forbidden"),
    ]
    assert all(r["client_ip"] == "testclient" for r in recs)
    assert recs[2]["key_id"] == "reader"
    assert recs[0]["key_id"] is None
    blob = json.dumps(recs) + " ".join(r.getMessage() for r in caplog.records)
    assert bad not in blob
    assert keys.reader not in blob


def test_repeated_bad_keys_get_throttled_before_auth(
    make_client: AppFactory, keys: Keys, caplog: pytest.LogCaptureFixture
) -> None:
    c = make_client(auth_fail_limit_per_min=3)
    bad = bearer("kvg_" + "y" * 43)
    codes = [c.get("/queue", headers=bad).status_code for _ in range(5)]
    assert codes == [401, 401, 401, 429, 429]
    # Throttle comes first: even a valid key from this source is refused until it refills.
    with caplog.at_level(logging.WARNING, logger="kevgate.auth"):
        r = c.get("/queue", headers=bearer(keys.admin))
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) >= 1
    assert _auth_records(caplog)[-1]["reason"] == "throttled"
    text = c.get("/metrics").text
    assert "kevgate_auth_throttled_total 3.0" in text
    assert 'kevgate_auth_failures_total{reason="invalid"} 3.0' in text


def test_valid_requests_never_consume_failure_budget(make_client: AppFactory, keys: Keys) -> None:
    c = make_client(auth_fail_limit_per_min=1)
    for _ in range(10):
        assert c.get("/queue", headers=bearer(keys.reader)).status_code == 200


def test_forbidden_does_not_consume_failure_budget(make_client: AppFactory, keys: Keys) -> None:
    c = make_client(auth_fail_limit_per_min=1)
    for _ in range(5):
        assert c.post("/findings", json=[], headers=bearer(keys.reader)).status_code == 403


def test_forwarded_for_ignored_when_peer_not_trusted(make_client: AppFactory) -> None:
    # The TestClient peer is the literal "testclient", never inside a trusted network.
    c = make_client(auth_fail_limit_per_min=1, trusted_proxies=("10.0.0.0/8",))
    assert c.get("/queue", headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 401
    assert c.get("/queue", headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 429


def test_trusted_proxy_header_separates_sources(make_client: AppFactory) -> None:
    inner = make_client(auth_fail_limit_per_min=1, trusted_proxies=("10.0.0.0/8",)).app

    async def behind_proxy(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            scope["client"] = ("10.1.1.1", 5000)
        await inner(scope, receive, send)

    c = TestClient(behind_proxy)
    assert c.get("/queue", headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 401
    assert c.get("/queue", headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 401
    assert c.get("/queue", headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 429
