from __future__ import annotations

import logging
from pathlib import Path

import pytest
from conftest import FIXTURES, KEV_PATH, AppFactory, Keys, app_state, bearer, finding
from fastapi.testclient import TestClient

from kevgate.app import create_app
from kevgate.config import ConfigError, Settings

# ---- auth matrix -----------------------------------------------------------

ROUTES = [
    ("POST", "/findings", "findings:write"),
    ("POST", "/findings/import", "findings:write"),
    ("GET", "/queue", "queue:read"),
    ("GET", "/findings/CVE-2021-44228", "queue:read"),
    ("GET", "/stats", "queue:read"),
    ("DELETE", "/findings/CVE-2021-44228?asset=web-01", "admin"),
]


def _call(c: TestClient, method: str, path: str, headers: dict[str, str]) -> int:
    if path == "/findings/import":
        headers = {**headers, "Content-Type": "text/csv"}
        return c.request(
            method, path, content=b"Host,CVE,CVSS\nh,CVE-2021-44228,9\n", headers=headers
        ).status_code
    if method == "POST":
        return c.request(method, path, json=[finding()], headers=headers).status_code
    return c.request(method, path, headers=headers).status_code


@pytest.mark.parametrize(("method", "path", "_scope"), ROUTES)
def test_no_key_is_401_with_challenge(
    client: TestClient, method: str, path: str, _scope: str
) -> None:
    r = client.request(method, path)
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"].startswith("Bearer")


@pytest.mark.parametrize(("method", "path", "_scope"), ROUTES)
@pytest.mark.parametrize(
    "header",
    [
        "Bearer kvg_not-a-real-key",
        "Basic dXNlcjpwYXNz",
        "Bearer",
        "bearer  ",
        "Bearer " + "x" * 300,
    ],
)
def test_bad_key_is_401(
    client: TestClient, method: str, path: str, _scope: str, header: str
) -> None:
    assert _call(client, method, path, {"Authorization": header}) == 401


@pytest.mark.parametrize(("method", "path", "scope"), ROUTES)
def test_scope_matrix(client: TestClient, keys: Keys, method: str, path: str, scope: str) -> None:
    client.post("/findings", json=[finding()], headers=bearer(keys.writer))
    by_scope = {"findings:write": keys.writer, "queue:read": keys.reader}
    for key_scope, key in by_scope.items():
        status = _call(client, method, path, bearer(key))
        if key_scope == scope:
            assert status in (200, 201, 204), (key_scope, status)
        else:
            assert status == 403, (key_scope, status)


def test_admin_scope_implies_everything(client: TestClient, keys: Keys) -> None:
    h = bearer(keys.admin)
    assert client.post("/findings", json=[finding()], headers=h).status_code == 201
    assert client.get("/queue", headers=h).status_code == 200
    assert client.delete("/findings/CVE-2021-44228?asset=web-01", headers=h).status_code == 204


def test_scheme_is_case_insensitive(client: TestClient, keys: Keys) -> None:
    r = client.get("/queue", headers={"Authorization": f"bearer {keys.reader}"})
    assert r.status_code == 200


def test_ops_endpoints_need_no_auth(client: TestClient) -> None:
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200
    assert client.get("/metrics").status_code == 200


def test_auth_failures_counted(client: TestClient, keys: Keys) -> None:
    client.get("/queue")
    client.get("/queue", headers=bearer("kvg_wrong"))
    client.post("/findings", json=[finding()], headers=bearer(keys.reader))
    text = client.get("/metrics").text
    assert 'kevgate_auth_failures_total{reason="missing"} 1.0' in text
    assert 'kevgate_auth_failures_total{reason="invalid"} 1.0' in text
    assert 'kevgate_auth_failures_total{reason="forbidden"} 1.0' in text


def test_prod_without_key_file_refuses_to_start() -> None:
    with pytest.raises(ConfigError):
        create_app(settings=Settings(env="prod", db_path=":memory:", kev_path=KEV_PATH))


def test_prod_with_empty_key_file_refuses_to_start(tmp_path: Path) -> None:
    empty = tmp_path / "keys"
    empty.write_text("# nothing\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        create_app(
            settings=Settings(
                env="prod", db_path=":memory:", kev_path=KEV_PATH, api_keys_file=str(empty)
            )
        )


def test_dev_without_keys_logs_loud_warning(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        create_app(KEV_PATH)
    assert any("AUTHENTICATION DISABLED" in r.getMessage() for r in caplog.records)


# ---- rate limiting -----------------------------------------------------------


def test_rate_limit_returns_429_with_retry_after(make_client: AppFactory, keys: Keys) -> None:
    c = make_client(rate_limit_per_min=3)
    h = bearer(keys.reader)
    assert [c.get("/queue", headers=h).status_code for _ in range(3)] == [200, 200, 200]
    r = c.get("/queue", headers=h)
    assert r.status_code == 429
    assert int(r.headers["Retry-After"]) >= 1
    # Buckets are per key: another key is unaffected.
    assert c.get("/queue", headers=bearer(keys.both)).status_code == 200
    assert "kevgate_rate_limited_total 1.0" in c.get("/metrics").text


def test_rate_limit_applies_when_auth_disabled(make_client: AppFactory) -> None:
    c = make_client(auth=False, rate_limit_per_min=1)
    assert c.get("/queue").status_code == 200
    assert c.get("/queue").status_code == 429


def test_ops_endpoints_not_rate_limited(make_client: AppFactory) -> None:
    c = make_client(rate_limit_per_min=1)
    assert all(c.get("/healthz").status_code == 200 for _ in range(5))


# ---- input hardening -----------------------------------------------------------


def test_body_over_limit_by_content_length_is_413(open_client: TestClient) -> None:
    r = open_client.post(
        "/findings",
        content=b"[" + b" " * (1024 * 1024) + b"]",
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 413
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_chunked_body_over_limit_is_413(open_client: TestClient) -> None:
    chunks = iter([b"[", b" " * 600_000, b" " * 600_000, b"]"])
    r = open_client.post("/findings", content=chunks, headers={"Content-Type": "application/json"})
    assert r.status_code == 413
    assert open_client.get("/queue").json() == []


def test_chunked_csv_over_limit_is_413(open_client: TestClient) -> None:
    chunks = iter([b"Host,CVE,CVSS\n", b"x" * 1_100_000])
    r = open_client.post("/findings/import", content=chunks, headers={"Content-Type": "text/csv"})
    assert r.status_code == 413


def test_invalid_content_length_is_400(open_client: TestClient) -> None:
    r = open_client.post("/findings", content=b"[]", headers={"Content-Length": "abc"})
    assert r.status_code == 400


def test_max_findings_per_request(open_client: TestClient) -> None:
    ok = [finding(f"CVE-2023-{i:05d}") for i in range(1000)]
    assert open_client.post("/findings", json=ok).status_code == 201
    too_many = [*ok, finding("CVE-2023-99999")]
    assert open_client.post("/findings", json=too_many).status_code == 422


@pytest.mark.parametrize(
    "bad",
    [
        {"extra": "field"},
        {"acr": "5"},
        {"acr": True},
        {"cvss": "9.0"},
        {"days_open": 1.5},
        {"asset": "a" * 129},
        {"asset": "web\n01"},
        {"cve": "CVE-2021-1"},
        {"cve": "CVE-2021-" + "1" * 30},
    ],
)
def test_strict_validation(open_client: TestClient, bad: dict[str, object]) -> None:
    assert open_client.post("/findings", json=[finding(**bad)]).status_code == 422


def test_nan_rejected(open_client: TestClient) -> None:
    body = b'[{"cve":"CVE-2021-44228","asset":"a","acr":1,"cvss":NaN,"epss":0.1,"days_open":1}]'
    r = open_client.post("/findings", content=body, headers={"Content-Type": "application/json"})
    assert r.status_code == 422
    assert r.json()["detail"][0]["loc"] == ["body", 0, "cvss"]


def test_validation_errors_do_not_echo_input(open_client: TestClient) -> None:
    r = open_client.post("/findings", json=[finding(asset="x" * 129)])
    assert r.status_code == 422
    assert "x" * 129 not in r.text
    assert set(r.json()["detail"][0]) == {"loc", "msg", "type"}


def test_body_must_be_a_list(open_client: TestClient) -> None:
    assert open_client.post("/findings", json=finding()).status_code == 422


# ---- findings and queue ---------------------------------------------------------


def test_upsert_is_idempotent_on_cve_asset(open_client: TestClient) -> None:
    open_client.post("/findings", json=[finding(cvss=5.0)])
    open_client.post("/findings", json=[finding(cvss=7.5), finding(asset="db-01")])
    q = open_client.get("/queue").json()
    assert len(q) == 2
    web = next(x for x in q if x["asset"] == "web-01")
    assert web["cvss"] == 7.5


def test_queue_filters(open_client: TestClient) -> None:
    open_client.post(
        "/findings",
        json=[
            finding("CVE-2021-44228", asset="web-01"),
            finding("CVE-2023-00001", asset="web-01"),
            finding("CVE-2024-3400", asset="fw-01"),
        ],
    )
    kev = open_client.get("/queue?kev_only=true").json()
    assert {x["cve"] for x in kev} == {"CVE-2021-44228", "CVE-2024-3400"}
    fw = open_client.get("/queue?asset=fw-01").json()
    assert [x["cve"] for x in fw] == ["CVE-2024-3400"]
    both = open_client.get("/queue?asset=web-01&kev_only=true").json()
    assert [x["cve"] for x in both] == ["CVE-2021-44228"]
    assert open_client.get("/queue?asset=").status_code == 422


def test_get_finding_by_cve(open_client: TestClient) -> None:
    open_client.post(
        "/findings", json=[finding(asset="b"), finding(asset="a"), finding("CVE-2023-00001")]
    )
    r = open_client.get("/findings/cve-2021-44228")
    assert r.status_code == 200
    body = r.json()
    assert [x["asset"] for x in body] == ["a", "b"]
    assert all(x["kev"] is True and x["risk"] > 0 for x in body)


def test_get_finding_404_and_422(open_client: TestClient) -> None:
    assert open_client.get("/findings/CVE-2020-0001").status_code == 404
    assert open_client.get("/findings/not-a-cve").status_code == 422


def test_delete_finding(open_client: TestClient) -> None:
    open_client.post("/findings", json=[finding(), finding(asset="db-01")])
    r = open_client.delete("/findings/CVE-2021-44228?asset=web-01")
    assert r.status_code == 204
    assert [x["asset"] for x in open_client.get("/queue").json()] == ["db-01"]
    assert open_client.delete("/findings/CVE-2021-44228?asset=web-01").status_code == 404
    assert open_client.delete("/findings/CVE-2021-44228").status_code == 422


def test_stats(open_client: TestClient) -> None:
    empty = open_client.get("/stats").json()
    assert empty["total"] == 0 and empty["kev"]["mean_cvss"] is None and empty["top_assets"] == []
    open_client.post(
        "/findings",
        json=[
            finding("CVE-2021-44228", asset="web-01", cvss=10.0, epss=0.9, days_open=30),
            finding("CVE-2024-3400", asset="fw-01", cvss=10.0, epss=0.7, days_open=10),
            finding("CVE-2023-00001", asset="web-01", cvss=4.0, epss=0.1, days_open=100),
        ],
    )
    s = open_client.get("/stats").json()
    assert s["total"] == 3
    assert s["kev"] == {"count": 2, "mean_cvss": 10.0, "mean_epss": 0.8, "mean_days_open": 20.0}
    assert s["non_kev"] == {"count": 1, "mean_cvss": 4.0, "mean_epss": 0.1, "mean_days_open": 100.0}
    assert s["top_assets"][0]["asset"] == "web-01"
    assert s["top_assets"][0]["findings"] == 2 and s["top_assets"][0]["kev_findings"] == 1


# ---- CSV import -----------------------------------------------------------------


def test_csv_import_tenable_export(open_client: TestClient) -> None:
    body = (FIXTURES / "tenable_export.csv").read_bytes()
    r = open_client.post(
        "/findings/import", content=body, headers={"Content-Type": "text/csv; charset=utf-8"}
    )
    assert r.status_code == 201
    assert r.json() == {"accepted": 5, "skipped": 2}
    q = open_client.get("/queue?limit=100").json()
    assert {x["cve"] for x in q} == {
        "CVE-2021-44228",
        "CVE-2024-3400",
        "CVE-2021-34527",
        "CVE-2021-1675",
        "CVE-2023-27997",
    }
    assert 'kevgate_findings_ingested_total{source="csv"} 5.0' in open_client.get("/metrics").text


def test_csv_import_default_acr(open_client: TestClient) -> None:
    body = b"Host,CVE,CVSS\nh,CVE-2021-44228,9\n"
    r = open_client.post(
        "/findings/import?default_acr=8", content=body, headers={"Content-Type": "text/csv"}
    )
    assert r.status_code == 201
    assert open_client.get("/queue").json()[0]["acr"] == 8
    bad = open_client.post(
        "/findings/import?default_acr=9", content=body, headers={"Content-Type": "text/csv"}
    )
    assert bad.status_code == 422


def test_csv_import_rejects_wrong_content_type(open_client: TestClient) -> None:
    r = open_client.post("/findings/import", json=[finding()])
    assert r.status_code == 415


def test_csv_import_rejects_non_utf8(open_client: TestClient) -> None:
    r = open_client.post(
        "/findings/import", content=b"\xff\xfe\x00bad", headers={"Content-Type": "text/csv"}
    )
    assert r.status_code == 422


def test_csv_import_row_errors_store_nothing(open_client: TestClient) -> None:
    body = b"Host,CVE,CVSS\nh,CVE-2021-44228,9\nh,CVE-2021-34527,eleven\n"
    r = open_client.post("/findings/import", content=body, headers={"Content-Type": "text/csv"})
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert "line 3" in detail["rows"][0]
    assert open_client.get("/queue").json() == []


def test_csv_import_over_finding_limit(open_client: TestClient) -> None:
    rows = "".join(f"h,CVE-2023-{i:05d},5\n" for i in range(1001))
    body = ("Host,CVE,CVSS\n" + rows).encode()
    r = open_client.post("/findings/import", content=body, headers={"Content-Type": "text/csv"})
    assert r.status_code == 422
    assert "limit is 1000" in r.json()["detail"]


# ---- ops endpoints -----------------------------------------------------------------


def test_readyz_ok(open_client: TestClient) -> None:
    r = open_client.get("/readyz")
    assert r.status_code == 200
    assert r.json() == {"status": "ready", "checks": {"db": "ok", "storage": "ok", "kev": "ok"}}


def test_readyz_fails_when_db_unreachable(open_client: TestClient) -> None:
    app_state(open_client).repo.close()
    r = open_client.get("/readyz")
    assert r.status_code == 503
    assert r.json()["checks"]["db"] == "fail"
    assert open_client.get("/healthz").status_code == 200


def test_readyz_fails_when_kev_missing(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.ERROR):
        c = TestClient(create_app(str(tmp_path / "missing.json")))
    assert any("KEV catalog failed to load" in r.getMessage() for r in caplog.records)
    r = c.get("/readyz")
    assert r.status_code == 503
    assert r.json()["checks"] == {"db": "ok", "storage": "ok", "kev": "fail"}


def test_readyz_fails_when_kev_invalid(tmp_path: Path) -> None:
    bad = tmp_path / "kev.json"
    bad.write_text('{"vulnerabilities": [{"cveID": "nope"}]}', encoding="utf-8")
    assert TestClient(create_app(str(bad))).get("/readyz").status_code == 503


def test_metrics_prometheus_format(open_client: TestClient) -> None:
    open_client.post("/findings", json=[finding()])
    open_client.get("/findings/CVE-2021-44228")
    open_client.get("/nope")
    r = open_client.get("/metrics")
    assert r.headers["content-type"].startswith("text/plain")
    text = r.text
    assert "kevgate_kev_entries 5.0" in text
    assert 'kevgate_findings_ingested_total{source="json"} 1.0' in text
    # Route label is the template, not the concrete path (bounded cardinality).
    assert 'route="/findings/{cve}",status="200"' in text
    assert 'route="unmatched",status="404"' in text
    assert "kevgate_http_request_duration_seconds_bucket" in text


# ---- headers, request id, logging, docs ------------------------------------------------


def test_security_headers_on_api_responses(open_client: TestClient) -> None:
    r = open_client.get("/queue")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Cache-Control"] == "no-store"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]


def test_request_id_generated_and_propagated(open_client: TestClient) -> None:
    generated = open_client.get("/healthz").headers["X-Request-ID"]
    assert len(generated) == 32
    r = open_client.get("/healthz", headers={"X-Request-ID": "abc-123"})
    assert r.headers["X-Request-ID"] == "abc-123"
    hostile = open_client.get("/healthz", headers={"X-Request-ID": 'x" injected'})
    assert hostile.headers["X-Request-ID"] != 'x" injected'


def test_access_log_has_fields_and_no_secrets(
    client: TestClient, keys: Keys, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="kevgate.access"):
        client.post(
            "/findings", json=[finding(asset="secret-asset-name")], headers=bearer(keys.writer)
        )
    records = [r for r in caplog.records if r.name == "kevgate.access"]
    assert len(records) == 1
    fields = records[0].fields  # type: ignore[attr-defined]
    assert fields["method"] == "POST" and fields["path"] == "/findings"
    assert fields["status"] == 201 and fields["key_id"] == "writer"
    assert isinstance(fields["latency_ms"], float) and fields["request_id"]
    dumped = repr(fields)
    assert keys.writer not in dumped and "secret-asset-name" not in dumped


def test_docs_enabled_in_dev_without_strict_csp(open_client: TestClient) -> None:
    r = open_client.get("/docs")
    assert r.status_code == 200
    assert "Content-Security-Policy" not in r.headers
    assert open_client.get("/openapi.json").status_code == 200


def test_docs_disabled_in_prod(keys: Keys) -> None:
    settings = Settings(env="prod", db_path=":memory:", kev_path=KEV_PATH, api_keys_file=keys.path)
    c = TestClient(create_app(settings=settings))
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert c.get(path).status_code == 404


def test_unhandled_error_is_500_and_logged(
    open_client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    state = app_state(open_client)

    def boom(asset: str | None = None) -> list[object]:
        raise RuntimeError("kaboom")

    state.repo.list_findings = boom  # type: ignore[method-assign]
    c = TestClient(open_client.app, raise_server_exceptions=False)
    with caplog.at_level(logging.ERROR, logger="kevgate.access"):
        r = c.get("/queue")
    assert r.status_code == 500
    assert "kaboom" not in r.text
    assert any(rec.getMessage() == "unhandled exception" for rec in caplog.records)


def test_lifespan_closes_db(open_client: TestClient) -> None:
    with open_client:
        assert open_client.get("/readyz").status_code == 200
    assert app_state(open_client).repo.ping() is False


def test_file_backed_db_persists_across_apps(tmp_path: Path) -> None:
    db = str(tmp_path / "kevgate.db")
    settings = Settings(db_path=db, kev_path=KEV_PATH)
    TestClient(create_app(settings=settings)).post("/findings", json=[finding()])
    q = TestClient(create_app(settings=settings)).get("/queue").json()
    assert [x["cve"] for x in q] == ["CVE-2021-44228"]
