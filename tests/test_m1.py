"""The first API contract tests. Change the code to satisfy them, not the tests."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from kevgate.app import create_app
from kevgate.scoring import load_kev, risk_score

KEV = str(Path(__file__).resolve().parents[1] / "data" / "kev_sample.json")


def finding(cve: str = "CVE-2021-44228", **kw: object) -> dict[str, object]:
    base: dict[str, object] = {"cve": cve, "asset": "web-01", "acr": 5, "cvss": 9.0, "epss": 0.5, "days_open": 10}
    base.update(kw)
    return base


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(KEV))


# ---- scoring -------------------------------------------------------------

def test_load_kev_uppercases_and_returns_set() -> None:
    kev = load_kev(KEV)
    assert "CVE-2021-44228" in kev
    assert len(kev) == 5


def test_score_bounds() -> None:
    assert risk_score(10.0, 1.0, 8, True) == 100.0
    assert risk_score(0.0, 0.0, 1, False) >= 0.0


def test_kev_outranks_non_kev_on_same_asset() -> None:
    assert risk_score(5.0, 0.1, 4, True) > risk_score(10.0, 1.0, 4, False)


def test_score_rounded_to_one_decimal() -> None:
    s = risk_score(7.3, 0.33, 3, False)
    assert s == round(s, 1)


# ---- API -----------------------------------------------------------------

def test_healthz(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_post_findings_accepted(client: TestClient) -> None:
    r = client.post("/findings", json=[finding(), finding("CVE-2023-99999")])
    assert r.status_code == 201 and r.json() == {"accepted": 2}


@pytest.mark.parametrize("bad", [
    {"cve": "not-a-cve"}, {"acr": 0}, {"acr": 9}, {"cvss": 10.5}, {"epss": -0.1},
    {"days_open": -1}, {"asset": ""},
])
def test_invalid_finding_rejected_and_nothing_stored(client: TestClient, bad: dict[str, object]) -> None:
    r = client.post("/findings", json=[finding(), finding(**bad)])
    assert r.status_code == 422
    assert client.get("/queue").json() == []


def test_cve_stored_uppercase(client: TestClient) -> None:
    client.post("/findings", json=[finding("cve-2021-44228")])
    assert client.get("/queue").json()[0]["cve"] == "CVE-2021-44228"


def test_queue_ranks_kev_first_and_marks_kev(client: TestClient) -> None:
    client.post("/findings", json=[
        finding("CVE-2023-99999", cvss=9.8, epss=0.9),
        finding("CVE-2021-34527", cvss=6.0, epss=0.2),
    ])
    q = client.get("/queue").json()
    assert [x["cve"] for x in q] == ["CVE-2021-34527", "CVE-2023-99999"]
    assert q[0]["kev"] is True and q[1]["kev"] is False
    assert q[0]["risk"] >= q[1]["risk"]


def test_queue_tie_break_epss_then_cvss(client: TestClient) -> None:
    client.post("/findings", json=[
        finding("CVE-2023-00001", cvss=5.0, epss=0.5, acr=3),
        finding("CVE-2023-00002", cvss=5.0, epss=0.5, acr=3),
    ])
    q = client.get("/queue").json()
    assert len(q) == 2 and q[0]["risk"] == q[1]["risk"]


def test_queue_limit(client: TestClient) -> None:
    client.post("/findings", json=[finding(f"CVE-2023-{i:05d}") for i in range(15)])
    assert len(client.get("/queue").json()) == 10
    assert len(client.get("/queue?limit=3").json()) == 3
    assert client.get("/queue?limit=0").status_code == 422
    assert client.get("/queue?limit=101").status_code == 422


def test_apps_do_not_share_state() -> None:
    a, b = TestClient(create_app(KEV)), TestClient(create_app(KEV))
    a.post("/findings", json=[finding()])
    assert b.get("/queue").json() == []
