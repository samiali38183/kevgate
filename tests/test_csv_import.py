from __future__ import annotations

from datetime import UTC, datetime

import pytest
from conftest import FIXTURES

from kevgate.csv_import import CsvImportError, parse_csv

NOW = datetime(2026, 11, 10, tzinfo=UTC)


def by_key(text: str, **kw: object) -> dict[tuple[str, str], dict[str, object]]:
    result = parse_csv(text, now=NOW, **kw)  # type: ignore[arg-type]
    return {(f.cve, f.asset): f.model_dump() for f in result.findings}


def test_tenable_fixture() -> None:
    result = parse_csv((FIXTURES / "tenable_export.csv").read_text(encoding="utf-8"), now=NOW)
    assert result.skipped == 2
    got = {(f.cve, f.asset): f for f in result.findings}
    assert set(got) == {
        ("CVE-2021-44228", "10.0.0.5"),
        ("CVE-2024-3400", "fw-edge-01"),
        ("CVE-2021-34527", "dc-01"),
        ("CVE-2021-1675", "dc-01"),
        ("CVE-2023-27997", "vpn-01"),
    }
    log4j = got[("CVE-2021-44228", "10.0.0.5")]
    # Two ports merged: highest epss and oldest discovery win; CVSS v3 preferred over v2.
    assert log4j.cvss == 10.0 and log4j.epss == 0.97
    assert log4j.days_open == (NOW - datetime(2021, 12, 11, tzinfo=UTC)).days
    # v3 column empty -> falls back to v2.
    assert got[("CVE-2023-27997", "vpn-01")].cvss == 9.8
    assert got[("CVE-2023-27997", "vpn-01")].days_open == 0
    # Tenable's "Apr 13, 2024 08:15:00 UTC" format.
    assert (
        got[("CVE-2024-3400", "fw-edge-01")].days_open
        == (NOW - datetime(2024, 4, 13, 8, 15, tzinfo=UTC)).days
    )
    assert all(f.acr == 4 for f in result.findings)


def test_header_aliases_case_insensitive_and_optional_columns() -> None:
    text = (
        "dns name,cves,CVSS BASE SCORE,epss score,Asset Criticality Rating,days open\n"
        "h1,cve-2021-44228,7.5,0.2,8,12\n"
    )
    got = by_key(text)
    assert got[("CVE-2021-44228", "h1")] == {
        "cve": "CVE-2021-44228",
        "asset": "h1",
        "acr": 8,
        "cvss": 7.5,
        "epss": 0.2,
        "days_open": 12,
    }


def test_asset_falls_back_across_columns() -> None:
    text = "Host,IP Address,CVE,CVSS\n,10.1.1.1,CVE-2021-44228,5\n"
    assert ("CVE-2021-44228", "10.1.1.1") in by_key(text)


def test_bom_and_crlf() -> None:
    text = "﻿Host,CVE,CVSS\r\nh,CVE-2021-44228,5\r\n".lstrip("﻿")
    assert len(by_key(text)) == 1


def test_quoted_fields_with_commas_and_newlines() -> None:
    text = 'Host,CVE,CVSS,Name\nh,CVE-2021-44228,5,"Log4j, the\nbad one"\n'
    assert len(by_key(text)) == 1


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("", "empty CSV"),
        ("Host,CVSS\nh,5\n", "missing required column"),
        ("CVE,CVSS\nCVE-2021-44228,5\n", "missing required column"),
    ],
)
def test_structural_errors(text: str, match: str) -> None:
    with pytest.raises(CsvImportError, match=match):
        parse_csv(text)


@pytest.mark.parametrize(
    ("row", "match"),
    [
        ("h,CVE-2021-44228,", "no CVSS"),
        ("h,CVE-2021-44228,high", "not a number"),
        ("h,CVE-2021-44228,11", "cvss"),
        ("h,CVE-2021-44228,nan", "finite"),
        ("h,NOT-A-CVE,5", "cve"),
        (",CVE-2021-44228,5", "asset"),
    ],
)
def test_row_errors(row: str, match: str) -> None:
    with pytest.raises(CsvImportError) as exc:
        parse_csv(f"Host,CVE,CVSS\n{row}\n")
    assert "nothing imported" in str(exc.value)
    assert match in exc.value.errors[0]
    assert exc.value.errors[0].startswith("line 2")


@pytest.mark.parametrize(
    ("header", "value", "match"),
    [
        ("ACR", "9", "acr"),
        ("ACR", "2.5", "whole number"),
        ("EPSS", "1.5", "epss"),
        ("Days Open", "-1", "days_open"),
        ("First Discovered", "last tuesday", "unrecognised date"),
    ],
)
def test_optional_column_errors(header: str, value: str, match: str) -> None:
    with pytest.raises(CsvImportError) as exc:
        parse_csv(f"Host,CVE,CVSS,{header}\nh,CVE-2021-44228,5,{value}\n")
    assert match in exc.value.errors[0]


def test_future_first_seen_clamps_to_zero() -> None:
    got = by_key("Host,CVE,CVSS,First Seen\nh,CVE-2021-44228,5,2030-01-01\n")
    assert got[("CVE-2021-44228", "h")]["days_open"] == 0


def test_error_list_is_capped() -> None:
    rows = "".join("h,CVE-2021-44228,bad\n" for _ in range(50))
    with pytest.raises(CsvImportError) as exc:
        parse_csv("Host,CVE,CVSS\n" + rows)
    assert len(exc.value.errors) == 20
    assert "50 invalid row(s)" in str(exc.value)


def test_nul_byte_rejected() -> None:
    with pytest.raises(CsvImportError):
        parse_csv("Host,CVE,CVSS\nh,CVE-2021-44228,5\x00\n")


def test_oversized_field_is_malformed() -> None:
    huge = "x" * 200_000
    with pytest.raises(CsvImportError, match="malformed CSV near line"):
        parse_csv(f'Host,CVE,CVSS\nh,CVE-2021-44228,"{huge}"\n')
    with pytest.raises(CsvImportError, match="malformed CSV"):
        parse_csv(f'"{huge}",CVE,CVSS\n')


def test_default_acr_validated() -> None:
    with pytest.raises(ValueError):
        parse_csv("Host,CVE,CVSS\n", default_acr=0)


def test_only_informational_rows() -> None:
    result = parse_csv("Host,CVE,CVSS\nh,,\nh,,\n")
    assert result.findings == [] and result.skipped == 2
