from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any

import pytest

from kevgate import cli
from kevgate.csv_import import CsvImportError
from kevgate.db import FindingRepository
from kevgate.trivy_import import load_epss, parse_trivy, pick_cvss


def vuln(vid: str, cvss: Any = None, **kw: Any) -> dict[str, Any]:
    v: dict[str, Any] = {"VulnerabilityID": vid, "PkgName": "libc6"}
    if cvss is not None:
        v["CVSS"] = cvss
    v.update(kw)
    return v


def report(*vulns: dict[str, Any], name: str = "mysql:5.6") -> str:
    return json.dumps(
        {"ArtifactName": name, "Results": [{"Target": "os", "Vulnerabilities": list(vulns)}]}
    )


def test_pick_cvss_preference() -> None:
    assert pick_cvss({"nvd": {"V3Score": 5.5, "V2Score": 9.0}, "redhat": {"V3Score": 8.0}}) == 5.5
    assert pick_cvss({"redhat": {"V3Score": 4.7}, "ghsa": {"V3Score": 6.1}}) == 6.1
    assert pick_cvss({"nvd": {"V2Score": 4.3}, "redhat": {"V2Score": 9.0}}) == 4.3
    assert pick_cvss({"redhat": {"V2Score": 6.2}, "x": {"V2Score": 7.2}}) == 7.2
    assert pick_cvss({"nvd": {"V2Score": 4.3}, "x": {"V3Score": 3.0}}) == 3.0
    assert pick_cvss({"nvd": {"V3Score": True, "V2Score": float("nan")}}) is None
    assert pick_cvss({"nvd": "bad"}) is None
    assert pick_cvss(None) is None


def test_parse_trivy_basic() -> None:
    text = report(
        vuln("CVE-2021-44228", {"nvd": {"V3Score": 10.0}}),
        vuln("CVE-2021-44228", {"nvd": {"V3Score": 9.0}}, PkgName="other"),  # merged, max kept
        vuln("cve-2019-0001", {"nvd": {"V2Score": 7.2}}),
        vuln("GHSA-xxxx-yyyy-zzzz", {"nvd": {"V3Score": 5.0}}),  # not a CVE
        vuln("CVE-2020-0001"),  # no CVSS
        vuln("CVE-2020-0002", {"nvd": {}}),  # no CVSS
    )
    res = parse_trivy(text, default_acr=7, epss={"CVE-2021-44228": 0.97})
    got = {f.cve: f for f in res.findings}
    assert set(got) == {"CVE-2021-44228", "CVE-2019-0001"}
    assert got["CVE-2021-44228"].cvss == 10.0 and got["CVE-2021-44228"].epss == 0.97
    assert got["CVE-2019-0001"].epss == 0.0 and got["CVE-2019-0001"].acr == 7
    assert all(f.asset == "mysql:5.6" and f.days_open == 0 for f in res.findings)
    assert (res.skipped_non_cve, res.skipped_no_cvss, res.epss_missing) == (1, 2, 1)


def test_parse_trivy_merge_keeps_highest_regardless_of_order() -> None:
    low_first = report(
        vuln("CVE-2021-1111", {"nvd": {"V3Score": 3.0}}),
        vuln("CVE-2021-1111", {"nvd": {"V3Score": 8.0}}),
    )
    assert parse_trivy(low_first).findings[0].cvss == 8.0


def test_parse_trivy_empty_results() -> None:
    assert parse_trivy(json.dumps({"ArtifactName": "x"})).findings == []
    assert (
        parse_trivy(json.dumps({"ArtifactName": "x", "Results": [{"Target": "t"}]})).findings == []
    )


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        "[]",
        json.dumps({"Results": []}),
        json.dumps({"ArtifactName": "", "Results": []}),
        json.dumps({"ArtifactName": "x", "Results": "no"}),
        # score above 10 fails Finding validation
        report(vuln("CVE-2021-1111", {"nvd": {"V3Score": 11.0}})),
    ],
)
def test_parse_trivy_rejects(text: str) -> None:
    with pytest.raises(CsvImportError):
        parse_trivy(text)


def test_parse_trivy_skips_non_dict_entries() -> None:
    doc = {"ArtifactName": "x", "Results": ["junk", {"Vulnerabilities": ["junk"]}]}
    assert parse_trivy(json.dumps(doc)).findings == []


def test_parse_trivy_bad_acr() -> None:
    with pytest.raises(ValueError, match="default_acr"):
        parse_trivy(report(), default_acr=9)


def test_load_epss_plain_and_gzip() -> None:
    raw = (
        b"#model_version:v2026.06.15,score_date:2026-11-14T12:00:22Z\n"
        b"cve,epss,percentile\nCVE-2021-44228,0.97,0.99\n\ncve-2020-1,0.5,0.9\n"
    )
    assert load_epss(raw) == {"CVE-2021-44228": 0.97, "CVE-2020-1": 0.5}
    assert load_epss(gzip.compress(raw)) == load_epss(raw)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"#only,comment\n",
        b"a,b\nx,1\n",
        b"cve,epss\nCVE-2021-1111,abc\n",
        b"cve,epss\nCVE-2021-1111,1.5\n",
        b"cve,epss\nCVE-2021-1111,nan\n",
    ],
)
def test_load_epss_rejects(raw: bytes) -> None:
    with pytest.raises(CsvImportError):
        load_epss(raw)


def test_cli_import_trivy(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rep = tmp_path / "r.json"
    rep.write_text(
        report(vuln("CVE-2021-44228", {"nvd": {"V3Score": 10.0}}), vuln("GHSA-a-b-c")),
        encoding="utf-8",
    )
    epss = tmp_path / "epss.csv"
    epss.write_text("cve,epss,percentile\nCVE-2021-44228,0.9,0.9\n", encoding="utf-8")
    db = str(tmp_path / "k.db")
    assert (
        cli.main(
            ["import-trivy", str(rep), "--db", db, "--default-acr", "8", "--epss-file", str(epss)]
        )
        == 0
    )
    assert (
        "imported 1 finding(s); skipped 1 non-CVE and 0 without CVSS; 0 had no EPSS"
        in capsys.readouterr().out
    )
    repo = FindingRepository(db)
    (row,) = repo.list_findings()
    assert (row.acr, row.epss, row.asset) == (8, 0.9, "mysql:5.6")
    repo.close()


def test_cli_import_trivy_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = str(tmp_path / "k.db")
    assert cli.main(["import-trivy", str(tmp_path / "missing.json"), "--db", db]) == 1
    bad = tmp_path / "bad.json"
    bad.write_text("nope", encoding="utf-8")
    assert cli.main(["import-trivy", str(bad), "--db", db]) == 1
    ok = tmp_path / "ok.json"
    ok.write_text(report(vuln("CVE-2021-1111", {"nvd": {"V3Score": 11.0}})), encoding="utf-8")
    assert cli.main(["import-trivy", str(ok), "--db", db]) == 1
    assert "CVE-2021-1111" in capsys.readouterr().err
    bad_epss = tmp_path / "e.csv"
    bad_epss.write_text("x,y\n", encoding="utf-8")
    assert cli.main(["import-trivy", str(ok), "--db", db, "--epss-file", str(bad_epss)]) == 1
