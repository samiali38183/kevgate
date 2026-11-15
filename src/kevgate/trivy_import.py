"""Parse a Trivy JSON report (``trivy image --format json``) and FIRST EPSS scores.

Trivy reports carry no asset criticality, no EPSS and no discovery date, so:

* the asset is the scanned artifact name (for example ``mysql:5.6``); every result target in the
  report (OS packages, language packages) belongs to that one asset
* ``acr`` is supplied by the caller (``default_acr``); the scanner cannot know it
* EPSS comes from an optional ``{cve: score}`` mapping (see :func:`load_epss`); a CVE missing from
  it scores 0.0 and is counted in ``epss_missing``
* ``days_open`` is 0, because a scan does not say when the finding was first seen
* CVSS is the NVD v3 base score if present, else the highest v3 score from any other source,
  else the NVD v2 score, else the highest v2 score from any source. Findings with no CVSS at all
  and findings whose ID is not a CVE (GHSA, distribution-only IDs) are skipped and counted.
* the same CVE reported for several packages is merged, keeping the highest CVSS
"""

from __future__ import annotations

import gzip
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from kevgate.csv_import import CsvImportError
from kevgate.models import CVE_REGEX, Finding

_CVE = re.compile(CVE_REGEX)


@dataclass
class TrivyResult:
    findings: list[Finding] = field(default_factory=list)
    skipped_non_cve: int = 0
    skipped_no_cvss: int = 0
    epss_missing: int = 0


def _scores(cvss: object, key: str) -> list[tuple[str, float]]:
    out: list[tuple[str, float]] = []
    if not isinstance(cvss, dict):
        return out
    for source, body in cvss.items():
        value = body.get(key) if isinstance(body, dict) else None
        if isinstance(value, int | float) and not isinstance(value, bool) and math.isfinite(value):
            out.append((str(source), float(value)))
    return out


def pick_cvss(cvss: object) -> float | None:
    """Return the CVSS base score kevgate uses for one Trivy ``CVSS`` object, or None."""
    for key in ("V3Score", "V2Score"):
        scores = _scores(cvss, key)
        for source, value in scores:
            if source == "nvd":
                return value
        if scores:
            return max(value for _, value in scores)
    return None


def parse_trivy(
    text: str | bytes,
    *,
    default_acr: int = 4,
    epss: Mapping[str, float] | None = None,
) -> TrivyResult:
    """Parse Trivy JSON. Raises CsvImportError (the shared import error) on bad input."""
    if not 1 <= default_acr <= 8:
        raise ValueError("default_acr must be in 1..8")
    try:
        doc: Any = json.loads(text)
    except ValueError as exc:
        raise CsvImportError(f"not valid JSON: {exc}") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("Results") or [], list):
        raise CsvImportError("not a Trivy report: expected an object with a Results list")
    asset = doc.get("ArtifactName")
    if not isinstance(asset, str) or not asset:
        raise CsvImportError("not a Trivy report: missing ArtifactName")

    scores = epss or {}
    result = TrivyResult()
    merged: dict[str, Finding] = {}
    errors: list[str] = []
    for res in doc.get("Results") or []:
        for vuln in (res.get("Vulnerabilities") or []) if isinstance(res, dict) else []:
            if not isinstance(vuln, dict):
                continue
            vid = str(vuln.get("VulnerabilityID", "")).strip()
            if not _CVE.match(vid):
                result.skipped_non_cve += 1
                continue
            cvss = pick_cvss(vuln.get("CVSS"))
            if cvss is None:
                result.skipped_no_cvss += 1
                continue
            try:
                finding = Finding.model_validate(
                    {
                        "cve": vid,
                        "asset": asset,
                        "acr": default_acr,
                        "cvss": cvss,
                        "epss": scores.get(vid.upper(), 0.0),
                        "days_open": 0,
                    }
                )
            except ValidationError as exc:
                errors.append(f"{vid}: {exc.error_count()} validation error(s)")
                continue
            prior = merged.get(finding.cve)
            if prior is None or finding.cvss > prior.cvss:
                merged[finding.cve] = finding
    if errors:
        raise CsvImportError(f"{len(errors)} invalid finding(s); nothing imported", errors[:20])
    result.findings = list(merged.values())
    result.epss_missing = sum(1 for f in result.findings if f.cve not in scores)
    return result


def load_epss(raw: bytes) -> dict[str, float]:
    """Parse a FIRST ``epss_scores`` CSV (plain or gzip) into ``{CVE: score}``."""
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    scores: dict[str, float] = {}
    header_seen = False
    for line in raw.decode("utf-8-sig").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if not header_seen:
            if [c.strip().lower() for c in line.split(",")][:2] != ["cve", "epss"]:
                raise CsvImportError("not a FIRST EPSS file: header must start with cve,epss")
            header_seen = True
            continue
        cve, _, rest = line.partition(",")
        try:
            value = float(rest.split(",")[0])
        except ValueError:
            raise CsvImportError(f"bad EPSS row: {line[:60]!r}") from None
        if not math.isfinite(value) or not 0.0 <= value <= 1.0:
            raise CsvImportError(f"EPSS out of range: {line[:60]!r}")
        scores[cve.strip().upper()] = value
    if not header_seen:
        raise CsvImportError("empty EPSS file")
    return scores
