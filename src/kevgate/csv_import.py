"""Parse Nessus / Tenable style CSV exports into findings.

Column names are matched case-insensitively against a list of aliases so the
same parser handles Nessus Professional, Tenable.io/VM and Tenable.sc exports:

======== =====================================================================
field    accepted headers (first non-empty wins)
======== =====================================================================
cve      CVE, CVEs  (a cell may hold several IDs separated by commas/spaces)
asset    Host, Asset, Asset Name, DNS Name, NetBIOS Name, IP Address
cvss     CVSS v3.0 Base Score, CVSS V3 Base Score, CVSS3 Base Score,
         CVSS v2.0 Base Score, CVSS V2 Base Score, CVSS Base Score, CVSS
epss     EPSS, EPSS Score                         (optional, default 0.0)
acr      ACR, Asset Criticality Rating            (optional, default_acr)
age      Days Open, Age                           (optional)
first    First Discovered, First Seen, First Found (used if no age column)
======== =====================================================================

Policy:
* Rows with no CVE (informational plugins) are skipped and counted.
* Rows that have a CVE but bad values are errors. Any error rejects the whole
  file so a half-imported scan never ends up in the queue.
* Duplicate (cve, asset) pairs, e.g. the same plugin on several ports, are
  merged keeping the highest cvss, epss and days_open.
"""

from __future__ import annotations

import csv
import io
import math
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from pydantic import ValidationError

from kevgate.models import Finding

ALIASES: dict[str, tuple[str, ...]] = {
    "cve": ("cve", "cves"),
    "asset": ("host", "asset", "asset name", "dns name", "netbios name", "ip address"),
    "cvss": (
        "cvss v3.0 base score",
        "cvss v3 base score",
        "cvss3 base score",
        "cvss v2.0 base score",
        "cvss v2 base score",
        "cvss base score",
        "cvss",
    ),
    "epss": ("epss", "epss score"),
    "acr": ("acr", "asset criticality rating"),
    "age": ("days open", "age"),
    "first": ("first discovered", "first seen", "first found"),
}
REQUIRED = ("cve", "asset", "cvss")
MAX_REPORTED_ERRORS = 20
_CVE_SPLIT = re.compile(r"[\s,;]+")
_DATE_FORMATS = ("%b %d, %Y %H:%M:%S %Z", "%Y-%m-%d")


class CsvImportError(ValueError):
    """The CSV could not be imported. ``errors`` lists per-row problems."""

    def __init__(self, message: str, errors: Sequence[str] = ()) -> None:
        super().__init__(message)
        self.errors = list(errors)


@dataclass
class ParseResult:
    findings: list[Finding] = field(default_factory=list)
    skipped: int = 0


def _resolve_columns(header: Sequence[str]) -> dict[str, list[str]]:
    normalized = {h.strip().lower(): h for h in header if h is not None}
    resolved: dict[str, list[str]] = {}
    for fieldname, aliases in ALIASES.items():
        cols = [normalized[a] for a in aliases if a in normalized]
        if cols:
            resolved[fieldname] = cols
    missing = [f for f in REQUIRED if f not in resolved]
    if missing:
        raise CsvImportError(f"missing required column(s): {', '.join(missing)}")
    return resolved


def _first(row: dict[str, str | None], cols: list[str] | None) -> str:
    for col in cols or ():
        value = (row.get(col) or "").strip()
        if value:
            return value
    return ""


def _number(raw: str, name: str) -> float:
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"{name} {raw!r} is not a number") from None
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite")
    return value


def _integer(raw: str, name: str) -> int:
    value = _number(raw, name)
    if not value.is_integer():
        raise ValueError(f"{name} {raw!r} is not a whole number")
    return int(value)


def _days_since(raw: str, now: datetime) -> int:
    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        for fmt in _DATE_FORMATS:
            try:
                parsed = datetime.strptime(raw, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        raise ValueError(f"unrecognised date {raw!r}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return max(0, (now - parsed).days)


def _merge(a: Finding, b: Finding) -> Finding:
    return a.model_copy(
        update={
            "cvss": max(a.cvss, b.cvss),
            "epss": max(a.epss, b.epss),
            "days_open": max(a.days_open, b.days_open),
            "acr": max(a.acr, b.acr),
        }
    )


def parse_csv(
    text: str,
    *,
    default_acr: int = 4,
    now: datetime | None = None,
) -> ParseResult:
    """Parse CSV text. Raises CsvImportError on structural or row-level problems."""
    if not 1 <= default_acr <= 8:
        raise ValueError("default_acr must be in 1..8")
    now = now or datetime.now(UTC)
    reader = csv.DictReader(io.StringIO(text, newline=""))
    try:
        header = reader.fieldnames
    except csv.Error as exc:
        raise CsvImportError(f"malformed CSV: {exc}") from None
    if not header:
        raise CsvImportError("empty CSV")
    cols = _resolve_columns(header)

    merged: dict[tuple[str, str], Finding] = {}
    errors: list[str] = []
    skipped = 0
    try:
        for row in reader:
            line = reader.line_num
            cve_cell = _first(row, cols["cve"])
            if not cve_cell:
                skipped += 1
                continue
            try:
                acr_raw = _first(row, cols.get("acr"))
                age_raw = _first(row, cols.get("age"))
                first_raw = _first(row, cols.get("first"))
                epss_raw = _first(row, cols.get("epss"))
                cvss_raw = _first(row, cols["cvss"])
                if not cvss_raw:
                    raise ValueError("no CVSS score")
                if age_raw:
                    days_open = _integer(age_raw, "days open")
                elif first_raw:
                    days_open = _days_since(first_raw, now)
                else:
                    days_open = 0
                base = {
                    "asset": _first(row, cols["asset"]),
                    "acr": _integer(acr_raw, "acr") if acr_raw else default_acr,
                    "cvss": _number(cvss_raw, "cvss"),
                    "epss": _number(epss_raw, "epss") if epss_raw else 0.0,
                    "days_open": days_open,
                }
                for cve in filter(None, _CVE_SPLIT.split(cve_cell)):
                    finding = Finding.model_validate({"cve": cve, **base})
                    key = (finding.cve, finding.asset)
                    prior = merged.get(key)
                    merged[key] = finding if prior is None else _merge(prior, finding)
            except ValidationError as exc:
                problems = "; ".join(
                    f"{'.'.join(str(p) for p in e['loc']) or 'row'}: {e['msg']}"
                    for e in exc.errors(include_input=False, include_url=False)
                )
                errors.append(f"line {line}: {problems}")
            except ValueError as exc:
                errors.append(f"line {line}: {exc}")
    except csv.Error as exc:
        raise CsvImportError(f"malformed CSV near line {reader.line_num}: {exc}") from None

    if errors:
        raise CsvImportError(
            f"{len(errors)} invalid row(s); nothing imported",
            errors[:MAX_REPORTED_ERRORS],
        )
    return ParseResult(findings=list(merged.values()), skipped=skipped)
