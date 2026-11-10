"""Request and response models.

Input models are strict: unknown fields are rejected, types are not coerced
(``"5"`` is not an int), NaN and infinity are rejected.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints

CVE_REGEX = r"^[Cc][Vv][Ee]-\d{4}-\d{4,19}$"
# Printable only: no control characters, which keeps log lines and CSV round trips sane.
ASSET_REGEX = r"^[^\x00-\x1f\x7f]+$"

CveId = Annotated[
    str,
    StringConstraints(pattern=CVE_REGEX, max_length=32),
    AfterValidator(str.upper),
]
AssetName = Annotated[str, StringConstraints(min_length=1, max_length=128, pattern=ASSET_REGEX)]


class Finding(BaseModel):
    """One vulnerability on one asset, as reported by a scanner."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, allow_inf_nan=False)

    cve: CveId
    asset: AssetName
    acr: Annotated[int, Field(ge=1, le=8, description="Asset criticality rating, 1 (low) to 8")]
    cvss: Annotated[float, Field(ge=0.0, le=10.0)]
    epss: Annotated[float, Field(ge=0.0, le=1.0)]
    days_open: Annotated[int, Field(ge=0, le=36500)]


class ScoredFinding(BaseModel):
    """A finding plus its KEV membership and computed risk score."""

    cve: str
    asset: str
    acr: int
    cvss: float
    epss: float
    days_open: int
    kev: bool
    risk: float


class Accepted(BaseModel):
    accepted: int


class ImportResult(BaseModel):
    accepted: int
    skipped: int


class GroupStats(BaseModel):
    count: int
    mean_cvss: float | None
    mean_epss: float | None
    mean_days_open: float | None


class AssetStats(BaseModel):
    asset: str
    findings: int
    kev_findings: int
    total_risk: float


class Stats(BaseModel):
    total: int
    kev: GroupStats
    non_kev: GroupStats
    top_assets: list[AssetStats]
