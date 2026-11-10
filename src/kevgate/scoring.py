"""Risk scoring and ranking.

risk = 100 * (0.40*kev + 0.25*acr/8 + 0.20*epss + 0.20*cvss/10) / 1.05

KEV carries the largest weight because confirmed exploitation in the wild is
the strongest signal available. With these weights a KEV finding scores at
least as high as any non-KEV finding on an asset with the same criticality
(equal only in the degenerate case cvss=0, epss=0 vs cvss=10, epss=1); the
queue breaks that tie in favour of KEV.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from kevgate.kev import parse_kev_feed
from kevgate.models import Finding, ScoredFinding

W_KEV = 0.40
W_ACR = 0.25
W_EPSS = 0.20
W_CVSS = 0.20
W_TOTAL = W_KEV + W_ACR + W_EPSS + W_CVSS


def risk_score(cvss: float, epss: float, acr: int, in_kev: bool) -> float:
    """Return a 0..100 score rounded to one decimal."""
    if not 0.0 <= cvss <= 10.0:
        raise ValueError("cvss must be in 0..10")
    if not 0.0 <= epss <= 1.0:
        raise ValueError("epss must be in 0..1")
    if not 1 <= acr <= 8:
        raise ValueError("acr must be in 1..8")
    raw = W_KEV * float(in_kev) + W_ACR * (acr / 8) + W_EPSS * epss + W_CVSS * (cvss / 10)
    return round(min(100.0, max(0.0, raw / W_TOTAL * 100)), 1)


def load_kev(path: str) -> frozenset[str]:
    """Read a CISA KEV JSON file and return upper-cased CVE IDs."""
    return parse_kev_feed(Path(path).read_bytes())


def score(finding: Finding, kev: frozenset[str]) -> ScoredFinding:
    in_kev = finding.cve in kev
    return ScoredFinding(
        **finding.model_dump(),
        kev=in_kev,
        risk=risk_score(finding.cvss, finding.epss, finding.acr, in_kev),
    )


def _sort_key(s: ScoredFinding) -> tuple[float, bool, float, float, str, str]:
    # Negate numerics for descending order; cve/asset ascending for determinism.
    return (-s.risk, not s.kev, -s.epss, -s.cvss, s.cve, s.asset)


def rank(
    findings: Iterable[Finding],
    kev: frozenset[str],
    *,
    kev_only: bool = False,
    limit: int | None = None,
) -> list[ScoredFinding]:
    """Score and order findings: risk desc, then KEV first, then epss desc, then cvss desc."""
    scored = [score(f, kev) for f in findings]
    if kev_only:
        scored = [s for s in scored if s.kev]
    scored.sort(key=_sort_key)
    return scored if limit is None else scored[:limit]
