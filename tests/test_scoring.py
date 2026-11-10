from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from kevgate.models import Finding
from kevgate.scoring import W_TOTAL, rank, risk_score

cvss_s = st.floats(min_value=0.0, max_value=10.0, allow_nan=False)
epss_s = st.floats(min_value=0.0, max_value=1.0, allow_nan=False)
acr_s = st.integers(min_value=1, max_value=8)


@given(cvss_s, epss_s, acr_s, st.booleans())
def test_score_always_in_bounds_and_one_decimal(
    cvss: float, epss: float, acr: int, kev: bool
) -> None:
    s = risk_score(cvss, epss, acr, kev)
    assert 0.0 <= s <= 100.0
    assert s == round(s, 1)


@given(cvss_s, epss_s, cvss_s, epss_s, acr_s)
def test_kev_never_ranks_below_non_kev_same_acr(
    c1: float, e1: float, c2: float, e2: float, acr: int
) -> None:
    assert risk_score(c1, e1, acr, True) >= risk_score(c2, e2, acr, False)


@given(cvss_s, cvss_s, epss_s, acr_s, st.booleans())
def test_monotonic_in_cvss(a: float, b: float, epss: float, acr: int, kev: bool) -> None:
    lo, hi = sorted((a, b))
    assert risk_score(lo, epss, acr, kev) <= risk_score(hi, epss, acr, kev)


@given(cvss_s, epss_s, acr_s, acr_s, st.booleans())
def test_monotonic_in_acr(cvss: float, epss: float, a: int, b: int, kev: bool) -> None:
    lo, hi = sorted((a, b))
    assert risk_score(cvss, epss, lo, kev) <= risk_score(cvss, epss, hi, kev)


def test_known_values() -> None:
    assert pytest.approx(1.05) == W_TOTAL
    assert risk_score(10.0, 1.0, 8, True) == 100.0
    assert risk_score(0.0, 0.0, 8, False) == round(0.25 / 1.05 * 100, 1)
    # Hand computed: (0.40 + 0.25*4/8 + 0.20*0.5 + 0.20*0.9) / 1.05 * 100 = 76.7
    assert risk_score(9.0, 0.5, 4, True) == 76.7


@pytest.mark.parametrize(
    "args",
    [(-0.1, 0.5, 4), (10.1, 0.5, 4), (5.0, -0.01, 4), (5.0, 1.01, 4), (5.0, 0.5, 0), (5.0, 0.5, 9)],
)
def test_out_of_range_inputs_raise(args: tuple[float, float, int]) -> None:
    with pytest.raises(ValueError):
        risk_score(*args, False)


def _f(cve: str, **kw: object) -> Finding:
    base: dict[str, object] = {"asset": "a", "acr": 4, "cvss": 5.0, "epss": 0.5, "days_open": 1}
    base.update(kw)
    return Finding.model_validate({"cve": cve, **base})


def test_rank_breaks_exact_tie_in_favour_of_kev() -> None:
    kev = frozenset({"CVE-2021-44228"})
    on_kev = _f("CVE-2021-44228", cvss=0.0, epss=0.0)
    off_kev = _f("CVE-2023-00001", cvss=10.0, epss=1.0)
    ranked = rank([off_kev, on_kev], kev)
    assert ranked[0].risk == ranked[1].risk
    assert ranked[0].kev is True


def test_rank_tie_break_order_and_determinism() -> None:
    kev: frozenset[str] = frozenset()
    a = _f("CVE-2023-00002", epss=0.5, cvss=5.0)
    b = _f("CVE-2023-00001", epss=0.5, cvss=5.0)
    ranked = rank([a, b], kev)
    assert [x.cve for x in ranked] == ["CVE-2023-00001", "CVE-2023-00002"]


def test_rank_kev_only_and_limit() -> None:
    kev = frozenset({"CVE-2021-44228"})
    items = [_f("CVE-2021-44228"), _f("CVE-2023-00001"), _f("CVE-2023-00002")]
    assert [x.cve for x in rank(items, kev, kev_only=True)] == ["CVE-2021-44228"]
    assert len(rank(items, kev, limit=2)) == 2
