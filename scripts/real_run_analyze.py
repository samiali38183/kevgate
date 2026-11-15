"""Rank the real-data inputs in docs/real-run/inputs/ with kevgate; write docs/real-run/results.*.

Three orderings of the same findings (all four images pooled into one queue):
  cvss_only   what a raw scanner export gives you: CVSS descending. Ties are common (many 9.8s),
              so the tie order is randomised (fixed seed, 1000 trials) and KEV counts are means.
  equal_acr   kevgate with every asset at ACR 4 (the importer default): asset importance carries
              no information
  assumed_acr kevgate with ACR chosen by me from each image's apparent role. These numbers are
              an assumption, not data; they exist to show what changes when assets differ.

Run from the repo root:  python scripts/real_run_analyze.py
"""

from __future__ import annotations

import csv
import gzip
import json
import random
import statistics
from pathlib import Path

from kevgate.kev import parse_kev_feed
from kevgate.scoring import rank
from kevgate.trivy_import import load_epss, parse_trivy

ROOT = Path(__file__).resolve().parent.parent
RUN = ROOT / "docs" / "real-run"
INPUTS = RUN / "inputs"
ASSUMED_ACR = {"mysql:5.6": 8, "tomcat:8.5.50": 6, "httpd:2.4.49": 4, "vulnerables/web-dvwa": 2}
EQUAL_ACR = 4
TOP_NS = (10, 25, 50, 100)
TRIALS = 1000


def load(acr_by_image: dict[str, int]) -> list:
    epss = load_epss((INPUTS / "epss_subset.csv").read_bytes())
    findings = []
    stats = {}
    for image, acr in acr_by_image.items():
        path = INPUTS / f"trivy_{image.replace('/', '_').replace(':', '_')}.json"
        res = parse_trivy(path.read_bytes(), default_acr=acr, epss=epss)
        findings += res.findings
        stats[image] = {
            "findings": len(res.findings),
            "skipped_non_cve": res.skipped_non_cve,
            "skipped_no_cvss": res.skipped_no_cvss,
            "epss_missing": res.epss_missing,
        }
    return findings, stats


def positions(order: list, kev: set[tuple[str, str]]) -> list[int]:
    return [i + 1 for i, f in enumerate(order) if (f.cve, f.asset) in kev]


def main() -> None:
    kev_ids = parse_kev_feed(gzip.decompress((INPUTS / "kev.json.gz").read_bytes()))
    findings_eq, scan_stats = load({k: EQUAL_ACR for k in ASSUMED_ACR})
    findings_as, _ = load(ASSUMED_ACR)
    kev_keys = {(f.cve, f.asset) for f in findings_eq if f.cve in kev_ids}
    n = len(findings_eq)

    # CVSS-only baseline with randomised tie order.
    rng = random.Random(0)  # noqa: S311 - tie-order shuffling, not security
    per_n = {top: [] for top in TOP_NS}
    first_kev, mean_pos, epss50 = [], [], []
    for _ in range(TRIALS):
        shuffled = findings_eq[:]
        rng.shuffle(shuffled)
        shuffled.sort(key=lambda f: -f.cvss)  # stable: ties keep the shuffled order
        pos = positions(shuffled, kev_keys)
        for top in TOP_NS:
            per_n[top].append(sum(1 for p in pos if p <= top))
        first_kev.append(pos[0])
        epss50.append(statistics.mean(f.epss for f in shuffled[:50]))
        mean_pos.append(statistics.mean(pos))
    cvss_sorted = sorted(findings_eq, key=lambda f: (-f.cvss, f.cve, f.asset))
    cvss_pos_detail = {}
    for f in sorted((f for f in findings_eq if (f.cve, f.asset) in kev_keys), key=lambda f: f.cve):
        above = sum(1 for g in findings_eq if g.cvss > f.cvss)
        tied = sum(1 for g in findings_eq if g.cvss == f.cvss)
        cvss_pos_detail[f"{f.cve}|{f.asset}"] = {
            "cvss": f.cvss,
            "ahead_strictly": above,
            "tied_incl_self": tied,
        }

    results: dict = {
        "findings_total": n,
        "kev_findings": len(kev_keys),
        "scan_stats": scan_stats,
        "kev_catalog_entries": len(kev_ids),
        "cvss_only": {
            "mean_kev_in_top": {str(t): round(statistics.mean(per_n[t]), 2) for t in TOP_NS},
            "min_max_kev_in_top": {str(t): [min(per_n[t]), max(per_n[t])] for t in TOP_NS},
            "mean_rank_of_kev": round(statistics.mean(mean_pos), 1),
            "mean_first_kev_rank": round(statistics.mean(first_kev), 1),
            "mean_epss_in_top50": round(statistics.mean(epss50), 3),
            "trials": TRIALS,
            "per_kev_finding": cvss_pos_detail,
        },
    }
    csv_rows = []
    for name, findings in (("equal_acr", findings_eq), ("assumed_acr", findings_as)):
        ranked = rank(findings, kev_ids)
        pos = [i + 1 for i, s in enumerate(ranked) if s.kev]
        results[name] = {
            "mean_epss_in_top50": round(statistics.mean(s.epss for s in ranked[:50]), 3),
            "kev_in_top": {str(t): sum(1 for p in pos if p <= t) for t in TOP_NS},
            "kev_ranks": pos,
            "mean_rank_of_kev": round(statistics.mean(pos), 1),
            # How many non-KEV findings sit above the lowest-ranked KEV finding?
            "non_kev_above_last_kev": pos[-1] - len(pos),
            "non_kev_above_first_kev": pos[0] - 1,
        }
        for i, s in enumerate(ranked, 1):
            csv_rows.append({"ordering": name, "rank": i, **s.model_dump()})
    for i, f in enumerate(cvss_sorted, 1):
        csv_rows.append(
            {
                "ordering": "cvss_only_tiebreak_by_cve_id",
                "rank": i,
                "cve": f.cve,
                "asset": f.asset,
                "acr": f.acr,
                "cvss": f.cvss,
                "epss": f.epss,
                "days_open": f.days_open,
                "kev": (f.cve, f.asset) in kev_keys,
                "risk": "",
            }
        )

    # Concrete cases where asset importance beats KEV (assumed ACR only).
    ranked_as = rank(findings_as, kev_ids)
    last_kev = max(i for i, s in enumerate(ranked_as) if s.kev)
    kev_low = [s for s in ranked_as if s.kev and s.acr <= 2]
    outranking = []
    for s in kev_low:
        i = ranked_as.index(s)
        outranking.append(
            {
                "cve": s.cve,
                "asset": s.asset,
                "risk": s.risk,
                "rank": i + 1,
                "non_kev_ahead": sum(1 for g in ranked_as[:i] if not g.kev),
                "ahead_highest_acr_non_kev": sum(
                    1 for g in ranked_as[:i] if not g.kev and g.acr == 8
                ),
            }
        )
    results["assumed_acr"]["kev_on_acr2_asset"] = outranking
    results["assumed_acr"]["last_kev_rank"] = last_kev + 1
    # Within one asset, is kevgate KEV-first? (guaranteed by the weights; verify on real data)
    violations = 0
    for acr_group in (findings_eq,):
        ranked = rank(acr_group, kev_ids)
        seen_non_kev = False
        for s in ranked:
            if not s.kev:
                seen_non_kev = True
            elif seen_non_kev:
                violations += 1
    results["equal_acr"]["kev_below_a_non_kev"] = violations
    top = ranked_as[:15]
    results["assumed_acr"]["top15"] = [
        {
            "cve": s.cve,
            "asset": s.asset,
            "kev": s.kev,
            "risk": s.risk,
            "cvss": s.cvss,
            "epss": s.epss,
        }
        for s in top
    ]
    (RUN / "results.json").write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
    with (RUN / "ranked_all.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(csv_rows[0]))
        w.writeheader()
        w.writerows(csv_rows)
    print(json.dumps({k: v for k, v in results.items() if k != "scan_stats"}, indent=1)[:6000])


if __name__ == "__main__":
    main()
