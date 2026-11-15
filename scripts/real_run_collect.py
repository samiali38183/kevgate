"""Turn raw downloads and Trivy reports into the committed inputs under docs/real-run/inputs/.

Raw files are large (the DVWA report alone is 9 MB), so the committed copies are reduced and the
SHA-256 of every raw file is recorded in MANIFEST.json so the reduction is auditable:

* kev.json.gz       the CISA KEV feed, gzip of the file as downloaded (unmodified content)
* epss_subset.csv   FIRST EPSS rows for only the CVEs that appear in the four scans
* trivy_<img>.json  the Trivy report cut down to the fields kevgate reads (ID, package, version,
                    severity, CVSS) plus the image digest; same schema, so `kevgate import-trivy`
                    reads it directly

Usage (from the repo root), after the downloads and scans described in docs/real-run/README.md:
    python scripts/real_run_collect.py RAW_DIR TRIVY_DB_UPDATED_AT
"""

from __future__ import annotations

import gzip
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "real-run" / "inputs"
IMAGES = ("vulnerables/web-dvwa", "mysql:5.6", "tomcat:8.5.50", "httpd:2.4.49")
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEEP = ("VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "CVSS")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def slim(report: dict) -> dict:
    meta = report.get("Metadata", {})
    return {
        "ArtifactName": report["ArtifactName"],
        "ArtifactType": report.get("ArtifactType"),
        "Metadata": {"OS": meta.get("OS"), "RepoDigests": meta.get("RepoDigests")},
        "Trivy": report.get("Trivy"),
        "CreatedAt": report.get("CreatedAt"),
        "Results": [
            {
                "Target": r.get("Target"),
                "Vulnerabilities": [
                    {k: v[k] for k in KEEP if k in v} for v in r.get("Vulnerabilities") or []
                ],
            }
            for r in report.get("Results", [])
        ],
    }


def main(raw_dir: str, trivy_db_updated: str) -> None:
    raw = Path(raw_dir)
    OUT.mkdir(parents=True, exist_ok=True)
    manifest: dict = {
        "collected_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "trivy_vulnerability_db_updated_at": trivy_db_updated,
        "raw_sha256": {},
    }
    kev_raw = raw / "kev.json"
    kev = json.loads(kev_raw.read_text(encoding="utf-8"))
    manifest["kev"] = {
        "url": KEV_URL,
        "catalogVersion": kev["catalogVersion"],
        "dateReleased": kev["dateReleased"],
        "count": kev["count"],
    }
    manifest["raw_sha256"]["kev.json"] = sha(kev_raw)
    with gzip.GzipFile(OUT / "kev.json.gz", "wb", mtime=0) as fh:
        fh.write(kev_raw.read_bytes())

    cves: set[str] = set()
    reports = []
    for image in IMAGES:
        path = raw / f"trivy_{image.replace('/', '_').replace(':', '_')}.json"
        manifest["raw_sha256"][path.name] = sha(path)
        report = json.loads(path.read_text(encoding="utf-8"))
        reduced = slim(report)
        (OUT / path.name).write_text(json.dumps(reduced, indent=1) + "\n", encoding="utf-8")
        for res in reduced["Results"]:
            cves.update(v["VulnerabilityID"] for v in res["Vulnerabilities"])
        reports.append(
            {
                "image": image,
                "digest": (report["Metadata"].get("RepoDigests") or [None])[0],
                "os": report["Metadata"].get("OS"),
                "scanned_at": report.get("CreatedAt"),
                "trivy_version": report["Trivy"]["Version"],
            }
        )
    manifest["scans"] = reports

    epss_raw = raw / "epss.csv.gz"
    manifest["raw_sha256"]["epss.csv.gz"] = sha(epss_raw)
    lines = gzip.decompress(epss_raw.read_bytes()).decode("utf-8").splitlines()
    manifest["epss"] = {"url": EPSS_URL, "header_line": lines[0], "rows_total": len(lines) - 2}
    keep = [lines[0], lines[1]] + [ln for ln in lines[2:] if ln.split(",")[0] in cves]
    (OUT / "epss_subset.csv").write_text("\n".join(keep) + "\n", encoding="utf-8")
    manifest["epss"]["rows_kept"] = len(keep) - 2
    (OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
