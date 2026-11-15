"""Collect the facts shown in docs/img/hero.png into docs/img/hero_data.json.

Two sources, both recorded as they were at collection time:
  * the latest commit on main for which the ci, security and deploy-kind workflows all finished
    (job and step conclusions, read with the `gh` CLI)
  * a local pytest run with branch coverage

Run from the repo root with the dev install and an authenticated `gh`:
    python scripts/collect_hero_data.py
Then render with: python scripts/make_hero.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = "samiali38183/kevgate"
WORKFLOWS = ("ci", "security", "deploy-kind")


def gh(*args: str) -> object:
    out = subprocess.run(  # noqa: S603
        ["gh", *args],  # noqa: S607
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout
    return json.loads(out)


def latest_green_sha() -> tuple[str, dict[str, dict]]:
    runs = gh(
        "run", "list", "-R", REPO, "--branch", "main", "--event", "push", "--limit", "60",
        "--json", "databaseId,workflowName,conclusion,headSha,createdAt",
    )  # fmt: skip
    by_sha: dict[str, dict[str, dict]] = {}
    for run in runs:  # newest first
        if run["workflowName"] in WORKFLOWS and run["conclusion"] == "success":
            by_sha.setdefault(run["headSha"], {}).setdefault(run["workflowName"], run)
    for sha, found in by_sha.items():
        if all(w in found for w in WORKFLOWS):
            return sha, found
    raise SystemExit("no main commit with ci, security and deploy-kind all green")


def steps_of(run_id: int) -> dict[str, dict[str, str]]:
    jobs = gh("api", f"repos/{REPO}/actions/runs/{run_id}/jobs")["jobs"]  # type: ignore[index]
    return {
        job["name"]: {
            step["name"]: step["conclusion"]
            for step in job["steps"]
            if step["conclusion"] != "skipped"
        }
        for job in jobs
    }


def local_tests() -> dict[str, object]:
    tmp = Path(tempfile.mkdtemp())
    junit, cov = tmp / "junit.xml", tmp / "cov.json"
    subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", f"--junitxml={junit}", "--cov=kevgate",
         f"--cov-report=json:{cov}"],
        cwd=ROOT, check=True, capture_output=True,
    )  # fmt: skip
    root = ET.parse(junit).getroot()  # noqa: S314 (our own pytest output)
    cases = list(root.iter("testcase"))
    failed = [c for c in cases if any(ch.tag in ("failure", "error", "skipped") for ch in c)]
    totals = json.loads(cov.read_text(encoding="utf-8"))["totals"]
    return {
        "tests": len(cases),
        "failed_or_skipped": len(failed),
        "coverage_percent": round(totals["percent_covered"], 2),
        "statements": totals["num_statements"],
    }


def release_provenance() -> dict[str, object]:
    """Verify the build provenance attestation of the newest release image."""
    tag = str(gh("release", "list", "-R", REPO, "--limit", "1", "--json", "tagName")[0]["tagName"])  # type: ignore[index]
    version = tag.removeprefix("v")
    image = f"oci://ghcr.io/{REPO}:{version}"
    result = subprocess.run(  # noqa: S603
        ["gh", "attestation", "verify", image, "-R", REPO],  # noqa: S607
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return {
        "image": f"ghcr.io/{REPO}:{version}",
        "verified": result.returncode == 0,
        "checked_on": datetime.now(UTC).date().isoformat(),
    }


def main() -> None:
    sha, found = latest_green_sha()
    data = {
        "commit": sha,
        "runs": {
            name: {
                "id": run["databaseId"],
                "created_at": run["createdAt"],
                "url": f"https://github.com/{REPO}/actions/runs/{run['databaseId']}",
                "jobs": steps_of(run["databaseId"]),
            }
            for name, run in found.items()
        },
        "local": local_tests(),
        "provenance": release_provenance(),
    }
    out = ROOT / "docs" / "img" / "hero_data.json"
    out.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {out} for {sha[:7]}: {data['local']}")


if __name__ == "__main__":
    main()
