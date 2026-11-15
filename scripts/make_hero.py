# ruff: noqa: E501
"""Render docs/img/hero.png from docs/img/hero_data.json and the scoring constants.

The weights come from kevgate.scoring. The check marks come from the recorded GitHub Actions job
and step conclusions in hero_data.json (a check that did not succeed is drawn as a red cross, never
dropped). Test count and coverage come from the recorded local pytest run.

Run from the repo root:  python scripts/make_hero.py    (refresh the data first with
collect_hero_data.py). Needs matplotlib and Pillow in addition to the dev install.
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
from PIL import Image

from kevgate import scoring

ROOT = Path(__file__).resolve().parent.parent
DATA = json.loads((ROOT / "docs" / "img" / "hero_data.json").read_text(encoding="utf-8"))

# Shared look across samiali38183 repos: light background, dark text, large type.
TEXT, MUTED, LINE, PANEL = "#111827", "#4b5563", "#d1d5db", "#f3f4f6"
GOOD, BAD, ACCENT = "#15803d", "#b91c1c", "#1d4ed8"
plt.rcParams["font.family"] = "DejaVu Sans"

# (label, [(workflow, job name prefix, step name), ...]) - every listed step must have succeeded.
CI = "lint, types, tests"
SAST = "SAST (Semgrep, Bandit)"
IAC = "IaC and config scan"
IMG = "Image build, Trivy scan, SBOM"
KIND = "kind deploy"
GATES: list[tuple[str, list[tuple[str, str, str]]]] = [
    ("ruff and mypy --strict", [("ci", CI, "ruff"), ("ci", CI, "mypy")]),
    ("Semgrep and Bandit", [("security", SAST, "Semgrep (p/python, p/owasp-top-ten)"),
                            ("security", SAST, "Bandit (medium severity and above)")]),
    ("gitleaks, full history", [("security", "Secret scan", "Scan full history")]),
    ("pip-audit on hashed lock", [("security", "SCA", "pip-audit")]),
    ("checkov and trivy config", [("security", IAC, "checkov (Dockerfile, rendered Kubernetes, Terraform)"),
                                  ("security", IAC, "trivy config (fail on MEDIUM and above)")]),
    ("Helm lint and promtool", [("security", IAC, "helm lint and kubeconform (strict)"),
                                ("security", IAC, "promtool (rules, unit tests, CRD in sync)")]),
    ("Trivy image gate and SBOM", [("security", IMG, "Trivy image gate (HIGH and CRITICAL with a fix available)"),
                                   ("security", IMG, "SBOM (CycloneDX)")]),
    ("Read-only non-root container", [("security", IMG, "Container runs read-only as UID 10001 and passes the smoke test")]),
    ("kind deploy and smoke test", [("deploy-kind", KIND, "Helm install"), ("deploy-kind", KIND, "Smoke test through port-forward")]),
    ("NetworkPolicy, Pod Security", [("deploy-kind", KIND, "NetworkPolicy, egress deny and Pod Security admission")]),
    ("OWASP ZAP baseline scan", [("deploy-kind", KIND, "OWASP ZAP baseline (DAST)")]),
]  # fmt: skip


def step_ok(workflow: str, job_prefix: str, step: str) -> bool:
    jobs = DATA["runs"][workflow]["jobs"]
    matches = [steps for name, steps in jobs.items() if name.startswith(job_prefix)]
    return bool(matches) and all(s.get(step) == "success" for s in matches)


def box(ax, x, y, w, h, fc, ec=LINE, lw=1.5, r=1.2) -> None:
    ax.add_patch(
        FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0,rounding_size={r}", fc=fc, ec=ec, lw=lw)
    )


def main() -> None:
    local = DATA["local"]
    fig = plt.figure(figsize=(9, 5.5), dpi=200, facecolor="white")
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, 180)
    ax.set_ylim(0, 110)
    ax.axis("off")

    ax.text(
        6,
        101,
        "Ranks fixes by what attackers actually exploit",
        fontsize=20,
        fontweight="bold",
        color=TEXT,
        va="center",
    )
    ax.text(
        6,
        92,
        "A small API turns a scanner export into a fix-first list, built and checked like "
        "production software.",
        fontsize=10.8,
        color=MUTED,
        va="center",
    )

    # Left: how the ranking works (weights read from the code)
    box(ax, 6, 19, 66, 66, PANEL)
    ax.text(
        10, 79, "How a finding is ranked", fontsize=10.5, fontweight="bold", color=TEXT, va="center"
    )
    ax.text(10, 75, "weight in the score, from scoring.py", fontsize=8.3, color=MUTED, va="center")
    weights = [("Known exploited (CISA KEV)", scoring.W_KEV, ACCENT),
               ("Asset importance (ACR)", scoring.W_ACR, "#6b7280"),
               ("Exploit likelihood (EPSS)", scoring.W_EPSS, "#6b7280"),
               ("Severity (CVSS)", scoring.W_CVSS, "#6b7280")]  # fmt: skip
    for i, (label, w, col) in enumerate(weights):
        y = 67 - i * 10.5
        ax.text(10, y + 3.2, label, fontsize=9.3, color=TEXT, va="center")
        box(ax, 10, y - 4, 40 * w / scoring.W_KEV, 4.2, col, ec=col, lw=0, r=0.5)
        ax.text(
            10 + 40 * w / scoring.W_KEV + 1.5,
            y - 1.9,
            f"{w:.2f}",
            fontsize=10.5,
            fontweight="bold",
            color=TEXT,
            va="center",
        )
    ax.text(
        10,
        27,
        "A KEV finding never ranks below a non-KEV one\non the same asset. Weights are my own\n"
        "choice, not tested against outcomes.",
        fontsize=8.3,
        color=MUTED,
        va="center",
        linespacing=1.4,
    )

    # Right: what runs on every push
    ok = [all(step_ok(*s) for s in steps) for _, steps in GATES]
    ax_n = len(GATES) + 1
    box(ax, 78, 19, 96, 66, PANEL)
    ax.text(
        82,
        79,
        "Checked on every push to main",
        fontsize=10.5,
        fontweight="bold",
        color=TEXT,
        va="center",
    )
    ax.text(
        82,
        75,
        f"{sum(ok) + 1} of {ax_n} checks green on commit {DATA['commit'][:7]}",
        fontsize=8.3,
        color=MUTED,
        va="center",
    )
    items = [
        (
            f"{local['tests']} tests, {local['coverage_percent']}% branch coverage",
            local["failed_or_skipped"] == 0,
        )
    ]
    items += [(g[0], o) for g, o in zip(GATES, ok, strict=True)]
    half = (len(items) + 1) // 2
    for i, (label, good) in enumerate(items):
        col, row = divmod(i, half)
        x, y = 82 + col * 49, 66 - row * 8.2
        ax.text(
            x,
            y,
            "✓" if good else "✗",
            fontsize=12,
            fontweight="bold",
            color=GOOD if good else BAD,
            va="center",
        )
        ax.text(x + 4, y, label, fontsize=8.4, color=TEXT, va="center")

    prov = DATA["provenance"]
    if prov["verified"]:
        ax.text(
            6,
            14,
            f"Release image {prov['image'].split('/')[-1]}: build provenance verified with "
            f"gh attestation verify on {prov['checked_on']}.",
            fontsize=10,
            color=TEXT,
            va="center",
        )
    ax.text(
        6,
        9,
        "Limits: one replica on SQLite, nothing deployed to a real AWS account, scoring weights "
        "not yet validated.",
        fontsize=8.8,
        color=MUTED,
        va="center",
    )
    ax.text(
        6,
        4,
        "Source: GitHub Actions ci, security and deploy-kind runs and a local pytest run, "
        "saved in docs/img/hero_data.json.",
        fontsize=8.2,
        color=MUTED,
        va="center",
    )

    out = ROOT / "docs" / "img" / "hero.png"
    fig.savefig(out, dpi=200, facecolor="white")
    Image.open(out).convert("RGB").quantize(colors=64, dither=Image.Dither.NONE).save(
        out, optimize=True
    )
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
