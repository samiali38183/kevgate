# ruff: noqa: E501
"""Render docs/img/real-run.png from docs/real-run/results.json and ranked_all.csv.

Left: for each of the 10 KEV-listed findings, where a CVSS-only sort puts it (grey bar = the span
of positions it can take among findings with the same CVSS, diamond = the middle) and where kevgate
puts it (red dot). Right: how many of the 10 land in the top N. Everything drawn comes from the
saved results; nothing is typed in here.

Run from the repo root after scripts/real_run_analyze.py:  python scripts/make_real_run.py
Needs matplotlib and Pillow in addition to the dev install.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
RUN = ROOT / "docs" / "real-run"
R = json.loads((RUN / "results.json").read_text(encoding="utf-8"))
MAN = json.loads((RUN / "inputs" / "MANIFEST.json").read_text(encoding="utf-8"))

TEXT, MUTED, LINE, PANEL = "#111827", "#4b5563", "#d1d5db", "#f3f4f6"
BAD, GREY = "#b91c1c", "#6b7280"
plt.rcParams["font.family"] = "DejaVu Sans"

n_total, n_kev = R["findings_total"], R["kev_findings"]
with (RUN / "ranked_all.csv").open(encoding="utf-8") as fh:
    kevgate_rank = {
        f"{r['cve']}|{r['asset']}": int(r["rank"])
        for r in csv.DictReader(fh)
        if r["ordering"] == "equal_acr" and r["kev"] == "True"
    }
rows = []
for key, d in R["cvss_only"]["per_kev_finding"].items():
    lo, hi = d["ahead_strictly"] + 1, d["ahead_strictly"] + d["tied_incl_self"]
    rows.append((kevgate_rank[key], key.replace("|", "  "), d["cvss"], lo, hi))
rows.sort(key=lambda r: (r[0], r[1]))

fig = plt.figure(figsize=(18, 10.2), dpi=100, facecolor="white")
fig.text(
    0.03,
    0.96,
    "A real scan of four old public container images: where the 10 actively exploited findings land",
    fontsize=23,
    fontweight="bold",
    color=TEXT,
    va="center",
)
fig.text(
    0.03,
    0.917,
    f"{n_total:,} findings, {n_kev} of them on CISA's Known Exploited Vulnerabilities list. Sorting by CVSS alone buries them; kevgate puts all {n_kev} first.",
    fontsize=16.5,
    color=MUTED,
    va="center",
)

ax = fig.add_axes([0.355, 0.215, 0.33, 0.57], facecolor="white")
ys = list(range(len(rows)))[::-1]
for y, (kr, _label, _cvss, lo, hi) in zip(ys, rows, strict=True):
    ax.plot([lo, hi], [y, y], color=GREY, lw=9, alpha=0.35, solid_capstyle="butt", zorder=2)
    ax.plot([((lo + hi) / 2)], [y], marker="D", color=GREY, ms=11, zorder=3)
    ax.plot([kr], [y], marker="o", color=BAD, ms=15, zorder=4)
    ax.annotate(
        "",
        xy=(kr * 1.25, y),
        xytext=(((lo + hi) / 2) / 1.2, y),
        arrowprops={"arrowstyle": "-|>", "color": LINE, "lw": 1.5},
        zorder=1,
    )
ax.set_yticks(ys)
ax.set_yticklabels(
    [f"{r[1].split('  ')[0]}   {r[1].split('  ')[1]}   (CVSS {r[2]:g})" for r in rows],
    fontsize=14,
    color=TEXT,
)
ax.set_xscale("log")
ax.set_xlim(0.8, n_total * 1.15)
ax.set_xticks([1, 10, 100, 1000])
ax.set_xticklabels(["1", "10", "100", "1,000"], fontsize=15, color=TEXT)
ax.set_ylim(-0.7, len(rows) - 0.3)
ax.grid(axis="x", color=LINE, lw=1, zorder=0)
for s in ("top", "right", "left"):
    ax.spines[s].set_visible(False)
ax.spines["bottom"].set_color(LINE)
ax.tick_params(axis="y", length=0)
ax.set_xlabel(
    "Position in the fix-first list (1 = fix first), log scale",
    fontsize=16,
    color=TEXT,
    labelpad=10,
)
fig.text(
    0.03,
    0.865,
    "Each exploited finding, before and after",
    fontsize=17,
    fontweight="bold",
    color=TEXT,
)
ax.plot([], [], marker="D", color=GREY, ls="", ms=11, label="CVSS only: expected position")
ax.plot([], [], color=GREY, lw=9, alpha=0.35, label="CVSS only: possible positions")
ax.plot([], [], marker="o", color=BAD, ls="", ms=13, label="kevgate")
ax.legend(
    loc="lower right",
    bbox_to_anchor=(1.05, 1.0),
    ncol=3,
    frameon=False,
    fontsize=12,
    handlelength=1.6,
    handletextpad=0.5,
    columnspacing=1.4,
)

ax2 = fig.add_axes([0.77, 0.215, 0.21, 0.57], facecolor="white")
tops = ["10", "25", "50", "100"]
cvss_vals = [R["cvss_only"]["mean_kev_in_top"][t] for t in tops]
kg_vals = [R["equal_acr"]["kev_in_top"][t] for t in tops]
x = range(len(tops))
w = 0.40
b1 = ax2.bar(
    [i - w / 2 for i in x], cvss_vals, w, color=GREY, label="CVSS only (mean of 1,000 tie orders)"
)
b2 = ax2.bar([i + w / 2 for i in x], kg_vals, w, color=BAD, label="kevgate")
for rect, v in zip(list(b1) + list(b2), cvss_vals + kg_vals, strict=True):
    grey = rect in b1
    ax2.text(
        rect.get_x() + rect.get_width() / 2,
        v + 0.2,
        f"{v:g}",
        ha="center",
        fontsize=14,
        fontweight="bold",
        color=TEXT,
        zorder=6,
        bbox={"facecolor": "white", "edgecolor": "none", "pad": 1.5} if grey else None,
    )
ax2.set_xticks(list(x))
ax2.set_xticklabels([f"top {t}" for t in tops], fontsize=15, color=TEXT)
ax2.set_ylim(0, n_kev + 1.6)
ax2.set_yticks([0, 5, 10])
ax2.tick_params(axis="y", labelsize=14, colors=TEXT)
ax2.grid(axis="y", color=LINE, lw=1, zorder=0)
ax2.set_axisbelow(True)
for s in ("top", "right"):
    ax2.spines[s].set_visible(False)
for s in ("left", "bottom"):
    ax2.spines[s].set_color(LINE)
fig.text(0.77, 0.865, "Exploited findings in the top N", fontsize=16, fontweight="bold", color=TEXT)
ax2.legend(loc="upper center", bbox_to_anchor=(0.5, -0.1), ncol=1, frameon=False, fontsize=12.5)

mi = ", ".join(s["image"] for s in MAN["scans"])
fig.text(
    0.03,
    0.115,
    f"Inputs: Trivy {MAN['scans'][0]['trivy_version']} scans of {mi};\n"
    f"CISA KEV catalog {MAN['kev']['catalogVersion']}; FIRST EPSS scores. Equal asset importance.",
    fontsize=13.5,
    color=MUTED,
    va="center",
    linespacing=1.5,
)
fig.text(
    0.03,
    0.04,
    "Limits: one run on four images, weights are my own choice and are not validated against remediation outcomes, and the KEV signal is also an input to the score,\n"
    "so putting KEV findings first is by design, not an independent test. What the run shows is how far down a CVSS sort leaves them.",
    fontsize=13.5,
    color=MUTED,
    va="center",
    linespacing=1.5,
)

out = ROOT / "docs" / "img" / "real-run.png"
fig.savefig(out, dpi=100, facecolor="white")
with Image.open(out) as im:
    print(im.size)
