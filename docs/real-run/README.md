# Real-data run

One run of kevgate on public data, collected 2026-11-14. Nothing here touches anyone's systems: the
"assets" are four old public container images, scanned from the registry with Trivy.

## Inputs

| Input | Source | Pinned by |
|---|---|---|
| KEV catalog | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, catalog 2026.11.13 (1,781 entries) | `inputs/kev.json.gz`, SHA-256 of the download in `inputs/MANIFEST.json` |
| EPSS | FIRST `epss_scores-current.csv.gz` (score date 2026-11-14) | SHA-256 of the full file in the manifest; `inputs/epss_subset.csv` holds the rows for the CVEs in the scans |
| Scanner reports | Trivy 0.76.2, `trivy image` on `vulnerables/web-dvwa`, `mysql:5.6`, `tomcat:8.5.50`, `httpd:2.4.49` | image digests and SHA-256 of each full report in the manifest; `inputs/trivy_*.json` are the reports cut down to the fields kevgate reads |

The full Trivy reports are up to 9 MB each, so the committed copies are reduced; the hashes let
anyone who re-scans the same digests compare. Trivy's vulnerability database was from
2026-11-10, three days older than the KEV catalog. Re-scanning later will give different numbers.

Collection commands (Trivy needs no Docker daemon):

```bash
for i in vulnerables/web-dvwa mysql:5.6 tomcat:8.5.50 httpd:2.4.49; do
  trivy image --scanners vuln --format json -o "raw/trivy_$(echo $i | tr '/:' '__').json" "$i"; done
curl -o raw/kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
curl -o raw/epss.csv.gz https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
python scripts/real_run_collect.py raw 2026-11-10T19:01:23Z   # trivy DB UpdatedAt, from `trivy version`
```

## Reproduce the numbers and the figure from the saved inputs

```bash
pip install -e ".[dev]" matplotlib pillow
python scripts/real_run_analyze.py     # writes docs/real-run/results.json and ranked_all.csv
python scripts/make_real_run.py        # writes docs/img/real-run.png
```

Or load one report into the service with the importer this run added:

```bash
kevgate import-trivy docs/real-run/inputs/trivy_mysql_5.6.json --default-acr 8 \
  --epss-file docs/real-run/inputs/epss_subset.csv
```

## Method

All four reports are pooled into one queue of 1,112 (CVE, image) findings. Trivy gives CVSS (NVD
v3 score, else other v3, else v2); EPSS and KEV come from the files above. Trivy cannot know how
important an asset is, so asset criticality (ACR) is an input I set:

- `equal_acr`: every image at ACR 4. No assumption about importance.
- `assumed_acr`: mysql:5.6 = 8 (a database), tomcat:8.5.50 = 6, httpd:2.4.49 = 4, web-dvwa = 2 (a
  training app). This is my guess at plausible roles, not data.
- `cvss_only`: what a raw export gives you, highest CVSS first. Many findings share a CVSS, so ties
  are ordered randomly (seed 0, 1,000 trials) and KEV counts are means.

## Results

10 of 1,112 findings are on the KEV list (8 distinct CVEs; two images share CVE-2023-44487 and
CVE-2020-15999).

| Ordering | KEV in top 10 | top 25 | top 50 | top 100 | mean rank of the 10 |
|---|---|---|---|---|---|
| CVSS only | 0.15 | 0.40 | 0.86 | 1.75 | 246 |
| kevgate, equal ACR | 10 | 10 | 10 | 10 | 5.5 |
| kevgate, assumed ACR | 10 | 10 | 10 | 10 | 5.5 |

- Under CVSS only, the first KEV finding sits at rank 40 on average. CVE-2023-44487 (HTTP/2 rapid
  reset, CVSS 7.5) shares its score with 293 other findings, so it can land anywhere from 317 to 610.
- I could not show kevgate declining to put KEV first because asset importance said otherwise: on
  this data that never happens. Even the six KEV findings on the ACR 2 image outrank every non-KEV
  finding on the ACR 8 database (which has no KEV findings). The 0.40 KEV weight swamps the 0.25 ACR
  weight unless a KEV finding also has near-zero EPSS and CVSS, and none in this data does (their
  mean EPSS is 0.85). So on this data kevgate is effectively "KEV first, then the rest by
  score". Asset importance does reorder the non-KEV tail (`ranked_all.csv`, `assumed_acr` rows),
  but I did not measure whether that reordering is better.
- Mean EPSS in the top 50: 0.16 for CVSS only, 0.82 for kevgate (0.71 with assumed ACR). EPSS is an
  input to the score, so this says the ranking does what it is built to do, not that it is right.

## Limits

- One run, four images, 10 KEV findings. It shows how far down a CVSS sort leaves known-exploited
  flaws on this data. It is not a benchmark.
- Circular by construction: KEV and EPSS are score inputs, so ranking KEV findings first is not
  independent evidence that the ranking is good.
- The weights are hand-chosen and have not been validated against remediation outcomes (what was
  actually exploited, what actually got fixed, how long it took).
- ACR is assumed; `days_open` is 0 because a container scan has no first-seen date.
- Findings here are what Trivy reports. It did not report CVE-2021-41773 (a KEV entry) for
  `httpd:2.4.49`, whose Apache build is not in the OS package database. A scanner gap is upstream of
  any ranking.
- Trivy findings with non-CVE IDs (36 across the four images) are skipped by the importer.

## Files

`inputs/` (data and manifest) , `results.json` (all numbers above), `ranked_all.csv` (every finding
under every ordering), `../img/real-run.png` (the figure).
