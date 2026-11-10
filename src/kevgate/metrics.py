"""Prometheus metrics. Each app instance owns its own registry (no global state)."""

from __future__ import annotations

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    PlatformCollector,
    ProcessCollector,
    generate_latest,
)

LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)


class Metrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        ProcessCollector(registry=self.registry)
        PlatformCollector(registry=self.registry)
        self.requests = Counter(
            "kevgate_http_requests",
            "HTTP requests by method, route template and status code.",
            ["method", "route", "status"],
            registry=self.registry,
        )
        self.latency = Histogram(
            "kevgate_http_request_duration_seconds",
            "HTTP request latency by method and route template.",
            ["method", "route"],
            buckets=LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.findings_ingested = Counter(
            "kevgate_findings_ingested",
            "Findings accepted and written, by source (json or csv).",
            ["source"],
            registry=self.registry,
        )
        self.auth_failures = Counter(
            "kevgate_auth_failures",
            "Rejected requests by reason (missing, invalid, forbidden).",
            ["reason"],
            registry=self.registry,
        )
        self.rate_limited = Counter(
            "kevgate_rate_limited",
            "Requests rejected with 429.",
            registry=self.registry,
        )
        self.kev_entries = Gauge(
            "kevgate_kev_entries",
            "CVE IDs in the loaded KEV catalog.",
            registry=self.registry,
        )

    def render(self) -> tuple[bytes, str]:
        return generate_latest(self.registry), CONTENT_TYPE_LATEST
