"""FastAPI application factory.

All state (database, KEV set, key store, limiter, metrics) hangs off
``app.state.kevgate``. Nothing is module-global, so two apps never share data.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from statistics import fmean
from typing import Annotated, cast

from fastapi import Body, Depends, FastAPI, HTTPException, Path, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from kevgate import __version__
from kevgate.auth import ANONYMOUS, KeyStore, Principal, Scope, parse_bearer
from kevgate.config import MAX_FINDINGS_PER_REQUEST, ConfigError, Settings
from kevgate.csv_import import CsvImportError, parse_csv
from kevgate.db import FindingRepository
from kevgate.kev import KevFeedError
from kevgate.metrics import Metrics
from kevgate.middleware import BodySizeLimitMiddleware, RequestContextMiddleware
from kevgate.models import (
    CVE_REGEX,
    Accepted,
    AssetName,
    AssetStats,
    Finding,
    GroupStats,
    ImportResult,
    ScoredFinding,
    Stats,
)
from kevgate.ratelimit import TokenBucketLimiter
from kevgate.scoring import load_kev, rank

logger = logging.getLogger("kevgate")

DOCS_PATHS = ("/docs", "/docs/oauth2-redirect", "/redoc")
TOP_ASSETS = 5
CSV_CONTENT_TYPES = frozenset({"text/csv", "application/csv", "text/plain"})


@dataclass
class AppState:
    settings: Settings
    repo: FindingRepository
    kev: frozenset[str]
    keys: KeyStore | None
    limiter: TokenBucketLimiter
    metrics: Metrics


def get_state(request: Request) -> AppState:
    return cast(AppState, request.app.state.kevgate)


def _load_kev_or_empty(path: str) -> frozenset[str]:
    """A bad KEV file must not crash the process; /readyz reports it instead."""
    try:
        kev = load_kev(path)
    except (OSError, KevFeedError) as exc:
        logger.error("KEV catalog failed to load", extra={"fields": {"error": str(exc)}})
        return frozenset()
    logger.info("KEV catalog loaded", extra={"fields": {"entries": len(kev)}})
    return kev


def _load_keys(settings: Settings) -> KeyStore | None:
    if settings.api_keys_file is None:
        if settings.is_prod:
            raise ConfigError("KEVGATE_API_KEYS_FILE is required when KEVGATE_ENV=prod")
        logger.warning(
            "AUTHENTICATION DISABLED: KEVGATE_API_KEYS_FILE is not set. "
            "Every request is treated as an admin. Never run like this outside local dev."
        )
        return None
    keys = KeyStore.from_file(settings.api_keys_file)
    if len(keys) == 0 and settings.is_prod:
        raise ConfigError("API key file contains no keys")
    logger.info("API keys loaded", extra={"fields": {"keys": len(keys)}})
    return keys


def require(scope: Scope) -> Callable[[Request], Principal]:
    """Dependency factory: authenticate (401), rate limit (429), authorize (403)."""

    def dependency(request: Request) -> Principal:
        st = get_state(request)
        if st.keys is None:
            principal = ANONYMOUS
        else:
            token = parse_bearer(request.headers.get("authorization"))
            if token is None:
                st.metrics.auth_failures.labels("missing").inc()
                raise HTTPException(
                    401,
                    "missing or malformed bearer token",
                    headers={"WWW-Authenticate": 'Bearer realm="kevgate"'},
                )
            found = st.keys.authenticate(token)
            if found is None:
                st.metrics.auth_failures.labels("invalid").inc()
                raise HTTPException(
                    401,
                    "invalid API key",
                    headers={"WWW-Authenticate": 'Bearer realm="kevgate", error="invalid_token"'},
                )
            principal = found
        request.state.key_id = principal.key_id

        bucket = principal.key_id
        if st.keys is None:
            bucket = f"ip:{request.client.host if request.client else 'unknown'}"
        decision = st.limiter.acquire(bucket)
        if not decision.allowed:
            st.metrics.rate_limited.inc()
            raise HTTPException(
                429, "rate limit exceeded", headers={"Retry-After": str(decision.retry_after)}
            )

        if not principal.allows(scope):
            st.metrics.auth_failures.labels("forbidden").inc()
            raise HTTPException(403, f"API key lacks required scope {scope.value!r}")
        return principal

    return dependency


CveParam = Annotated[str, Path(pattern=CVE_REGEX, max_length=32)]


async def _validation_error_handler(_: Request, exc: Exception) -> JSONResponse:
    """422 without echoing the submitted values back.

    FastAPI's default handler includes each offending input, which reflects
    client data into the response and crashes on values JSON cannot encode (NaN).
    """
    errors = exc.errors() if isinstance(exc, RequestValidationError) else []
    detail = [
        {"loc": list(e.get("loc", ())), "msg": str(e.get("msg", "")), "type": e.get("type")}
        for e in errors[:50]
    ]
    return JSONResponse({"detail": detail}, status_code=422)


def _group(items: list[ScoredFinding]) -> GroupStats:
    if not items:
        return GroupStats(count=0, mean_cvss=None, mean_epss=None, mean_days_open=None)
    return GroupStats(
        count=len(items),
        mean_cvss=round(fmean(i.cvss for i in items), 2),
        mean_epss=round(fmean(i.epss for i in items), 4),
        mean_days_open=round(fmean(i.days_open for i in items), 1),
    )


def compute_stats(scored: list[ScoredFinding]) -> Stats:
    per_asset: dict[str, AssetStats] = {}
    for s in scored:
        a = per_asset.setdefault(
            s.asset, AssetStats(asset=s.asset, findings=0, kev_findings=0, total_risk=0.0)
        )
        a.findings += 1
        a.kev_findings += int(s.kev)
        a.total_risk = round(a.total_risk + s.risk, 1)
    top = sorted(per_asset.values(), key=lambda a: (-a.total_risk, -a.kev_findings, a.asset))
    return Stats(
        total=len(scored),
        kev=_group([s for s in scored if s.kev]),
        non_kev=_group([s for s in scored if not s.kev]),
        top_assets=top[:TOP_ASSETS],
    )


def create_app(kev_path: str | None = None, settings: Settings | None = None) -> FastAPI:
    """Build an app. With no settings: dev mode, in-memory DB, auth disabled."""
    if settings is None:
        settings = Settings(db_path=":memory:")
    if kev_path is not None:
        settings = replace(settings, kev_path=kev_path)

    keys = _load_keys(settings)
    repo = FindingRepository(settings.db_path)
    metrics = Metrics()
    kev = _load_kev_or_empty(settings.kev_path)
    metrics.kev_entries.set(len(kev))
    state = AppState(
        settings=settings,
        repo=repo,
        kev=kev,
        keys=keys,
        limiter=TokenBucketLimiter(settings.rate_limit_per_min),
        metrics=metrics,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        repo.close()

    docs = not settings.is_prod
    app = FastAPI(
        title="kevgate",
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
    )
    app.state.kevgate = state
    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    # Added last = outermost: the context middleware also sees 413s from the body limit.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)
    app.add_middleware(RequestContextMiddleware, metrics=metrics, csp_exempt=DOCS_PATHS)

    write = Depends(require(Scope.FINDINGS_WRITE))
    read = Depends(require(Scope.QUEUE_READ))
    admin = Depends(require(Scope.ADMIN))

    @app.get("/healthz", tags=["ops"])
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", tags=["ops"])
    def readyz() -> JSONResponse:
        checks = {
            "db": "ok" if repo.ping() else "fail",
            "kev": "ok" if state.kev else "fail",
        }
        ready = all(v == "ok" for v in checks.values())
        return JSONResponse(
            {"status": "ready" if ready else "not ready", "checks": checks},
            status_code=200 if ready else 503,
        )

    @app.get("/metrics", tags=["ops"], include_in_schema=False)
    def metrics_endpoint() -> Response:
        body, content_type = metrics.render()
        return Response(body, media_type=content_type)

    @app.post("/findings", status_code=201, tags=["findings"], dependencies=[write])
    def post_findings(
        findings: Annotated[list[Finding], Body(max_length=MAX_FINDINGS_PER_REQUEST)],
    ) -> Accepted:
        n = repo.upsert_many(findings)
        metrics.findings_ingested.labels("json").inc(n)
        return Accepted(accepted=n)

    @app.post(
        "/findings/import",
        status_code=201,
        tags=["findings"],
        dependencies=[write],
        openapi_extra={"requestBody": {"content": {"text/csv": {"schema": {"type": "string"}}}}},
    )
    async def import_csv(
        request: Request,
        default_acr: Annotated[int, Query(ge=1, le=8)] = 4,
    ) -> ImportResult:
        media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if media_type not in CSV_CONTENT_TYPES:
            raise HTTPException(415, "send the export as text/csv")
        raw = await request.body()
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise HTTPException(422, "CSV must be UTF-8 encoded") from None
        try:
            result = parse_csv(text, default_acr=default_acr)
        except CsvImportError as exc:
            raise HTTPException(422, {"error": str(exc), "rows": exc.errors}) from None
        if len(result.findings) > MAX_FINDINGS_PER_REQUEST:
            raise HTTPException(
                422,
                f"{len(result.findings)} findings in one request; "
                f"the limit is {MAX_FINDINGS_PER_REQUEST}. Split the file or use the CLI.",
            )
        n = await run_in_threadpool(repo.upsert_many, result.findings)
        metrics.findings_ingested.labels("csv").inc(n)
        return ImportResult(accepted=n, skipped=result.skipped)

    @app.get("/queue", tags=["queue"], dependencies=[read])
    def queue(
        limit: Annotated[int, Query(ge=1, le=100)] = 10,
        kev_only: bool = False,
        asset: Annotated[AssetName | None, Query()] = None,
    ) -> list[ScoredFinding]:
        return rank(repo.list_findings(asset), state.kev, kev_only=kev_only, limit=limit)

    @app.get("/findings/{cve}", tags=["findings"], dependencies=[read])
    def get_finding(cve: CveParam) -> list[ScoredFinding]:
        found = repo.get_by_cve(cve)
        if not found:
            raise HTTPException(404, "no findings for that CVE")
        return rank(found, state.kev)

    @app.delete("/findings/{cve}", status_code=204, tags=["findings"], dependencies=[admin])
    def delete_finding(cve: CveParam, asset: Annotated[AssetName, Query()]) -> Response:
        if repo.delete(cve, asset) == 0:
            raise HTTPException(404, "no such finding")
        logger.info("finding deleted", extra={"fields": {"cve": cve.upper(), "asset": asset}})
        return Response(status_code=204)

    @app.get("/stats", tags=["queue"], dependencies=[read])
    def stats() -> Stats:
        return compute_stats(rank(repo.list_findings(), state.kev))

    return app
