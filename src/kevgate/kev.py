"""CISA Known Exploited Vulnerabilities feed: parsing, validation and refresh.

The service only ever reads a local file. Refreshing from the network is an
explicit operator action (``kevgate kev-refresh``) so the API process never
makes outbound calls.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any, Protocol

from pydantic import BaseModel, ConfigDict, StringConstraints, ValidationError

from kevgate.models import CVE_REGEX

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_FEED_BYTES = 32 * 1024 * 1024


class KevEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")
    cveID: Annotated[str, StringConstraints(pattern=CVE_REGEX, max_length=32)]  # noqa: N815


class KevFeed(BaseModel):
    """Subset of the CISA feed schema that kevgate depends on."""

    model_config = ConfigDict(extra="ignore")
    vulnerabilities: list[KevEntry]
    count: int | None = None


class KevFeedError(ValueError):
    """The KEV feed could not be fetched or failed validation."""


def parse_kev_feed(raw: bytes | str) -> frozenset[str]:
    """Validate a feed document and return the upper-cased CVE IDs."""
    try:
        feed = KevFeed.model_validate_json(raw)
    except ValidationError as exc:
        raise KevFeedError(
            f"KEV feed failed schema validation: {exc.error_count()} error(s)"
        ) from exc
    if feed.count is not None and feed.count != len(feed.vulnerabilities):
        raise KevFeedError(
            f"KEV feed count mismatch: header says {feed.count}, "
            f"found {len(feed.vulnerabilities)} entries"
        )
    return frozenset(v.cveID.upper() for v in feed.vulnerabilities)


class _Response(Protocol):
    def read(self, amt: int = ..., /) -> bytes: ...
    def __enter__(self) -> _Response: ...
    def __exit__(self, *args: object) -> Any: ...


Opener = Callable[..., _Response]


def fetch_kev_feed(
    url: str = CISA_KEV_URL,
    *,
    timeout: float = 30.0,
    max_bytes: int = MAX_FEED_BYTES,
    opener: Opener | None = None,
) -> bytes:
    """Download the feed over HTTPS with a timeout and a size cap."""
    if not url.lower().startswith("https://"):
        raise KevFeedError("refusing to fetch KEV feed over a non-HTTPS URL")
    open_url: Opener = opener if opener is not None else urllib.request.urlopen
    request = urllib.request.Request(url, headers={"User-Agent": "kevgate-kev-refresh"})  # noqa: S310
    try:
        with open_url(request, timeout=timeout) as resp:
            body = resp.read(max_bytes + 1)
    except OSError as exc:  # URLError, timeouts and socket errors are all OSError
        raise KevFeedError(f"failed to fetch KEV feed: {exc}") from exc
    if len(body) > max_bytes:
        raise KevFeedError(f"KEV feed larger than {max_bytes} bytes, refusing")
    return body


def write_atomic(path: str, data: bytes) -> None:
    """Write via a temp file in the same directory, then rename over the target."""
    target = Path(path)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        Path(tmp).replace(target)
    except BaseException:
        with contextlib.suppress(OSError):
            Path(tmp).unlink()
        raise


def refresh_kev(
    output: str,
    *,
    url: str = CISA_KEV_URL,
    timeout: float = 30.0,
    min_entries: int = 1,
    opener: Opener | None = None,
) -> int:
    """Fetch, validate and atomically replace the local KEV file. Returns entry count."""
    body = fetch_kev_feed(url, timeout=timeout, opener=opener)
    ids = parse_kev_feed(body)
    if len(ids) < min_entries:
        raise KevFeedError(f"KEV feed has {len(ids)} entries, expected at least {min_entries}")
    # Re-serialise the validated document so a partially valid upstream body is never stored.
    write_atomic(output, json.dumps(json.loads(body)).encode("utf-8"))
    return len(ids)
