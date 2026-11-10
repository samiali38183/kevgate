"""Runtime configuration, read from environment variables.

Every setting has a safe default except authentication in production: if
``KEVGATE_ENV=prod`` and no key file is configured the app refuses to start.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

DEFAULT_DB_PATH = "/data/kevgate.db"
DEFAULT_KEV_PATH = str(Path(__file__).resolve().parent / "data" / "kev_sample.json")
DEFAULT_RATE_LIMIT_PER_MIN = 120
MAX_BODY_BYTES = 1024 * 1024
MAX_FINDINGS_PER_REQUEST = 1000

_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})

Env = Literal["dev", "prod"]


class ConfigError(ValueError):
    """Raised when configuration is invalid or unsafe."""


@dataclass(frozen=True)
class Settings:
    env: Env = "dev"
    db_path: str = DEFAULT_DB_PATH
    kev_path: str = DEFAULT_KEV_PATH
    api_keys_file: str | None = None
    rate_limit_per_min: int = DEFAULT_RATE_LIMIT_PER_MIN
    log_level: str = "INFO"
    max_body_bytes: int = MAX_BODY_BYTES

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Settings:
        e = os.environ if environ is None else environ

        env_raw = e.get("KEVGATE_ENV", "dev").strip().lower()
        if env_raw not in ("dev", "prod"):
            raise ConfigError(f"KEVGATE_ENV must be 'dev' or 'prod', got {env_raw!r}")
        env: Env = "prod" if env_raw == "prod" else "dev"

        rate_raw = e.get("KEVGATE_RATE_LIMIT_PER_MIN", str(DEFAULT_RATE_LIMIT_PER_MIN)).strip()
        try:
            rate = int(rate_raw)
        except ValueError as exc:
            raise ConfigError("KEVGATE_RATE_LIMIT_PER_MIN must be an integer") from exc
        if rate < 1:
            raise ConfigError("KEVGATE_RATE_LIMIT_PER_MIN must be >= 1")

        level = e.get("KEVGATE_LOG_LEVEL", "INFO").strip().upper()
        if level not in _LOG_LEVELS:
            raise ConfigError(f"KEVGATE_LOG_LEVEL must be one of {sorted(_LOG_LEVELS)}")

        return cls(
            env=env,
            db_path=e.get("KEVGATE_DB_PATH", "").strip() or DEFAULT_DB_PATH,
            kev_path=e.get("KEVGATE_KEV_PATH", "").strip() or DEFAULT_KEV_PATH,
            api_keys_file=e.get("KEVGATE_API_KEYS_FILE", "").strip() or None,
            rate_limit_per_min=rate,
            log_level=level,
        )
