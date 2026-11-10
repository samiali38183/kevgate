"""ASGI entry point: ``uvicorn kevgate.main:app``. Configuration comes from env vars."""

from __future__ import annotations

from fastapi import FastAPI

from kevgate.app import create_app
from kevgate.config import Settings
from kevgate.logs import configure_logging


def build() -> FastAPI:
    settings = Settings.from_env()
    configure_logging(settings.log_level)
    return create_app(settings=settings)


app = build()
