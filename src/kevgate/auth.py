"""API key authentication and scope checks.

Keys look like ``kvg_<43 url-safe chars>`` (32 random bytes, 256 bits). The
server stores only ``sha256(key)``. A fast hash is the right choice here:
slow password hashes (scrypt, argon2) exist to make guessing low-entropy
human passwords expensive, but a 256-bit random key cannot be brute forced
from its SHA-256 digest, and a deliberately slow hash on every request would
hand an attacker a cheap CPU exhaustion lever.

Key file format, one key per line, ``#`` comments allowed::

    key_id:scope[,scope...]:sha256hex
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

KEY_PREFIX = "kvg_"
MAX_TOKEN_LENGTH = 256
KEY_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class Scope(StrEnum):
    FINDINGS_WRITE = "findings:write"
    QUEUE_READ = "queue:read"
    ADMIN = "admin"


ALL_SCOPES = frozenset(Scope)


class KeyFileError(ValueError):
    """The API key file is malformed. The service must not start with it."""


@dataclass(frozen=True)
class Principal:
    """The caller, after authentication. Never carries the key itself."""

    key_id: str
    scopes: frozenset[Scope]

    def allows(self, scope: Scope) -> bool:
        return Scope.ADMIN in self.scopes or scope in self.scopes


ANONYMOUS = Principal(key_id="anonymous", scopes=ALL_SCOPES)


@dataclass(frozen=True)
class StoredKey:
    key_id: str
    scopes: frozenset[Scope]
    digest: bytes

    @property
    def principal(self) -> Principal:
        return Principal(self.key_id, self.scopes)


def generate_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def parse_scopes(raw: str) -> frozenset[Scope]:
    scopes: set[Scope] = set()
    for part in raw.split(","):
        name = part.strip()
        try:
            scopes.add(Scope(name))
        except ValueError:
            raise KeyFileError(f"unknown scope {name!r}") from None
    return frozenset(scopes)


def format_key_line(key_id: str, scopes: Iterable[Scope], key: str) -> str:
    if not KEY_ID_RE.fullmatch(key_id):
        raise ValueError("key_id must match [A-Za-z0-9_.-]{1,64}")
    scope_list = ",".join(sorted(s.value for s in set(scopes)))
    if not scope_list:
        raise ValueError("at least one scope is required")
    return f"{key_id}:{scope_list}:{hash_key(key)}"


def parse_bearer(header: str | None) -> str | None:
    """Extract the token from ``Authorization: Bearer <token>``; None if absent or malformed."""
    if not header:
        return None
    scheme, _, token = header.partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token or len(token) > MAX_TOKEN_LENGTH:
        return None
    return token


class KeyStore:
    def __init__(self, keys: Sequence[StoredKey]) -> None:
        ids = [k.key_id for k in keys]
        if len(ids) != len(set(ids)):
            raise KeyFileError("duplicate key_id in key file")
        self._keys = tuple(keys)

    def __len__(self) -> int:
        return len(self._keys)

    @classmethod
    def parse(cls, lines: Iterable[str]) -> KeyStore:
        keys: list[StoredKey] = []
        for lineno, raw in enumerate(lines, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            # Scopes contain colons themselves ("queue:read"), so take id and hash from the ends.
            if len(parts) < 3:
                raise KeyFileError(f"line {lineno}: expected key_id:scopes:hash")
            key_id, digest_hex = parts[0], parts[-1].lower()
            scope_raw = ":".join(parts[1:-1])
            if not KEY_ID_RE.fullmatch(key_id):
                raise KeyFileError(f"line {lineno}: invalid key_id")
            if not _HEX64_RE.fullmatch(digest_hex):
                raise KeyFileError(f"line {lineno}: hash must be 64 hex chars (sha256)")
            try:
                scopes = parse_scopes(scope_raw)
            except KeyFileError as exc:
                raise KeyFileError(f"line {lineno}: {exc}") from None
            keys.append(StoredKey(key_id, scopes, bytes.fromhex(digest_hex)))
        return cls(keys)

    @classmethod
    def from_file(cls, path: str) -> KeyStore:
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise KeyFileError(f"cannot read API key file: {exc.strerror}") from exc
        return cls.parse(text.splitlines())

    def authenticate(self, token: str) -> Principal | None:
        """Constant-time match of the token's digest against every stored digest.

        The loop never exits early, so response time does not reveal which
        (if any) key matched or how many leading bytes were right.
        """
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        match: StoredKey | None = None
        for key in self._keys:
            if hmac.compare_digest(digest, key.digest):
                match = key
        return match.principal if match is not None else None
