from __future__ import annotations

import importlib
import json
import logging
import sys
from pathlib import Path
from typing import Any

import pytest
from conftest import FIXTURES, KEV_PATH
from fastapi.testclient import TestClient
from test_kev import FEED, opener_returning

from kevgate import cli, kev
from kevgate.auth import KeyStore
from kevgate.config import DEFAULT_DB_PATH, DEFAULT_KEV_PATH, ConfigError, Settings
from kevgate.db import FindingRepository
from kevgate.logs import JsonFormatter, configure_logging

# ---- config ---------------------------------------------------------------------


def test_defaults() -> None:
    s = Settings.from_env({})
    assert s.env == "dev" and not s.is_prod
    assert s.db_path == DEFAULT_DB_PATH == "/data/kevgate.db"
    assert s.kev_path == DEFAULT_KEV_PATH and Path(s.kev_path).is_file()
    assert s.api_keys_file is None
    assert s.rate_limit_per_min == 120 and s.log_level == "INFO"


def test_all_env_vars() -> None:
    s = Settings.from_env(
        {
            "KEVGATE_ENV": "PROD",
            "KEVGATE_DB_PATH": "/tmp/x.db",
            "KEVGATE_KEV_PATH": "/tmp/kev.json",
            "KEVGATE_API_KEYS_FILE": "/run/secrets/keys",
            "KEVGATE_RATE_LIMIT_PER_MIN": "30",
            "KEVGATE_LOG_LEVEL": "debug",
        }
    )
    assert s.is_prod and s.db_path == "/tmp/x.db" and s.kev_path == "/tmp/kev.json"
    assert s.api_keys_file == "/run/secrets/keys"
    assert s.rate_limit_per_min == 30 and s.log_level == "DEBUG"


@pytest.mark.parametrize(
    "env",
    [
        {"KEVGATE_ENV": "staging"},
        {"KEVGATE_RATE_LIMIT_PER_MIN": "lots"},
        {"KEVGATE_RATE_LIMIT_PER_MIN": "0"},
        {"KEVGATE_LOG_LEVEL": "LOUD"},
    ],
)
def test_invalid_env(env: dict[str, str]) -> None:
    with pytest.raises(ConfigError):
        Settings.from_env(env)


def test_bundled_kev_sample_matches_repo_copy() -> None:
    assert Path(DEFAULT_KEV_PATH).read_bytes() == Path(KEV_PATH).read_bytes()


def test_main_module_builds_app_from_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("KEVGATE_DB_PATH", str(tmp_path / "k.db"))
    monkeypatch.setenv("KEVGATE_LOG_LEVEL", "WARNING")
    sys.modules.pop("kevgate.main", None)
    main = importlib.import_module("kevgate.main")
    c = TestClient(main.app)
    assert c.get("/readyz").status_code == 200
    # The only file written is the database (plus SQLite's WAL/SHM siblings).
    assert {p.name for p in tmp_path.iterdir()} <= {"k.db", "k.db-wal", "k.db-shm"}
    main.app.state.kevgate.repo.close()


# ---- logging --------------------------------------------------------------------


def test_json_formatter_shape() -> None:
    record = logging.LogRecord("kevgate.access", logging.INFO, __file__, 1, "request", None, None)
    record.fields = {"status": 200, "key_id": "ci"}
    record.password = "should-not-appear"
    out = json.loads(JsonFormatter().format(record))
    assert out["msg"] == "request" and out["level"] == "INFO" and out["status"] == 200
    assert "password" not in out and "ts" in out


def test_json_formatter_includes_exception() -> None:
    try:
        raise ValueError("bad")
    except ValueError:
        record = logging.LogRecord("x", logging.ERROR, __file__, 1, "oops", None, sys.exc_info())
    assert "ValueError: bad" in json.loads(JsonFormatter().format(record))["exc"]


def test_configure_logging_idempotent() -> None:
    root = logging.getLogger()
    before = list(root.handlers)
    level = root.level
    try:
        configure_logging("DEBUG")
        configure_logging("DEBUG")
        ours = [h for h in root.handlers if h.get_name() == "kevgate-json"]
        assert len(ours) == 1 and root.level == logging.DEBUG
        assert logging.getLogger("uvicorn.access").disabled
    finally:
        for h in list(root.handlers):
            if h not in before:
                root.removeHandler(h)
        root.setLevel(level)


# ---- CLI --------------------------------------------------------------------------


def test_keygen_prints_key_once_and_valid_line(capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        cli.main(["keygen", "--scope", "queue:read", "--scope", "findings:write", "--key-id", "ci"])
        == 0
    )
    out = capsys.readouterr().out.splitlines()
    key = out[0].removeprefix("key:  ")
    line = out[1].removeprefix("line: ")
    assert line.startswith("ci:findings:write,queue:read:")
    assert key not in line
    principal = KeyStore.parse([line]).authenticate(key)
    assert principal is not None and principal.key_id == "ci"


def test_keygen_random_id_and_bad_id(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["keygen", "--scope", "admin"]) == 0
    assert capsys.readouterr().out.splitlines()[1].startswith("line: key-")
    assert cli.main(["keygen", "--scope", "admin", "--key-id", "a:b"]) == 2


def test_keygen_rejects_unknown_scope() -> None:
    with pytest.raises(SystemExit):
        cli.main(["keygen", "--scope", "root"])


def test_import_csv(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = str(tmp_path / "k.db")
    rc = cli.main(
        ["import-csv", str(FIXTURES / "tenable_export.csv"), "--db", db, "--default-acr", "6"]
    )
    assert rc == 0
    assert "imported 5 finding(s), skipped 2" in capsys.readouterr().out
    repo = FindingRepository(db)
    assert repo.count() == 5 and all(f.acr == 6 for f in repo.list_findings())
    repo.close()


def test_import_csv_errors(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = str(tmp_path / "k.db")
    assert cli.main(["import-csv", str(tmp_path / "missing.csv"), "--db", db]) == 1
    bad = tmp_path / "bad.csv"
    bad.write_text("Host,CVE,CVSS\nh,CVE-2021-44228,x\n", encoding="utf-8")
    assert cli.main(["import-csv", str(bad), "--db", db]) == 1
    assert "line 2" in capsys.readouterr().err


def test_import_csv_uses_env_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("KEVGATE_DB_PATH", str(tmp_path / "env.db"))
    assert cli.main(["import-csv", str(FIXTURES / "tenable_export.csv")]) == 0
    assert (tmp_path / "env.db").exists()


def test_kev_refresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    opener = opener_returning(json.dumps(FEED).encode())
    real = kev.refresh_kev

    def patched(output: str, **kw: Any) -> int:
        return real(output, opener=opener, **kw)

    monkeypatch.setattr(cli, "refresh_kev", patched)
    out = tmp_path / "kev.json"
    assert cli.main(["kev-refresh", "--output", str(out), "--timeout", "5"]) == 0
    assert "wrote 2 KEV entries" in capsys.readouterr().out
    assert opener.calls[0][1] == 5.0
    assert cli.main(["kev-refresh", "--output", str(out), "--min-entries", "10"]) == 1


def test_kev_refresh_default_output_from_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "env-kev.json"
    monkeypatch.setenv("KEVGATE_KEV_PATH", str(target))
    opener = opener_returning(json.dumps(FEED).encode())
    real = kev.refresh_kev
    monkeypatch.setattr(cli, "refresh_kev", lambda output, **kw: real(output, opener=opener, **kw))
    assert cli.main(["kev-refresh"]) == 0
    assert target.exists()


def test_serve_invokes_uvicorn(monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn

    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: calls.append((a, kw)))
    root_handlers = list(logging.getLogger().handlers)
    try:
        assert cli.main(["serve", "--host", "0.0.0.0", "--port", "9000"]) == 0
    finally:
        for h in list(logging.getLogger().handlers):
            if h not in root_handlers:
                logging.getLogger().removeHandler(h)
    args, kwargs = calls[0]
    assert args == ("kevgate.main:app",)
    assert kwargs["host"] == "0.0.0.0" and kwargs["port"] == 9000
    assert kwargs["server_header"] is False and kwargs["access_log"] is False


def test_config_error_exit_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("KEVGATE_ENV", "nope")
    assert cli.main(["import-csv", "x.csv"]) == 2
    assert "config error" in capsys.readouterr().err


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert "kevgate 0.1.0" in capsys.readouterr().out
