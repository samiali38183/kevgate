# Works on Linux/macOS and on Windows under Git Bash with GNU make.
ifeq ($(OS),Windows_NT)
  BIN := .venv/Scripts
else
  BIN := .venv/bin
endif
PY := $(BIN)/python

.PHONY: install lint type test run clean

install:
	python -m venv .venv
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"

lint:
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

type:
	$(BIN)/mypy --strict src

test:
	$(PY) -m pytest --cov=kevgate --cov-report=term-missing

# Local dev server: auth disabled (loud warning), database in the repo root.
run:
	KEVGATE_ENV=dev KEVGATE_DB_PATH=./kevgate.db $(BIN)/uvicorn kevgate.main:app --reload --port 8000

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov build dist kevgate.db*
