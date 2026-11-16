.PHONY: venv install test lint typecheck calibrate demo site

ifeq ($(OS),Windows_NT)
PY ?= .venv/Scripts/python.exe
else
PY ?= .venv/bin/python
endif

venv:
	python -m venv .venv

install: venv
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check src tests scripts
	$(PY) -m ruff format --check src tests scripts

typecheck:
	$(PY) -m mypy src

calibrate:
	$(PY) scripts/calibrate.py

demo:
	$(PY) scripts/generate_demo_case.py
	$(PY) scripts/run_demo.py

site:
	$(PY) -m http.server 8000 --bind 127.0.0.1
