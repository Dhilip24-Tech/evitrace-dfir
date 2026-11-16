.PHONY: venv install test lint calibrate demo site

PY := .venv/Scripts/python.exe

venv:
	python -m venv .venv

install: venv
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check src tests scripts

calibrate:
	$(PY) scripts/calibrate.py

demo:
	$(PY) scripts/generate_demo_case.py
	$(PY) scripts/run_demo.py

site:
	node "$(HOME)/.agents/skills/hallmark/scripts/sloplint.mjs" index.html styles.css --genre modern-minimal --render
