# tamper-evident-ledger — task runner.
#
# Quick start:
#   make up         # postgres + alembic upgrade head
#   make seed       # insert 10 ledger rows with valid chain
#   make verify     # walk the chain, print OK / broken row
#   make tamper     # simulate a DBA editing a row via raw SQL
#   make verify     # now prints chain broken at row #5
#   make down       # tear down

PY ?= python3
ALEMBIC ?= alembic

.PHONY: help up down migrate seed verify tamper verify-tampered test test-unit lint clean

help:
	@echo "Targets:"
	@echo "  up               docker compose up -d + alembic upgrade head"
	@echo "  down             docker compose down -v"
	@echo "  migrate          alembic upgrade head"
	@echo "  seed             insert 10 ledger rows with valid hash chain"
	@echo "  verify           walk chain and print result"
	@echo "  tamper           simulate raw-SQL UPDATE bypassing API (best effort)"
	@echo "  verify-tampered  alias for 'verify' after tamper"
	@echo "  test             pytest"
	@echo "  test-unit        pytest tests that need no DB"

up:
	docker compose up -d
	@echo "Waiting for postgres healthcheck..."
	@until docker compose exec -T db pg_isready -U audit -d audit >/dev/null 2>&1; do sleep 1; done
	$(ALEMBIC) upgrade head

down:
	docker compose down -v

migrate:
	$(ALEMBIC) upgrade head

seed:
	$(PY) scripts/seed.py

verify:
	$(PY) scripts/verify_chain.py

tamper:
	$(PY) scripts/tamper.py

verify-tampered: verify

test:
	pytest -v

test-unit:
	pytest -v tests/test_chain.py tests/test_encryption.py tests/test_repository.py

lint:
	ruff check app tests scripts
	ruff format --check app tests scripts

clean:
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
