.PHONY: test lint security run-docker clean

# ── Local Development ───────────────────────────────────────────────

test:
	poetry run pytest tests/ -v

lint:
	poetry run ruff check src/ tests/
	poetry run ruff format --check src/ tests/

security:
	poetry run bandit -r src/ -ll

# ── Docker ──────────────────────────────────────────────────────────

run-docker:
	docker compose run --rm --build agent

clean:
	docker compose down --rmi local --volumes
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
