.PHONY: help install test lint format typecheck security clean lint-imports mutate build-exe context all

help:
	@echo "TaipanStack - Development Commands"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  install      Install dependencies with Poetry"
	@echo "  test         Run tests with pytest"
	@echo "  lint         Run ruff linter"
	@echo "  format       Format code with ruff"
	@echo "  typecheck    Run mypy type checker"
	@echo "  security     Run security checks (bandit, safety)"
	@echo "  lint-imports Check architecture with import-linter"
	@echo "  mutate       Run mutation testing with mutmut"
	@echo "  build-exe    Build standalone executable with PyApp"
	@echo "  context      Generate project context for AI with gitingest"
	@echo "  clean        Clean cache and temporary files"
	@echo "  all          Run all checks (lint, typecheck, security, test)"

install:
	poetry install --with dev

test:
	poetry run pytest tests/ -v --cov=src --cov-report=html --cov-report=term-missing

lint:
	poetry run ruff check src/ tests/ taipanstack_bootstrapper.py

format:
	poetry run ruff format src/ tests/ taipanstack_bootstrapper.py

typecheck:
	poetry run mypy src/ --strict

security:
	@echo "Running Bandit security scanner..."
	poetry run bandit -r src/ -ll -c pyproject.toml
	@echo ""
	@echo "Running Safety dependency checker..."
	poetry run safety check

lint-imports:
	@echo "Checking architecture with Import Linter..."
	poetry run lint-imports

mutate:
	@echo "Running mutation testing with Mutmut..."
	@echo "This may take a while..."
	poetry run mutmut run
	poetry run mutmut results

build-exe:
	@echo "Building standalone executable..."
	@cd pyapp && ./build.sh

context:
	@echo "Generating project context for AI..."
	poetry run gitingest .

clean:
	@echo "Cleaning cache and temporary files..."
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mutmut-cache -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type f -name "*.bak" -delete 2>/dev/null || true
	rm -rf htmlcov/ .coverage 2>/dev/null || true
	@echo "Clean complete!"

all: lint typecheck security lint-imports test
	@echo ""
	@echo "✅ All checks passed!"
