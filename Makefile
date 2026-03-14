.PHONY: help install install-dev test test-cov lint format clean build publish

help:  ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install package in production mode
	pip install -e .

install-dev:  ## Install package with all development dependencies
	pip install -e '.[dev,gemini,api,edge,pdf]'
	pre-commit install

test:  ## Run tests
	pytest tests/ -v

test-cov:  ## Run tests with coverage report
	pytest tests/ --cov=butterfence --cov-report=term-missing --cov-report=html --cov-report=xml -v
	@echo "Coverage report generated in htmlcov/index.html"

lint:  ## Run all linters
	black --check src/ tests/
	isort --check-only --profile black src/ tests/
	ruff check src/ tests/
	pylint src/butterfence/ --fail-under=8.0
	mypy src/butterfence/ --ignore-missing-imports

format:  ## Format code with black and isort
	black src/ tests/
	isort --profile black src/ tests/
	ruff check --fix src/ tests/

security:  ## Run security checks
	bandit -r src/butterfence/ -f screen
	safety check

clean:  ## Remove build artifacts and cache files
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .eggs/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

build:  ## Build distribution packages
	python -m build

publish-test:  ## Publish to TestPyPI
	python -m twine upload --repository testpypi dist/*

publish:  ## Publish to PyPI
	python -m twine upload dist/*

pre-commit:  ## Run pre-commit hooks on all files
	pre-commit run --all-files

init-repo:  ## Initialize development environment
	@echo "Setting up development environment..."
	python -m venv .venv
	@echo "Activate virtual environment with: source .venv/bin/activate"
	@echo "Then run: make install-dev"
