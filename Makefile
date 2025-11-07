.PHONY: help install install-dev clean format lint test build publish

help:
	@echo "Available targets:"
	@echo "  install       - Install package dependencies"
	@echo "  install-dev   - Install package with dev dependencies"
	@echo "  format        - Format code with black and ruff"
	@echo "  lint          - Lint code with ruff"
	@echo "  test          - Run tests with pytest"
	@echo "  build         - Build source and wheel distributions"
	@echo "  clean         - Remove build artifacts and caches"
	@echo "  publish       - Upload package to PyPI"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf src/*.egg-info
	rm -rf .pytest_cache
	rm -rf .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

format:
	black src/
	ruff check --fix src/

lint:
	ruff check src/

test:
	pytest

build: clean
	python -m build

publish: build
	twine upload dist/*
