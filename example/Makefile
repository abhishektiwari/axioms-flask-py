.PHONY: help install run clean test-health test-protected db-reset

help:
	@echo "Axioms Flask Example - Available Commands:"
	@echo ""
	@echo "  make install      - Install dependencies"
	@echo "  make run          - Run the Flask application"
	@echo "  make clean        - Clean up generated files"
	@echo "  make db-reset     - Reset the database"
	@echo "  make test-health  - Test health endpoint"
	@echo "  make test-protected - Test protected endpoint (requires token)"
	@echo ""

install:
	@echo "Installing dependencies..."
	pip install -r requirements.txt

run:
	@echo "Starting Flask application on http://localhost:8000..."
	python app.py

clean:
	@echo "Cleaning up..."
	rm -f test.db
	rm -rf __pycache__
	rm -rf .pytest_cache
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete

db-reset: clean
	@echo "Database reset complete. It will be recreated on next run."

test-health:
	@echo "Testing health endpoint..."
	@curl -s http://localhost:8000/health | python -m json.tool || echo "Error: Is the server running?"

test-protected:
	@echo "Testing protected endpoint (should fail without token)..."
	@curl -s http://localhost:8000/protected | python -m json.tool || echo "Error: Is the server running?"
