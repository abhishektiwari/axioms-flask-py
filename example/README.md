# Axioms Flask Example App

This example demonstrates all features of the axioms-flask-py library:

- Public endpoints
- Authentication-only endpoints
- Scope-based authorization (OR and AND logic)
- Role-based authorization (OR and AND logic)
- Permission-based authorization
- Mixed authorization (combining scopes, roles, and permissions)
- Object-level permissions (row-level security)
- Custom owner field names

## Setup

### Using Make (Recommended)

```bash
cd example
make install    # Install dependencies
make run        # Run the app
```

### Manual Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set environment variables (optional):
```bash
export AXIOMS_AUDIENCE="https://api.example.com"
export AXIOMS_ISS_URL="https://jwtforge.dev"
export AXIOMS_JWKS_URL="https://jwtforge.dev/.well-known/jwks.json"
```

3. Run the app:
```bash
python app.py
```

The API will be available at `http://localhost:8000`.

## Testing with Postman

1. Import the Postman collection: `Axioms_Flask_Example.postman_collection.json`
2. The collection uses [jwtforge.dev](https://jwtforge.dev) to generate test tokens
3. Each request automatically generates a token with appropriate claims
4. Run the entire collection to test all endpoints

## Database

The example uses SQLite by default (`test.db`). To use a different database:

```bash
export DATABASE_URL="postgresql://user:pass@localhost/dbname"
```

## Makefile Commands

The example includes a Makefile with helpful commands:

```bash
make help          # Show all available commands
make install       # Install dependencies from requirements.txt
make run           # Run the Flask application
make clean         # Remove database and Python cache files
make db-reset      # Reset the database (clean + recreate on next run)
make test-health   # Test the /health endpoint
make test-protected # Test the /protected endpoint
```

## Learn More

- [axioms-flask-py](https://github.com/abhishektiwari/axioms-flask-py)
- [axioms-core-py](https://github.com/abhishektiwari/axioms-core-py)
- [jwtforge.dev](https://jwtforge.dev) - Test token generator
