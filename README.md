# axioms-flask-py ![PyPI](https://img.shields.io/pypi/v/axioms-flask-py) ![Pepy Total Downloads](https://img.shields.io/pepy/dt/axioms-flask-py)

OAuth2/OIDC authentication and authorization for Flask APIs. Supports authentication and claim-based fine-grained authorization (scopes, roles, permissions) using JWT tokens.

Works with access tokens issued by various authorization servers including [AWS Cognito](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html), [Auth0](https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles), [Okta](https://developer.okta.com/docs/api/oauth2/), [Microsoft Entra](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles), etc.

> **Using FastAPI or Django REST Framework?** This package is specifically for Flask. For FastAPI applications, use [axioms-fastapi](https://github.com/abhishektiwari/axioms-fastapi). For DRF applications, use [axioms-drf-py](https://github.com/abhishektiwari/axioms-drf-py).

![GitHub Release](https://img.shields.io/github/v/release/abhishektiwari/axioms-flask-py)
![GitHub Actions Test Workflow Status](https://img.shields.io/github/actions/workflow/status/abhishektiwari/axioms-flask-py/test.yml?label=tests)
![PyPI - Version](https://img.shields.io/pypi/v/axioms-flask-py)
![Python Wheels](https://img.shields.io/pypi/wheel/axioms-flask-py)
![Python Versions](https://img.shields.io/pypi/pyversions/axioms-flask-py?logo=python&logoColor=white)
![GitHub last commit](https://img.shields.io/github/last-commit/abhishektiwari/axioms-flask-py)
![PyPI - Status](https://img.shields.io/pypi/status/axioms-flask-py)
![License](https://img.shields.io/github/license/abhishektiwari/axioms-flask-py)
![PyPI Downloads](https://img.shields.io/pepy/dt/axioms-flask-py?label=PyPI%20Downloads)

## Features

- JWT token validation with automatic JWKS retrieval and refresh
- Algorithm validation (only secure asymmetric algorithms allowed)
- Issuer validation to prevent token substitution attacks
- Middleware for automatic token extraction and validation
- Authorization decorators: scopes, roles, permissions
- Object-level permissions for row-level security
- Custom claim name support for different auth servers
- Safe methods support (e.g., OPTIONS for CORS)

## Installation

```bash
pip install axioms-flask-py
```

## Quick Start

**1. Configure Flask app:**

```python
from flask import Flask
from flask_dotenv import DotEnv
from axioms_flask import init_axioms, setup_token_middleware, register_axioms_error_handler

app = Flask(__name__)
env = DotEnv(app)

init_axioms(app)
setup_token_middleware(app)  # Optional: automatic token validation
register_axioms_error_handler(app)
```

**2. Configure environment (`.env`):**

```bash
AXIOMS_AUDIENCE=your-api-audience
AXIOMS_ISS_URL=https://your-auth.domain.com
```

**3. Protect routes:**

```python
from axioms_flask.decorators import has_valid_access_token, has_required_permissions

@app.route('/api/protected')
@has_valid_access_token
def protected():
    return {'message': 'Authenticated'}

@app.route('/api/admin')
@has_valid_access_token
@has_required_permissions(['admin:write'])
def admin():
    return {'message': 'Authorized'}
```

## Available Decorators

| Decorator | Purpose |
|-----------|---------|
| `has_valid_access_token` | Validates JWT token (signature, expiry, audience, issuer) |
| `has_required_scopes` | Requires specific scopes in token |
| `has_required_roles` | Requires specific roles in token |
| `has_required_permissions` | Requires specific permissions in token |
| `check_object_ownership` | Validates user owns the resource (row-level security) |
| `require_ownership` | Simpler ownership check for pre-fetched objects |

## Authorization Logic

**OR Logic (default)** - Requires ANY of the specified claims:

```python
@app.route('/api/resource')
@has_valid_access_token
@has_required_scopes(['read', 'write'])  # Needs read OR write
def resource():
    return {'data': 'success'}
```

**AND Logic** - Chain decorators to require ALL claims:

```python
@app.route('/api/admin')
@has_valid_access_token
@has_required_scopes(['read'])      # Needs read
@has_required_scopes(['write'])     # AND write
@has_required_roles(['admin'])      # AND admin role
def admin():
    return {'data': 'authorized'}
```

## Examples

**Scopes:**
```python
@app.route('/api/data')
@has_valid_access_token
@has_required_scopes(['openid', 'profile'])
def get_data():
    return {'data': 'User data'}
```

**Roles:**
```python
@app.route('/api/admin/users')
@has_valid_access_token
@has_required_roles(['admin', 'superuser'])
def manage_users():
    return {'users': []}
```

**Permissions:**
```python
@app.route('/api/posts', methods=['POST'])
@has_valid_access_token
@has_required_permissions(['posts:create'])
def create_post():
    return {'id': 1, 'message': 'Post created'}
```

**Object Ownership (Row-level security):**
```python
from axioms_flask.decorators import check_object_ownership

def get_article(article_id):
    return Article.query.get_or_404(article_id)

@app.route('/articles/<int:article_id>', methods=['PATCH'])
@has_valid_access_token
@check_object_ownership(get_article, inject_as='article')
def update_article(article_id, article):
    # Only owner can update (article.user must match token.sub)
    article.title = request.json.get('title')
    db.session.commit()
    return {'id': article.id}
```

**CORS Support:**
```python
@app.route('/api/resource', methods=['GET', 'OPTIONS'])
@has_valid_access_token  # OPTIONS bypassed by default
@has_required_scopes(['read'])
def resource():
    return {'data': 'success'}
```

## Documentation

Full documentation: [https://axioms-flask-py.abhishek-tiwari.com](https://axioms-flask-py.abhishek-tiwari.com)

## License

MIT License - see LICENSE file for details.
