# axioms-flask-py ![PyPI](https://img.shields.io/pypi/v/axioms-flask-py) ![Pepy Total Downloads](https://img.shields.io/pepy/dt/axioms-flask-py)
OAuth2/OIDC authentication and authorization for Flask APIs. Supports authentication and claim-based fine-grained authorization (scopes, roles, permissions) using JWT tokens.

![GitHub Release](https://img.shields.io/github/v/release/abhishektiwari/axioms-flask-py)
![GitHub Actions Test Workflow Status](https://img.shields.io/github/actions/workflow/status/abhishektiwari/axioms-flask-py/test.yml?label=tests)
![PyPI - Version](https://img.shields.io/pypi/v/axioms-flask-py)
![Python Wheels](https://img.shields.io/pypi/wheel/axioms-flask-py)
![Python Versions](https://img.shields.io/pypi/pyversions/axioms-flask-py?logo=python&logoColor=white)
![GitHub last commit](https://img.shields.io/github/last-commit/abhishektiwari/axioms-flask-py)
![PyPI - Status](https://img.shields.io/pypi/status/axioms-flask-py)
![License](https://img.shields.io/github/license/abhishektiwari/axioms-flask-py)
![PyPI Downloads](https://img.shields.io/pepy/dt/axioms-flask-py?label=PyPI%20Downloads)

## Prerequisite

* Python 3.7+
* An OAuth2/OIDC client which can obtain access token after user's authentication and authorization and include obtained access token as bearer in `Authorization` header of all API request sent to Python/Flask application server.

## Install SDK
Install `axioms-flask-py` in you Flask API project,

```
pip install axioms-flask-py
```

## Documentation

### Prerequisite

- Python 3.7+
- An Axioms client which can obtain access token after user's authentication and authorization and include obtained access token as bearer in `Authorization` header of all API request sent to Python/Flask application server.

### Install SDK
Install `axioms-flask-py` in you Flask API project,

```
pip install axioms-flask-py
```

### Add environment variables
Create a `.env` file and add following configs

**Option 1: Using AXIOMS_DOMAIN** (for Axioms or standard OAuth2/OIDC providers)
```bash title=".env"
AXIOMS_DOMAIN=<your-axioms-slug>.axioms.io
AXIOMS_AUDIENCE=<your-axioms-resource-identifier-or-endpoint>
```

**Option 2: Using AXIOMS_JWKS_URL** (for custom JWKS endpoints)
```bash title=".env"
AXIOMS_JWKS_URL=https://my-auth.domain.com/oauth2/.well-known/jwks.json
AXIOMS_AUDIENCE=<your-axioms-resource-identifier-or-endpoint>
```

**Configuration Options:**
- `AXIOMS_AUDIENCE` (required): Your resource identifier or API audience
- `AXIOMS_JWKS_URL` (optional): Full URL to your JWKS endpoint
- `AXIOMS_DOMAIN` (optional): Your auth domain (e.g., `my-auth.domain.com`)

**Note:** You must provide either `AXIOMS_JWKS_URL` or `AXIOMS_DOMAIN`.

**Claims Handling:**
- Roles are checked from `roles` claim, or `https://{AXIOMS_DOMAIN}/claims/roles` if using namespaced claims
- Permissions are checked from `permissions` claim, or `https://{AXIOMS_DOMAIN}/claims/permissions` if using namespaced claims
- Scopes are checked from the standard `scope` claim

### Load environment variables
In your Flask app file (where flask app is declared) add following.

```py title="app.py"
from flask_dotenv import DotEnv
env = DotEnv(app)
```

### Register Error
In your Flask app file (where flask app is declared) add following.

```py title="app.py"
from flask import jsonify
from axioms_flask.error import AxiomsError

@app.errorhandler(AxiomsError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    if ex.status_code == 401:
        response.headers[
            "WWW-Authenticate"
        ] = "Bearer realm='{}', error='{}', error_description='{}'".format(
            app.config["AXIOMS_DOMAIN"], ex.error["error"], ex.error["error_description"]
        )
    return response
```

### Guard Your Flask API Views
Use following decorators to guard you API views.

| Decorators | Description | Parameter |
| -- | -- | -- |
| `axioms_flask.decorators.`<br/>`has_valid_access_token` | Checks if API request includes a valid bearer access token as authorization header. Check performed includes: token signature validation, expiry datetime validation, and token audience validation. Should be always the `first` decorator on the protected or private view. |  |
| `axioms_flask.decorators.`<br/>`has_required_scopes` | Check any of the given scopes included in `scope` claim of the access token. Should be after `has_valid_access_token`. | An array of strings as `conditional OR` representing any of the allowed scope or scopes for the view as parameter. For instance, to check `openid` or `profile` pass `['profile', 'openid']` as parameter. |
| `axioms_flask.decorators.`<br/>`has_required_roles` | Check any of the given roles included in `roles` claim of the access token. Should be after `has_valid_access_token`. | An array of strings as `conditional OR` representing any of the allowed role or roles for the view as parameter. For instance, to check `sample:role1` or `sample:role2` roles you will pass `['sample:role1', 'sample:role2']` as parameter. |
| `axioms_flask.decorators.`<br/>`has_required_permissions` | Check any of the given permissions included in `permissions` claim of the access token. Should be after `has_valid_access_token`. | An array of strings as `conditional OR` representing any of the allowed permission or permissions for the view as parameter. For instance, to check `sample:create` or `sample:update` permissions you will pass `['sample:create', 'sample:update']` as parameter. |

#### OR vs AND Logic

By default, authorization decorators use **OR logic** - the token must have **at least ONE** of the specified claims. To require **ALL claims (AND logic)**, chain multiple decorators.

**OR Logic (Default)** - Requires ANY of the specified claims:

```python
@app.route('/api/resource')
@has_valid_access_token
@has_required_scopes(['read:resource', 'write:resource'])
def resource_route():
    # User needs EITHER 'read:resource' OR 'write:resource' scope
    return {'data': 'success'}

@app.route('/admin/users')
@has_valid_access_token
@has_required_roles(['admin', 'superuser'])
def admin_route():
    # User needs EITHER 'admin' OR 'superuser' role
    return {'users': []}
```

**AND Logic (Chaining)** - Requires ALL of the specified claims:

```python
@app.route('/api/strict')
@has_valid_access_token
@has_required_scopes(['read:resource'])
@has_required_scopes(['write:resource'])
def strict_route():
    # User needs BOTH 'read:resource' AND 'write:resource' scopes
    return {'data': 'requires both scopes'}

@app.route('/admin/critical')
@has_valid_access_token
@has_required_roles(['admin'])
@has_required_roles(['superuser'])
def critical_route():
    # User needs BOTH 'admin' AND 'superuser' roles
    return {'message': 'requires both roles'}
```

**Mixed Logic** - Combine OR and AND by chaining:

```python
@app.route('/api/advanced')
@has_valid_access_token
@has_required_scopes(['openid', 'profile'])  # Needs openid OR profile
@has_required_roles(['editor'])               # AND must have editor role
@has_required_permissions(['resource:read', 'resource:write'])  # AND read OR write permission
def advanced_route():
    # User needs: (openid OR profile) AND (editor) AND (read OR write)
    return {'data': 'complex authorization'}
```

### Examples

- Check `openid` or `profile` scope present in the token

```py
from axioms_flask.decorators import has_valid_access_token, has_required_scopes

private_api = Blueprint("private_api", __name__)

@private_api.route('/private', methods=["GET"])
@has_valid_access_token
@has_required_scopes(['openid', 'profile'])
def api_private():
    return jsonify({'message': 'All good. You are authenticated!'})
```

- Check `sample:role` role present in the token

```py
from axioms_flask.decorators import has_valid_access_token, has_required_roles

role_api = Blueprint("role_api", __name__)

@role_api.route("/role", methods=["GET", "POST", "PATCH", "DELETE"])
@has_valid_access_token
@has_required_roles(["sample:role"])
def sample_role():
    if request.method == 'POST':
        return jsonify({"message": "Sample created."})
    if request.method == 'PATCH':
        return jsonify({"message": "Sample updated."})
    if request.method == 'GET':
        return jsonify({"message": "Sample read."})
    if request.method == 'DELETE':
        return jsonify({"message": "Sample deleted."})
```

- Check permission present in the token at API method level

```py
from axioms_flask.decorators import has_valid_access_token, has_required_permissions

permission_api = Blueprint("permission_api", __name__)

@permission_api.route("/permission", methods=["POST"])
@has_valid_access_token
@has_required_permissions(["sample:create"])
def sample_create():
    return jsonify({"message": "Sample created."})


@permission_api.route("/permission", methods=["PATCH"])
@has_valid_access_token
@has_required_permissions(["sample:update"])
def sample_update():
    return jsonify({"message": "Sample updated."})


@permission_api.route("/permission", methods=["GET"])
@has_valid_access_token
@has_required_permissions(["sample:read"])
def sample_read():
    return jsonify({"message": "Sample read."})


@permission_api.route("/permission", methods=["DELETE"])
@has_valid_access_token
@has_required_permissions(["sample:delete"])
def sample_delete():
    return jsonify({"message": "Sample deleted."})
```

## Flask Sample
To see a complete working example download [Flask sample](https://github.com/axioms-io/sample-python-flask) from our Github repository or simply deploy to heroku by clicking following button. You will need to provide Axioms domain and Axioms audience to complete deployment.
