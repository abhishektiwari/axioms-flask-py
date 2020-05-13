# axioms-flask-py ![PyPI](https://img.shields.io/pypi/v/axioms-flask-py)
[Axioms](https://axioms.io) Python client for Flask. Secure your Flask APIs using Axioms Authentication and Authorization.

## Prerequisite

* Python 3.7+
* An [Axioms](https://axioms.io) client which can obtain access token after user's authentication and authorization and include in `Authorization` header of all API request sent to Python/Flask application server.

## Install SDK
Install `axioms-flask-py` in you Flask API project,

```
pip install axioms-flask-py
```

## Basic usage

### Add `.env` file
Create a `.env` file and add following configs,

```
AXIOMS_DOMAIN=<your-axioms-slug>.axioms.io
AXIOMS_AUDIENCE=<your-axioms-resource-identifier>
```

### Load Config
In your Flask app file (where flask app is declared) add following.

```
from flask_dotenv import DotEnv
env = DotEnv(app)
```

### Register Error
In your Flask app file (where flask app is declared) add following.

```
from flask import jsonify
from axioms_flask.error import AxiomsError

@app.errorhandler(AxiomsError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    response.headers[
        "WWW-Authenticate"
    ] = "Bearer realm='{}', error='{}', error_description='{}'".format(
        app.config["AXIOMS_DOMAIN"], ex.error["error"], ex.error["error_description"]
    )
    return response
```

## Guard API Views
Use `has_valid_token` along with `has_required_scopes`, `has_required_roles`, `has_required_permissions` decorators to guard your views. 

For a protected API view, `has_valid_token` should be always the 
first decorator. Order of decorators is important. Other decorators should
always come after `has_valid_token`.

### has required scopes
`has_required_scopes` requires an array of strings representing the allowed scope or scopes for the view as parameter.

For instance, to check `openid` or `profile` pass `['profile', 'openid']` as parameter in `has_required_scopes`.


```
from axioms_flask.decorators import has_valid_token, has_required_scopes

@private_api.route('/private', methods=["GET"])
@has_valid_token
@has_required_scopes(['openid', 'profile'])
def api_private():
    return jsonify({'message': 'All good. You are authenticated!'})
```

### Has required roles
**Prerequisite:** Roles should be [defined](https://developer.axioms.io/docs/getting-started/role/index) and [assigned to users](https://developer.axioms.io/docs/getting-started/user/index#edit-user-roles) in Axioms.

`has_required_roles` requires an array of strings representing the allowed role or roles for the view as parameter. If intersection of allowed roles on the view and the roles in the token is a positive number, function will return true otherwise false.

```
@role_api.route("/role", methods=["GET", "POST", "PATCH", "DELETE"])
@has_valid_token
@has_required_roles(["sample:role"])
def sample_role():
    return jsonify({'message': 'You have required role to create, update, read, delete!'})
```

### Has required permissions
**Prerequisite:** Permissions should be defined when a resource is created and configured in Axioms (see how to add [permissions on resource](https://developer.axioms.io/docs/getting-started/resource/configure/permissions/)).

`has_required_roles` requires an array of strings representing the allowed permission or permissions for the view as parameter.

For instance, to check `sample:create` or `sample:update` permissions you will pass `['sample:create', 'sample:update']` as parameter in `has_required_roles`. If intersection of allowed roles on the view and the roles in the token is a positive number, function will return true otherwise false.

```
@permission_api.route("/permission", methods=["POST", "PATCH"])
@has_valid_token
@has_required_permissions(["sample:create", "sample:updated"])
def sample_create():
    return jsonify({'message': 'You have required permissions to create or update!'})
```

## Flask Sample 
To learn more download our [Flask sample](https://github.com/axioms-io/sample-python-flask) from our Github repository. In less than 10 minutes you can deploy sample to Heroku or AWS Lambda.