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
    return response
```

## Guard API Views
Use `is_authenticated` and `has_required_scopes` decorators to guard your views. For a protected API view, `is_authenticated` should be always the 
first decorator. Order of decorators is important. `has_required_scopes`
should always come after `is_authenticated`.

`has_required_scopes` requires an array of strings representing the required scopes as parameter.

For instance, to check `openid` and `profile` pass `['profile', 'openid']` as parameter in `has_required_scopes`.

```
from axioms_flask.decorators import is_authenticated, has_required_scopes

@private_api.route('/private', methods=["GET"])
@is_authenticated
@has_required_scopes(['openid', 'profile'])
def api_private():
    return jsonify({'message': 'All good. You are authenticated!'})
```