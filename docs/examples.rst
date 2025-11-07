Examples
========

This page provides practical examples of using axioms-flask-py decorators to secure your Flask API routes.

Scope-Based Authorization
--------------------------

Check if ``openid`` or ``profile`` scope is present in the token:

.. code-block:: python

   from flask import Blueprint, jsonify
   from axioms_flask.decorators import has_valid_access_token, has_required_scopes

   private_api = Blueprint("private_api", __name__)

   @private_api.route('/private', methods=["GET"])
   @has_valid_access_token
   @has_required_scopes(['openid', 'profile'])
   def api_private():
       return jsonify({'message': 'All good. You are authenticated!'})

**Example JWT Token Payload (Success):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "scope": "openid profile email",
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** because the token contains ``openid`` in the ``scope`` claim.

**Example JWT Token Payload (Failure):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "scope": "email",
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **fail** with 403 Forbidden because the token does not contain ``openid`` or ``profile`` in the ``scope`` claim.

Role-Based Authorization
-------------------------

Check if ``sample:role`` role is present in the token:

.. code-block:: python

   from flask import Blueprint, jsonify, request
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

**Example JWT Token Payload (Success):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "roles": ["sample:role", "viewer"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** because the token contains ``sample:role`` in the ``roles`` claim.

**Example JWT Token Payload with Namespaced Claims (Success):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "https://your-domain.com/claims/roles": ["sample:role", "admin"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will also **succeed** if ``AXIOMS_DOMAIN`` is set to ``your-domain.com``.

**Example JWT Token Payload (Failure):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "roles": ["viewer", "editor"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **fail** with 403 Forbidden because the token does not contain ``sample:role``.

Permission-Based Authorization
-------------------------------

Check permissions at the API method level:

.. code-block:: python

   from flask import Blueprint, jsonify
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

**Example JWT Token Payload (Success for sample:read):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "permissions": ["sample:read", "sample:update"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** for the GET endpoint because the token contains ``sample:read`` in the ``permissions`` claim.

**Example JWT Token Payload with Namespaced Claims (Success):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "https://your-domain.com/claims/permissions": ["sample:create", "sample:delete"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **succeed** for POST and DELETE endpoints if ``AXIOMS_DOMAIN`` is set to ``your-domain.com``.

**Example JWT Token Payload (Failure):**

.. code-block:: json

   {
     "sub": "user123",
     "aud": "your-api-audience",
     "permissions": ["other:read"],
     "exp": 1735689600,
     "iat": 1735686000
   }

This request will **fail** with 403 Forbidden because the token does not contain any of the required ``sample:*`` permissions.

Complete Flask Application
---------------------------

For a complete working example, check out the `Flask sample application <https://github.com/axioms-io/sample-python-flask>`_
on GitHub. The sample demonstrates a fully functional Flask application with authentication and authorization.
