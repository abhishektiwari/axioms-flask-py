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

Complete Flask Application
---------------------------

For a complete working example, check out the `Flask sample application <https://github.com/axioms-io/sample-python-flask>`_
on GitHub. The sample demonstrates a fully functional Flask application with authentication and authorization.
