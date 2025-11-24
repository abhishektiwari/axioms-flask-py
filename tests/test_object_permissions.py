"""Tests for object-level permission checking."""

import json
import time

import pytest
from flask import Flask, abort, jsonify, request

from axioms_flask import (
    check_object_ownership,
    register_axioms_error_handler,
    setup_token_middleware,
)


# Mock database models
class Article:
    """Mock Article model with user owner field."""

    def __init__(self, id, title, user):
        self.id = id
        self.title = title
        self.user = user


class Comment:
    """Mock Comment model with created_by owner field."""

    def __init__(self, id, text, created_by):
        self.id = id
        self.text = text
        self.created_by = created_by


# Mock database
ARTICLES_DB = {
    1: Article(1, "Article by user123", "user123"),
    2: Article(2, "Article by user456", "user456"),
}

COMMENTS_DB = {
    1: Comment(1, "Comment by user123", "user123"),
    2: Comment(2, "Comment by user456", "user456"),
}


def generate_jwt_token(test_key, claims_dict):
    """Generate a JWT token using test keys."""
    from jwcrypto import jwk, jws

    key = jwk.JWK(**test_key)
    token = jws.JWS(claims_dict.encode("utf-8"))
    token.add_signature(
        key,
        alg="RS256",
        protected=json.dumps({"alg": "RS256", "typ": "JWT", "kid": test_key["kid"]}),
    )
    return token.serialize(compact=True)


@pytest.fixture
def test_app(test_key, mock_jwks_data, monkeypatch):
    """Create Flask app with object permission routes."""
    import axioms_core.helper as helper

    # Mock JWKS fetch
    def mock_get_jwks(url):
        return mock_jwks_data

    monkeypatch.setattr(helper._jwks_manager, "get_jwks", mock_get_jwks)

    app = Flask(__name__)
    app.config["AXIOMS_AUDIENCE"] = "test-audience"
    app.config["AXIOMS_DOMAIN"] = "test-domain.com"
    app.config["TESTING"] = True

    # Setup middleware without init_axioms (for testing)
    setup_token_middleware(app)
    register_axioms_error_handler(app)

    # Object getter functions
    def get_article(article_id):
        article = ARTICLES_DB.get(article_id)
        if not article:
            abort(404, description="Article not found")
        return article

    def get_comment(comment_id):
        comment = COMMENTS_DB.get(comment_id)
        if not comment:
            abort(404, description="Comment not found")
        return comment

    # Routes with default ownership (article.user == token.sub)
    @app.route("/articles/<int:article_id>", methods=["GET"])
    @check_object_ownership(get_article)
    def get_article_route(article_id):
        article = get_article(article_id)
        return jsonify({"id": article.id, "title": article.title, "user": article.user})

    @app.route("/articles/<int:article_id>", methods=["PATCH"])
    @check_object_ownership(get_article, inject_as="article")
    def update_article_route(article_id, article):
        # Article is injected, no need to fetch again
        new_title = request.json.get("title")
        article.title = new_title
        return jsonify({"id": article.id, "title": article.title})

    # Routes with custom owner field (comment.created_by == token.sub)
    @app.route("/comments/<int:comment_id>", methods=["PATCH"])
    @check_object_ownership(get_comment, owner_field="created_by")
    def update_comment_route(comment_id):
        comment = get_comment(comment_id)
        new_text = request.json.get("text")
        comment.text = new_text
        return jsonify({"id": comment.id, "text": comment.text})

    # Route with custom claim field
    @app.route("/articles-by-email/<int:article_id>", methods=["GET"])
    @check_object_ownership(get_article, owner_field="user", claim_field="email")
    def get_article_by_email(article_id):
        article = get_article(article_id)
        return jsonify({"id": article.id})

    # Route with dictionary object
    @app.route("/dict-objects/<int:obj_id>", methods=["GET"])
    def get_dict_object(obj_id):
        def get_obj(obj_id):
            return {"id": obj_id, "user": "user123", "data": "test"}

        @check_object_ownership(get_obj)
        def handler(obj_id):
            obj = get_obj(obj_id)
            return jsonify(obj)

        return handler(obj_id)

    return app


class TestCheckObjectOwnership:
    """Test check_object_ownership decorator."""

    def test_owner_can_access_object(self, test_app, test_key):
        """Test that object owner can access their object."""
        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user123",  # Owns article 1
                "iss": "https://test-domain.com",
                "aud": ["test-audience"],
                "exp": now + 3600,
                "iat": now,
            }
        )
        token = generate_jwt_token(test_key, claims)

        with test_app.test_client() as client:
            response = client.get(
                "/articles/1", headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["id"] == 1
            assert data["user"] == "user123"

    def test_non_owner_cannot_access_object(self, test_app, test_key):
        """Test that non-owner is denied access to object."""
        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user456",  # Doesn't own article 1
                "iss": "https://test-domain.com",
                "aud": ["test-audience"],
                "exp": now + 3600,
                "iat": now,
            }
        )
        token = generate_jwt_token(test_key, claims)

        with test_app.test_client() as client:
            response = client.get(
                "/articles/1", headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 403
            data = json.loads(response.data)
            assert data["error"] == "insufficient_scope"
            assert "permission" in data["error_description"].lower()

    def test_owner_can_access_their_different_object(self, test_app, test_key):
        """Test that user456 can access their own article (article 2)."""
        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user456",  # Owns article 2
                "iss": "https://test-domain.com",
                "aud": ["test-audience"],
                "exp": now + 3600,
                "iat": now,
            }
        )
        token = generate_jwt_token(test_key, claims)

        with test_app.test_client() as client:
            response = client.get(
                "/articles/2", headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["id"] == 2
            assert data["user"] == "user456"

    def test_unauthenticated_request_denied(self, test_app):
        """Test that unauthenticated requests are denied."""
        with test_app.test_client() as client:
            response = client.get("/articles/1")
            assert response.status_code == 401
            data = json.loads(response.data)
            assert data["error"] == "invalid_token"

    def test_object_not_found_returns_404(self, test_app, test_key):
        """Test that non-existent object returns 404."""
        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user123",
                "iss": "https://test-domain.com",
                "aud": ["test-audience"],
                "exp": now + 3600,
                "iat": now,
            }
        )
        token = generate_jwt_token(test_key, claims)

        with test_app.test_client() as client:
            response = client.get(
                "/articles/999", headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 404


class TestCustomOwnerField:
    """Test object ownership with custom owner field."""

    def test_custom_owner_field(self, test_app, test_key):
        """Test ownership check with custom owner_field."""
        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user123",  # Owns comment 1 (created_by field)
                "iss": "https://test-domain.com",
                "aud": ["test-audience"],
                "exp": now + 3600,
                "iat": now,
            }
        )
        token = generate_jwt_token(test_key, claims)

        with test_app.test_client() as client:
            response = client.patch(
                "/comments/1",
                headers={"Authorization": f"Bearer {token}"},
                json={"text": "Updated text"},
            )
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["text"] == "Updated text"

    def test_custom_owner_field_wrong_user(self, test_app, test_key):
        """Test that wrong user is denied with custom owner_field."""
        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user456",  # Doesn't own comment 1
                "iss": "https://test-domain.com",
                "aud": ["test-audience"],
                "exp": now + 3600,
                "iat": now,
            }
        )
        token = generate_jwt_token(test_key, claims)

        with test_app.test_client() as client:
            response = client.patch(
                "/comments/1",
                headers={"Authorization": f"Bearer {token}"},
                json={"text": "Updated text"},
            )
            assert response.status_code == 403


class TestObjectInjection:
    """Test object injection into route handler."""

    def test_object_injected_into_handler(self, test_app, test_key):
        """Test that object is injected when inject_as is specified."""
        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user123",
                "iss": "https://test-domain.com",
                "aud": ["test-audience"],
                "exp": now + 3600,
                "iat": now,
            }
        )
        token = generate_jwt_token(test_key, claims)

        with test_app.test_client() as client:
            response = client.patch(
                "/articles/1",
                headers={"Authorization": f"Bearer {token}"},
                json={"title": "New Title"},
            )
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["title"] == "New Title"
            # Verify article was updated (injected object was modified)
            assert ARTICLES_DB[1].title == "New Title"


class TestCustomClaimField:
    """Test object ownership with custom claim field."""

    def test_custom_claim_field(self, test_app, test_key):
        """Test ownership check with custom claim_field."""
        # Modify article to use email for testing
        original_user = ARTICLES_DB[1].user
        ARTICLES_DB[1].user = "user123@example.com"

        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user123",
                "email": "user123@example.com",  # Custom claim for matching
                "iss": "https://test-domain.com",
                "aud": ["test-audience"],
                "exp": now + 3600,
                "iat": now,
            }
        )
        token = generate_jwt_token(test_key, claims)

        try:
            with test_app.test_client() as client:
                response = client.get(
                    "/articles-by-email/1", headers={"Authorization": f"Bearer {token}"}
                )
                assert response.status_code == 200
        finally:
            # Restore original value
            ARTICLES_DB[1].user = original_user


class TestDictionaryObjects:
    """Test object ownership with dictionary objects."""

    def test_dict_object_ownership(self, test_app, test_key):
        """Test ownership check works with dictionary objects."""
        now = int(time.time())
        claims = json.dumps(
            {
                "sub": "user123",
                "iss": "https://test-domain.com",
                "aud": ["test-audience"],
                "exp": now + 3600,
                "iat": now,
            }
        )
        token = generate_jwt_token(test_key, claims)

        with test_app.test_client() as client:
            response = client.get(
                "/dict-objects/1", headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data["user"] == "user123"
