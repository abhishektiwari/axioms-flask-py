"""Example Flask application demonstrating Axioms authentication and authorization.

This example app demonstrates:
- Public endpoints
- Authentication-only endpoints
- Scope-based authorization (OR and AND logic)
- Role-based authorization (OR and AND logic)
- Permission-based authorization
- Mixed authorization (combining scopes, roles, and permissions)
- Object-level permissions (row-level security)
- Custom owner field names

Run with: flask run
Or: python app.py
"""

import os

from flask import Flask, abort, g, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from axioms_flask import (
    check_object_ownership,
    has_required_permissions,
    has_required_roles,
    has_required_scopes,
    has_valid_access_token,
    init_axioms,
    register_axioms_error_handler,
    setup_token_middleware,
)


# Database setup
class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)


# Database Models
class Article(db.Model):
    """Article model with default 'user' owner field."""

    __tablename__ = "article"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    content: Mapped[str] = mapped_column(String(2000))
    user: Mapped[str] = mapped_column(
        String(100), index=True
    )  # Matches JWT 'sub' claim


class Comment(db.Model):
    """Comment model with custom 'created_by' owner field."""

    __tablename__ = "comment"

    id: Mapped[int] = mapped_column(primary_key=True)
    article_id: Mapped[int] = mapped_column()
    text: Mapped[str] = mapped_column(String(500))
    created_by: Mapped[str] = mapped_column(
        String(100), index=True
    )  # Custom owner field name


# Flask app
app = Flask(__name__)

# Database Configuration
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///test.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Axioms Configuration
app.config["AXIOMS_AUDIENCE"] = os.getenv("AXIOMS_AUDIENCE", "https://api.example.com")
app.config["AXIOMS_ISS_URL"] = os.getenv("AXIOMS_ISS_URL", "https://jwtforge.dev")
app.config["AXIOMS_JWKS_URL"] = os.getenv(
    "AXIOMS_JWKS_URL", "https://jwtforge.dev/.well-known/jwks.json"
)

# Initialize extensions
db.init_app(app)

# Initialize Axioms
init_axioms(app)
setup_token_middleware(app)
register_axioms_error_handler(app)

# Create tables
with app.app_context():
    db.create_all()


#
# === PUBLIC ENDPOINTS ===
#


@app.route("/")
def root():
    """Welcome endpoint."""
    return jsonify(
        {
            "message": "Welcome to Axioms Flask Example API",
            "docs": "See README.md for endpoint documentation",
        }
    )


@app.route("/health")
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy"})


#
# === AUTHENTICATION ONLY ===
#


@app.route("/protected")
@has_valid_access_token
def protected():
    """Protected endpoint - requires authentication only."""
    return jsonify({"message": "This is a protected endpoint"})


@app.route("/me")
@has_valid_access_token
def me():
    """User profile endpoint - returns JWT claims."""
    return jsonify(dict(g.auth_jwt))


#
# === SCOPE-BASED AUTHORIZATION ===
#


@app.route("/api/read")
@has_valid_access_token
@has_required_scopes("read:data", "admin")  # OR logic
def read_data():
    """Requires 'read:data' OR 'admin' scope."""
    return jsonify({"message": "Read data endpoint", "data": [1, 2, 3]})


@app.route("/api/write")
@has_valid_access_token
@has_required_scopes("write:data")  # AND logic via chaining
@has_required_scopes("openid")
def write_data():
    """Requires 'write:data' AND 'openid' scopes (chained decorators)."""
    return jsonify({"message": "Write data endpoint", "success": True})


#
# === ROLE-BASED AUTHORIZATION ===
#


@app.route("/admin/users")
@has_valid_access_token
@has_required_roles("admin", "superuser")  # OR logic
def admin_users():
    """Requires 'admin' OR 'superuser' role."""
    return jsonify({"message": "Admin users endpoint", "users": []})


@app.route("/admin/users/<user_id>", methods=["DELETE"])
@has_valid_access_token
@has_required_roles("admin")  # AND logic via chaining
@has_required_roles("superuser")
def delete_user(user_id):
    """Requires 'admin' AND 'superuser' roles (chained decorators)."""
    return jsonify({"message": f"User {user_id} deleted", "success": True})


#
# === PERMISSION-BASED AUTHORIZATION ===
#


@app.route("/api/resource", methods=["POST"])
@has_valid_access_token
@has_required_permissions("resource:create")
def create_resource():
    """Requires 'resource:create' permission."""
    return jsonify({"message": "Resource created", "id": 123})


#
# === MIXED AUTHORIZATION ===
#


@app.route("/api/strict")
@has_valid_access_token
@has_required_scopes("openid", "profile")  # Requires ONE of these
@has_required_roles("editor")  # AND this role
@has_required_permissions("resource:write")  # AND this permission
def strict_endpoint():
    """Requires (openid OR profile) AND editor AND resource:write."""
    return jsonify({"message": "Strict endpoint accessed", "data": "sensitive"})


#
# === OBJECT-LEVEL PERMISSIONS (ARTICLES) ===
#


def get_article(article_id: int) -> Article:
    """Get article by ID or 404."""
    article = db.session.get(Article, article_id)
    if not article:
        abort(404, description="Article not found")
    return article


@app.route("/articles", methods=["GET"])
@has_valid_access_token
def list_articles():
    """List all articles (authenticated users only)."""
    articles = db.session.query(Article).all()
    return jsonify(
        {"articles": [{"id": a.id, "title": a.title, "user": a.user} for a in articles]}
    )


@app.route("/articles", methods=["POST"])
@has_valid_access_token
def create_article():
    """Create article (sets user from token.sub)."""
    data = request.get_json()
    user_id = g.auth_jwt.sub  # From middleware

    article = Article(
        title=data.get("title"),
        content=data.get("content"),
        user=user_id,  # Owner is authenticated user
    )
    db.session.add(article)
    db.session.commit()
    db.session.refresh(article)
    return (
        jsonify({"id": article.id, "title": article.title, "user": article.user}),
        201,
    )


@app.route("/articles/<int:article_id>", methods=["GET"])
@check_object_ownership(get_article, inject_as="article")
def get_article_route(article_id: int, article: Article):
    """Get article - owner only."""
    return jsonify(
        {"id": article.id, "title": article.title, "content": article.content}
    )


@app.route("/articles/<int:article_id>", methods=["PATCH"])
@check_object_ownership(get_article, inject_as="article")
def update_article(article_id: int, article: Article):
    """Update article - owner only."""
    data = request.get_json()

    article.title = data.get("title", article.title)
    article.content = data.get("content", article.content)
    db.session.add(article)
    db.session.commit()
    db.session.refresh(article)
    return jsonify({"id": article.id, "title": article.title})


@app.route("/articles/<int:article_id>", methods=["DELETE"])
@check_object_ownership(get_article, inject_as="article")
def delete_article(article_id: int, article: Article):
    """Delete article - owner only."""
    db.session.delete(article)
    db.session.commit()
    return jsonify({"message": "Article deleted", "id": article_id})


#
# === OBJECT-LEVEL PERMISSIONS (COMMENTS WITH CUSTOM OWNER FIELD) ===
#


def get_comment(comment_id: int) -> Comment:
    """Get comment by ID or 404."""
    comment = db.session.get(Comment, comment_id)
    if not comment:
        abort(404, description="Comment not found")
    return comment


@app.route("/articles/<int:article_id>/comments", methods=["POST"])
@has_valid_access_token
def create_comment(article_id: int):
    """Create comment (sets created_by from token.sub)."""
    data = request.get_json()
    user_id = g.auth_jwt.sub

    comment = Comment(
        article_id=article_id,
        text=data.get("text"),
        created_by=user_id,  # Custom owner field
    )
    db.session.add(comment)
    db.session.commit()
    db.session.refresh(comment)
    return (
        jsonify(
            {"id": comment.id, "text": comment.text, "created_by": comment.created_by}
        ),
        201,
    )


@app.route("/comments/<int:comment_id>", methods=["PATCH"])
@check_object_ownership(
    get_comment, owner_field="created_by", inject_as="comment"
)  # Custom field
def update_comment(comment_id: int, comment: Comment):
    """Update comment - creator only (uses created_by field)."""
    data = request.get_json()

    comment.text = data.get("text", comment.text)
    db.session.add(comment)
    db.session.commit()
    db.session.refresh(comment)
    return jsonify({"id": comment.id, "text": comment.text})


@app.route("/comments/<int:comment_id>", methods=["DELETE"])
@check_object_ownership(get_comment, owner_field="created_by", inject_as="comment")
def delete_comment(comment_id: int, comment: Comment):
    """Delete comment - creator only (uses created_by field)."""
    db.session.delete(comment)
    db.session.commit()
    return jsonify({"message": "Comment deleted", "id": comment_id})


if __name__ == "__main__":
    app.run(debug=True, port=8000)
