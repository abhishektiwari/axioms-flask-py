"""Shared test fixtures for axioms-flask-py tests."""

import json

import pytest
from jwcrypto import jwk


@pytest.fixture
def test_key():
    """Generate RSA key pair for JWT signing and verification."""
    key = jwk.JWK.generate(kty="RSA", size=2048, kid="test-key-id")
    return key


@pytest.fixture
def mock_jwks_data(test_key):
    """Generate mock JWKS data for testing."""
    public_key = test_key.export_public(as_dict=True)
    jwks = {"keys": [public_key]}
    return json.dumps(jwks).encode("utf-8")
