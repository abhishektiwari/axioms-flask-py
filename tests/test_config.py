"""Tests for axioms_flask.config module."""

from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from axioms_flask.config import _AXIOMS_CONFIG_KEY, get_config, init_axioms, shutdown_axioms


class TestInitAxioms:
    """Test init_axioms function."""

    def test_init_axioms_from_app_config(self, mock_jwks_data):
        """Test initializing Axioms from Flask app.config."""
        app = Flask(__name__)
        app.config["AXIOMS_AUDIENCE"] = "test-audience"
        app.config["AXIOMS_ISS_URL"] = "https://auth.example.com"
        app.config["AXIOMS_JWKS_URL"] = "https://auth.example.com/.well-known/jwks.json"

        with patch("axioms_flask.config.initialize_jwks_manager") as mock_init_jwks:
            config = init_axioms(app)

            # Verify AxiomsConfig was created correctly
            assert config.AXIOMS_AUDIENCE == "test-audience"
            assert config.AXIOMS_ISS_URL == "https://auth.example.com"
            assert (
                config.AXIOMS_JWKS_URL
                == "https://auth.example.com/.well-known/jwks.json"
            )

            # Verify config was stored in app.config
            assert _AXIOMS_CONFIG_KEY in app.config
            assert app.config[_AXIOMS_CONFIG_KEY] is config

            # Verify JWKS manager was initialized
            mock_init_jwks.assert_called_once()
            call_kwargs = mock_init_jwks.call_args[1]
            assert call_kwargs["config"] is config
            assert call_kwargs["refresh_interval"] == config.AXIOMS_JWKS_REFRESH_INTERVAL
            assert call_kwargs["cache_ttl"] == config.AXIOMS_JWKS_CACHE_TTL
            assert call_kwargs["prefetch"] == config.AXIOMS_JWKS_PREFETCH

    def test_init_axioms_with_kwargs_override(self, mock_jwks_data):
        """Test initializing Axioms with kwargs overriding app.config."""
        app = Flask(__name__)
        app.config["AXIOMS_AUDIENCE"] = "app-config-audience"
        app.config["AXIOMS_ISS_URL"] = "https://app-config.example.com"

        with patch("axioms_flask.config.initialize_jwks_manager"):
            config = init_axioms(
                app,
                AXIOMS_AUDIENCE="kwargs-audience",
                AXIOMS_JWKS_URL="https://kwargs.example.com/.well-known/jwks.json",
                AXIOMS_JWKS_REFRESH_INTERVAL=1800,
            )

            # Verify kwargs override app.config
            assert config.AXIOMS_AUDIENCE == "kwargs-audience"
            assert (
                config.AXIOMS_JWKS_URL
                == "https://kwargs.example.com/.well-known/jwks.json"
            )
            assert config.AXIOMS_JWKS_REFRESH_INTERVAL == 1800

            # Verify app.config value used when not in kwargs
            assert config.AXIOMS_ISS_URL == "https://app-config.example.com"

    def test_init_axioms_with_domain(self, mock_jwks_data):
        """Test initializing Axioms with AXIOMS_DOMAIN."""
        app = Flask(__name__)
        app.config["AXIOMS_AUDIENCE"] = "test-audience"
        app.config["AXIOMS_DOMAIN"] = "auth.example.com"

        with patch("axioms_flask.config.initialize_jwks_manager"):
            config = init_axioms(app)

            # Verify domain was set
            assert config.AXIOMS_DOMAIN == "auth.example.com"
            # AXIOMS_ISS_URL and AXIOMS_JWKS_URL are constructed by helper functions
            # when needed, not during initialization
            assert config.AXIOMS_ISS_URL is None
            assert config.AXIOMS_JWKS_URL is None

    def test_init_axioms_with_custom_claims(self, mock_jwks_data):
        """Test initializing Axioms with custom claim names."""
        app = Flask(__name__)
        app.config["AXIOMS_AUDIENCE"] = "test-audience"
        app.config["AXIOMS_ISS_URL"] = "https://auth.example.com"
        app.config["AXIOMS_SCOPE_CLAIMS"] = ["scope", "scp"]
        app.config["AXIOMS_ROLES_CLAIMS"] = ["roles", "cognito:groups"]
        app.config["AXIOMS_PERMISSIONS_CLAIMS"] = ["permissions", "perms"]

        with patch("axioms_flask.config.initialize_jwks_manager"):
            config = init_axioms(app)

            # Verify custom claim names
            assert config.AXIOMS_SCOPE_CLAIMS == ["scope", "scp"]
            assert config.AXIOMS_ROLES_CLAIMS == ["roles", "cognito:groups"]
            assert config.AXIOMS_PERMISSIONS_CLAIMS == ["permissions", "perms"]

    def test_init_axioms_with_token_typs(self, mock_jwks_data):
        """Test initializing Axioms with custom token types."""
        app = Flask(__name__)
        app.config["AXIOMS_AUDIENCE"] = "test-audience"
        app.config["AXIOMS_ISS_URL"] = "https://auth.example.com"
        app.config["AXIOMS_TOKEN_TYPS"] = ["JWT", "at+jwt"]

        with patch("axioms_flask.config.initialize_jwks_manager"):
            config = init_axioms(app)

            # Verify custom token types
            assert config.AXIOMS_TOKEN_TYPS == ["JWT", "at+jwt"]

    def test_init_axioms_with_jwks_settings(self, mock_jwks_data):
        """Test initializing Axioms with custom JWKS settings."""
        app = Flask(__name__)
        app.config["AXIOMS_AUDIENCE"] = "test-audience"
        app.config["AXIOMS_ISS_URL"] = "https://auth.example.com"
        app.config["AXIOMS_JWKS_REFRESH_INTERVAL"] = 1800
        app.config["AXIOMS_JWKS_CACHE_TTL"] = 3600
        app.config["AXIOMS_JWKS_PREFETCH"] = False

        with patch("axioms_flask.config.initialize_jwks_manager") as mock_init_jwks:
            config = init_axioms(app)

            # Verify JWKS settings
            assert config.AXIOMS_JWKS_REFRESH_INTERVAL == 1800
            assert config.AXIOMS_JWKS_CACHE_TTL == 3600
            assert config.AXIOMS_JWKS_PREFETCH is False

            # Verify JWKS manager was initialized with these settings
            call_kwargs = mock_init_jwks.call_args[1]
            assert call_kwargs["refresh_interval"] == 1800
            assert call_kwargs["cache_ttl"] == 3600
            assert call_kwargs["prefetch"] is False

    def test_init_axioms_logging(self, mock_jwks_data, caplog):
        """Test that init_axioms logs initialization."""
        import logging

        app = Flask(__name__)
        app.config["AXIOMS_AUDIENCE"] = "test-audience"
        app.config["AXIOMS_ISS_URL"] = "https://auth.example.com"

        with patch("axioms_flask.config.initialize_jwks_manager"):
            with caplog.at_level(logging.INFO):
                config = init_axioms(app)

                # Verify logging
                assert "Axioms initialized for Flask app" in caplog.text
                assert "refresh_interval=3600s" in caplog.text
                assert "cache_ttl=7200s" in caplog.text


class TestGetConfig:
    """Test get_config function."""

    def test_get_config_with_init_axioms(self, mock_jwks_data):
        """Test get_config returns AxiomsConfig instance when init_axioms was called."""
        app = Flask(__name__)
        app.config["AXIOMS_AUDIENCE"] = "test-audience"
        app.config["AXIOMS_ISS_URL"] = "https://auth.example.com"

        with patch("axioms_flask.config.initialize_jwks_manager"):
            config = init_axioms(app)

            with app.app_context():
                retrieved_config = get_config()

                # Should return the AxiomsConfig instance
                assert retrieved_config is config
                assert hasattr(retrieved_config, "AXIOMS_AUDIENCE")
                assert retrieved_config.AXIOMS_AUDIENCE == "test-audience"

    def test_get_config_without_init_axioms(self):
        """Test get_config returns app.config dict when init_axioms was not called."""
        app = Flask(__name__)
        app.config["AXIOMS_AUDIENCE"] = "test-audience"
        app.config["AXIOMS_ISS_URL"] = "https://auth.example.com"

        with app.app_context():
            retrieved_config = get_config()

            # Should return Flask app.config dict
            assert retrieved_config is app.config
            assert retrieved_config["AXIOMS_AUDIENCE"] == "test-audience"

    def test_get_config_no_flask_context(self, caplog):
        """Test get_config returns None when no Flask context."""
        import logging

        with caplog.at_level(logging.DEBUG):
            config = get_config()

            # Should return None
            assert config is None

            # Should log debug message
            assert "No Flask application context available" in caplog.text

    def test_get_config_attribute_access(self, mock_jwks_data):
        """Test accessing config attributes from get_config."""
        app = Flask(__name__)
        app.config["AXIOMS_AUDIENCE"] = "test-audience"
        app.config["AXIOMS_ISS_URL"] = "https://auth.example.com"

        with patch("axioms_flask.config.initialize_jwks_manager"):
            init_axioms(app)

            with app.app_context():
                config = get_config()

                # Test attribute access (AxiomsConfig object)
                assert config.AXIOMS_AUDIENCE == "test-audience"

    def test_get_config_dict_access(self):
        """Test accessing config as dict from get_config."""
        app = Flask(__name__)
        app.config["AXIOMS_AUDIENCE"] = "test-audience"
        app.config["AXIOMS_ISS_URL"] = "https://auth.example.com"

        with app.app_context():
            config = get_config()

            # Test dict access (Flask config dict)
            assert config.get("AXIOMS_AUDIENCE") == "test-audience"
            assert config["AXIOMS_ISS_URL"] == "https://auth.example.com"


class TestShutdownAxioms:
    """Test shutdown_axioms function."""

    def test_shutdown_axioms(self, caplog):
        """Test shutdown_axioms calls shutdown_jwks_manager and logs."""
        import logging

        with patch("axioms_flask.config.shutdown_jwks_manager") as mock_shutdown:
            with caplog.at_level(logging.INFO):
                shutdown_axioms()

                # Verify shutdown_jwks_manager was called
                mock_shutdown.assert_called_once()

                # Verify logging
                assert "Axioms JWKS manager shutdown" in caplog.text

    def test_shutdown_axioms_idempotent(self):
        """Test shutdown_axioms can be called multiple times."""
        with patch("axioms_flask.config.shutdown_jwks_manager") as mock_shutdown:
            shutdown_axioms()
            shutdown_axioms()

            # Should be called twice
            assert mock_shutdown.call_count == 2


class TestConfigIntegration:
    """Integration tests for config module."""

    def test_full_lifecycle(self, mock_jwks_data):
        """Test full init -> get -> shutdown lifecycle."""
        app = Flask(__name__)
        app.config["AXIOMS_AUDIENCE"] = "test-audience"
        app.config["AXIOMS_ISS_URL"] = "https://auth.example.com"

        with patch("axioms_flask.config.initialize_jwks_manager"):
            with patch("axioms_flask.config.shutdown_jwks_manager"):
                # Initialize
                config = init_axioms(app)
                assert config is not None

                # Get config within context
                with app.app_context():
                    retrieved_config = get_config()
                    assert retrieved_config is config

                # Shutdown
                shutdown_axioms()

    def test_multiple_apps(self, mock_jwks_data):
        """Test that different Flask apps can have different configs."""
        app1 = Flask("app1")
        app1.config["AXIOMS_AUDIENCE"] = "app1-audience"
        app1.config["AXIOMS_ISS_URL"] = "https://app1.example.com"

        app2 = Flask("app2")
        app2.config["AXIOMS_AUDIENCE"] = "app2-audience"
        app2.config["AXIOMS_ISS_URL"] = "https://app2.example.com"

        with patch("axioms_flask.config.initialize_jwks_manager"):
            config1 = init_axioms(app1)
            config2 = init_axioms(app2)

            # Verify configs are different
            assert config1.AXIOMS_AUDIENCE == "app1-audience"
            assert config2.AXIOMS_AUDIENCE == "app2-audience"

            # Verify get_config returns correct config for each app
            with app1.app_context():
                assert get_config().AXIOMS_AUDIENCE == "app1-audience"

            with app2.app_context():
                assert get_config().AXIOMS_AUDIENCE == "app2-audience"
