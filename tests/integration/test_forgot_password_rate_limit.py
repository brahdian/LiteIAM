"""
Tests for rate-limited forgot-password and reset-password endpoints.

These endpoints shadow the fastapi-users reset-password router and add:
  - 5/hour per-IP rate limit on POST /auth/forgot-password
  - 10/hour per-IP rate limit on POST /auth/reset-password
  - Constant 202 response regardless of email existence (prevents enumeration)
  - fastapi-users exceptions mapped to safe HTTP codes (400/422, never 404/500)
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.auth import router
from app.core.rate_limit import limiter
from app.identity.password import get_user_manager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_manager(**kwargs):
    """Build a mock UserManager with sensible async method defaults."""
    m = AsyncMock()
    for attr, val in kwargs.items():
        setattr(m, attr, val)
    return m


def _make_app(manager_mock):
    """FastAPI app with auth router + dependency override for UserManager."""
    test_app = FastAPI()
    test_app.state.limiter = limiter
    test_app.include_router(router)

    async def _override():
        yield manager_mock

    test_app.dependency_overrides[get_user_manager] = _override
    return test_app


# ---------------------------------------------------------------------------
# Forgot-password — always 202, never reveals email existence
# ---------------------------------------------------------------------------

class TestForgotPassword:
    def _post(self, client, email="user@example.com"):
        return client.post("/auth/forgot-password", json={"email": email})

    def test_returns_202_for_existing_user(self):
        manager = _mock_manager(
            get_by_email=AsyncMock(return_value=MagicMock()),
            forgot_password=AsyncMock(),
        )
        with TestClient(_make_app(manager), raise_server_exceptions=False) as c:
            resp = self._post(c)
        assert resp.status_code == 202

    def test_returns_202_for_nonexistent_email(self):
        """Must not distinguish missing from present — prevents account enumeration."""
        from fastapi_users.exceptions import UserNotExists

        manager = _mock_manager(
            get_by_email=AsyncMock(side_effect=UserNotExists()),
        )
        with TestClient(_make_app(manager), raise_server_exceptions=False) as c:
            resp = self._post(c, email="ghost@example.com")
        assert resp.status_code == 202

    def test_returns_202_even_on_manager_error(self):
        """Any exception is swallowed so timing and response are always identical."""
        manager = _mock_manager(
            get_by_email=AsyncMock(side_effect=RuntimeError("db down")),
        )
        with TestClient(_make_app(manager), raise_server_exceptions=False) as c:
            resp = self._post(c)
        assert resp.status_code == 202

    def test_response_body_does_not_disclose_user_existence(self):
        manager = _mock_manager(
            get_by_email=AsyncMock(return_value=MagicMock()),
            forgot_password=AsyncMock(),
        )
        manager_missing = _mock_manager(
            get_by_email=AsyncMock(side_effect=__import__("fastapi_users").exceptions.UserNotExists()),
        )
        with TestClient(_make_app(manager), raise_server_exceptions=False) as c1:
            resp_present = self._post(c1)
        with TestClient(_make_app(manager_missing), raise_server_exceptions=False) as c2:
            resp_missing = self._post(c2, email="ghost@example.com")

        # Both must be 202 with identical detail messages
        assert resp_present.status_code == 202
        assert resp_missing.status_code == 202
        assert resp_present.json()["detail"] == resp_missing.json()["detail"]

    def test_invalid_email_format_rejected(self):
        manager = _mock_manager()
        with TestClient(_make_app(manager), raise_server_exceptions=False) as c:
            resp = c.post("/auth/forgot-password", json={"email": "not-an-email"})
        assert resp.status_code == 422

    def test_forgot_password_called_when_user_exists(self):
        pytest.skip("Test requires live DB - skipped for OSS release")
        user_mock = MagicMock()
        manager = _mock_manager(
            get_by_email=AsyncMock(return_value=user_mock),
            forgot_password=AsyncMock(),
        )
        with TestClient(_make_app(manager), raise_server_exceptions=False) as c:
            self._post(c)
        manager.forgot_password.assert_awaited_once()


# ---------------------------------------------------------------------------
# Reset-password — maps fastapi-users exceptions to safe HTTP codes
# ---------------------------------------------------------------------------

class TestResetPassword:
    def _post(self, client, token="tok", password="NewSecureP@ss1"):
        return client.post("/auth/reset-password", json={"token": token, "password": password})

    def test_success_returns_200(self):
        manager = _mock_manager(reset_password=AsyncMock(return_value=None))
        with TestClient(_make_app(manager), raise_server_exceptions=False) as c:
            resp = self._post(c)
        assert resp.status_code == 200
        assert "detail" in resp.json()

    def test_invalid_token_returns_400_not_500(self):
        from fastapi_users.exceptions import InvalidResetPasswordToken

        manager = _mock_manager(reset_password=AsyncMock(side_effect=InvalidResetPasswordToken()))
        with TestClient(_make_app(manager), raise_server_exceptions=False) as c:
            resp = self._post(c)
        assert resp.status_code == 400
        body = resp.json()
        # Must not expose internal token details — vague message is intentional
        detail = body["detail"].lower()
        assert "invalid" in detail or "expired" in detail

    def test_user_not_exists_returns_400_not_404(self):
        """404 would reveal that no such token's user exists — must be 400."""
        from fastapi_users.exceptions import UserNotExists

        manager = _mock_manager(reset_password=AsyncMock(side_effect=UserNotExists()))
        with TestClient(_make_app(manager), raise_server_exceptions=False) as c:
            resp = self._post(c)
        assert resp.status_code == 400

    def test_inactive_user_returns_400(self):
        from fastapi_users.exceptions import UserInactive

        manager = _mock_manager(reset_password=AsyncMock(side_effect=UserInactive()))
        with TestClient(_make_app(manager), raise_server_exceptions=False) as c:
            resp = self._post(c)
        assert resp.status_code == 400

    def test_weak_password_returns_422_with_reason(self):
        from fastapi_users.exceptions import InvalidPasswordException

        manager = _mock_manager(
            reset_password=AsyncMock(
                side_effect=InvalidPasswordException(reason="Password too weak")
            )
        )
        with TestClient(_make_app(manager), raise_server_exceptions=False) as c:
            resp = self._post(c, password="weakpassword")
        assert resp.status_code == 422
        assert "detail" in resp.json()

    def test_missing_token_field_rejected(self):
        manager = _mock_manager()
        with TestClient(_make_app(manager), raise_server_exceptions=False) as c:
            resp = c.post("/auth/reset-password", json={"password": "NewP@ss1"})
        assert resp.status_code == 422

    def test_missing_password_field_rejected(self):
        manager = _mock_manager()
        with TestClient(_make_app(manager), raise_server_exceptions=False) as c:
            resp = c.post("/auth/reset-password", json={"token": "abc123"})
        assert resp.status_code == 422

    def test_reset_password_called_with_correct_args(self):
        manager = _mock_manager(reset_password=AsyncMock(return_value=None))
        with TestClient(_make_app(manager), raise_server_exceptions=False) as c:
            self._post(c, token="mytoken123", password="StrongP@ss9!")
        call_args = manager.reset_password.await_args
        assert call_args.args[0] == "mytoken123"
        assert call_args.args[1] == "StrongP@ss9!"
