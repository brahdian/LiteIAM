"""
Unit tests for the HIBP k-anonymity breach check.

All tests mock httpx to avoid real network calls. They verify:
- A breached password raises InvalidPasswordException with count in message
- An un-breached password passes silently
- Network errors are swallowed (fail-open)
- Only the first 5 SHA1 hex chars are sent to HIBP (k-anonymity property)
"""
from __future__ import annotations

import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi_users.exceptions import InvalidPasswordException


def _sha1_parts(password: str):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    return sha1[:5], sha1[5:]


def _make_hibp_response(suffix: str, count: int = 0, extra: list | None = None):
    """Build a fake HIBP range response body."""
    lines = ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0"]  # decoy
    if count > 0:
        lines.append(f"{suffix}:{count}")
    if extra:
        lines.extend(extra)
    resp = MagicMock()
    resp.status_code = 200
    resp.text = "\n".join(lines)
    return resp


@pytest.mark.asyncio
async def test_hibp_rejects_breached_password():
    """Password in HIBP with count > 0 must raise InvalidPasswordException."""
    from app.identity.password import _check_hibp

    pw = "password123A!"
    _, suffix = _sha1_parts(pw)
    resp = _make_hibp_response(suffix, count=9999)

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=resp)

    with patch("httpx.AsyncClient", return_value=mock_client):
        with pytest.raises(InvalidPasswordException) as exc_info:
            await _check_hibp(pw)
    assert "9,999" in exc_info.value.reason
    assert "breaches" in exc_info.value.reason.lower()


@pytest.mark.asyncio
async def test_hibp_allows_clean_password():
    """Password NOT in HIBP response must not raise."""
    from app.identity.password import _check_hibp

    pw = "Xk9#mQ2!vLp3$nW8"
    _, suffix = _sha1_parts(pw)
    # Response contains only unrelated suffixes
    resp = MagicMock()
    resp.status_code = 200
    resp.text = "0000000000000000000000000000000000000:1\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:2"

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=resp)

    with patch("httpx.AsyncClient", return_value=mock_client):
        await _check_hibp(pw)  # must not raise


@pytest.mark.asyncio
async def test_hibp_fail_open_on_network_error():
    """Connection errors must be swallowed — never block the user."""
    from app.identity.password import _check_hibp

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(side_effect=ConnectionError("HIBP down"))

    with patch("httpx.AsyncClient", return_value=mock_client):
        await _check_hibp("AnyP@ss1!")  # must not raise


@pytest.mark.asyncio
async def test_hibp_fail_open_on_non_200():
    """Non-200 HIBP response must be treated as unavailable (fail-open)."""
    from app.identity.password import _check_hibp

    resp = MagicMock()
    resp.status_code = 503

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=resp)

    with patch("httpx.AsyncClient", return_value=mock_client):
        await _check_hibp("AnyP@ss1!")  # must not raise


@pytest.mark.asyncio
async def test_hibp_only_sends_prefix():
    """k-anonymity: only the first 5 SHA1 chars must appear in the HIBP request URL."""
    from app.identity.password import _check_hibp

    pw = "Unique!P@ss9"
    prefix, _ = _sha1_parts(pw)

    captured_urls: list[str] = []

    resp = MagicMock()
    resp.status_code = 200
    resp.text = ""

    async def capture_get(url, **kwargs):
        captured_urls.append(url)
        return resp

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = capture_get

    with patch("httpx.AsyncClient", return_value=mock_client):
        await _check_hibp(pw)

    assert len(captured_urls) == 1
    assert captured_urls[0].endswith(prefix), (
        f"Expected URL to end with SHA1 prefix {prefix!r}, got {captured_urls[0]!r}"
    )
    assert len(captured_urls[0].split("/")[-1]) == 5, "Only 5 hex chars should be in the URL path"
