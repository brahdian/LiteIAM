from __future__ import annotations

import os
import uuid

import pytest

# Use a test-only SECRET_KEY so config validation passes without .env
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-unit-tests-min-32-chars!!")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/auth_engine_test")
os.environ.setdefault("BASE_URL", "http://localhost:8000")


@pytest.fixture
def tenant_id() -> uuid.UUID:
    return uuid.UUID("00000000-0000-0000-0000-000000000001")


@pytest.fixture
def user_id() -> uuid.UUID:
    return uuid.UUID("00000000-0000-0000-0000-000000000002")


@pytest.fixture(autouse=True)
def clear_inflight_tasks():
    """Clear inflight tasks before and after each test to ensure isolation."""
    from app.core.events import _inflight_tasks
    _inflight_tasks.clear()
    yield
    _inflight_tasks.clear()
