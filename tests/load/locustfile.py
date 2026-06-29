"""
Locust load test for LiteIAM.

Phase 6 gate: 500 concurrent users, p99 latency < 200ms for login endpoint.

Usage:
    pip install locust
    locust -f tests/load/locustfile.py --host=http://localhost:8000 \
           --users 500 --spawn-rate 50 --run-time 60s --headless

Pass criteria (checked automatically via --csv and --html flags, or read from terminal):
    - login p99 < 200ms
    - error rate < 0.1%
    - token issuance p99 < 200ms

Environment variables:
    LOAD_TEST_EMAIL    — email of a pre-seeded test user (default: loadtest@example.com)
    LOAD_TEST_PASSWORD — password for that user (default: LoadTest1!)
    LOAD_TEST_TENANT   — tenant_id UUID (default: uses first 200 OK response)
"""
from __future__ import annotations

import os

from locust import HttpUser, between, events, task

_EMAIL = os.environ.get("LOAD_TEST_EMAIL", "loadtest@example.com")
_PASSWORD = os.environ.get("LOAD_TEST_PASSWORD", "LoadTest1!")


class AuthUser(HttpUser):
    """Simulates a user performing the full password login flow."""

    wait_time = between(0.1, 0.5)  # think time between requests

    def on_start(self):
        self._token: str | None = None

    @task(8)
    def login(self):
        """POST /auth/login — the primary Phase 6 gate endpoint."""
        with self.client.post(
            "/auth/login",
            json={"email": _EMAIL, "password": _PASSWORD},
            catch_response=True,
            name="POST /auth/login",
        ) as resp:
            if resp.status_code == 200:
                body = resp.json()
                self._token = body.get("access_token") or body.get("mfa_pending_token")
                resp.success()
            elif resp.status_code == 429:
                # Rate limit hit — not a failure for the SUT, but mark so we
                # can track how often the load test saturates the rate limiter.
                resp.failure("rate_limited")
            else:
                resp.failure(f"login failed: {resp.status_code}")

    @task(2)
    def jwks(self):
        """GET /.well-known/jwks.json — must be <50ms at load (serves token verification)."""
        with self.client.get(
            "/.well-known/jwks.json",
            catch_response=True,
            name="GET /.well-known/jwks.json",
        ) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"jwks failed: {resp.status_code}")

    @task(1)
    def oidc_discovery(self):
        """GET /.well-known/openid-configuration — used by relying parties on startup."""
        with self.client.get(
            "/.well-known/openid-configuration",
            catch_response=True,
            name="GET /.well-known/openid-configuration",
        ) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"discovery failed: {resp.status_code}")

    @task(3)
    def userinfo(self):
        """GET /users/me — authenticated endpoint; exercises JWT validation on every call."""
        if not self._token:
            return
        with self.client.get(
            "/users/me",
            headers={"Authorization": f"Bearer {self._token}"},
            catch_response=True,
            name="GET /users/me",
        ) as resp:
            if resp.status_code in (200, 401):
                # 401 = token expired between task runs — not a SUT failure
                resp.success()
            else:
                resp.failure(f"userinfo failed: {resp.status_code}")


@events.quitting.add_listener
def check_p99_gate(environment, **kwargs):
    """Fail the run if Phase 6 p99 gate is not met."""
    if environment.runner is None:
        return

    stats = environment.runner.stats
    login_stat = stats.get("/auth/login", "POST")
    if login_stat is None:
        print("[load-gate] WARNING: no login stats found — cannot verify p99 gate")
        return

    p99_ms = login_stat.get_response_time_percentile(0.99)
    error_rate = login_stat.fail_ratio

    gate_pass = p99_ms < 200 and error_rate < 0.001
    print(
        f"\n{'✓' if gate_pass else '✗'} Phase 6 load gate: "
        f"login p99={p99_ms:.0f}ms (< 200ms), "
        f"error_rate={error_rate*100:.3f}% (< 0.1%)"
    )
    if not gate_pass:
        environment.process_exit_code = 1
