from __future__ import annotations

"""Canonical ownership and policy for outbound HTTP clients."""

import asyncio
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class TransportProfile:
    """Connection-pool, deadline, and retry policy for one traffic class."""

    timeout_seconds: float
    connect_timeout_seconds: float = 5.0
    max_connections: int = 100
    max_keepalive_connections: int = 20
    keepalive_expiry_seconds: float = 30.0
    max_attempts: int = 1
    retry_statuses: frozenset[int] = frozenset({408, 429, 502, 503, 504})

    def timeout(self) -> httpx.Timeout:
        return httpx.Timeout(
            self.timeout_seconds,
            connect=self.connect_timeout_seconds,
        )

    def limits(self) -> httpx.Limits:
        return httpx.Limits(
            max_connections=self.max_connections,
            max_keepalive_connections=self.max_keepalive_connections,
            keepalive_expiry=self.keepalive_expiry_seconds,
        )


DEFAULT_TRANSPORT_PROFILES: Mapping[str, TransportProfile] = {
    "identity": TransportProfile(15.0, max_attempts=2),
    "billing": TransportProfile(30.0, max_attempts=2),
    "provider-short": TransportProfile(15.0, max_attempts=3),
    "provider-long": TransportProfile(
        900.0,
        connect_timeout_seconds=10.0,
        max_connections=40,
        max_keepalive_connections=10,
    ),
    "internal": TransportProfile(
        60.0,
        max_connections=200,
        max_keepalive_connections=50,
        max_attempts=2,
    ),
}

_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})


class OutboundClientRegistry:
    """Own all outbound pools for one service process."""

    def __init__(
        self,
        service_name: str,
        profiles: Mapping[str, TransportProfile] | None = None,
    ) -> None:
        self.service_name = service_name
        self._profiles = dict(DEFAULT_TRANSPORT_PROFILES)
        if profiles:
            self._profiles.update(profiles)
        self._clients: dict[str, httpx.AsyncClient] = {}
        self._closed = False

    def profile(self, name: str) -> TransportProfile:
        try:
            return self._profiles[name]
        except KeyError as exc:
            raise KeyError(f"Unknown outbound transport profile: {name}") from exc

    def get(
        self,
        profile: str = "internal",
        *,
        name: str | None = None,
        base_url: str = "",
        headers: Mapping[str, str] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        transport_factory: Callable[[], httpx.AsyncBaseTransport] | None = None,
        timeout: httpx.Timeout | float | None = None,
    ) -> httpx.AsyncClient:
        if self._closed:
            raise RuntimeError("OutboundClientRegistry is closed")

        client_name = name or profile
        existing = self._clients.get(client_name)
        if existing is not None and not getattr(existing, "is_closed", False):
            return existing

        policy = self.profile(profile)
        kwargs: dict[str, Any] = {
            "timeout": timeout or policy.timeout(),
            "limits": policy.limits(),
        }
        if base_url:
            kwargs["base_url"] = base_url
        if headers:
            kwargs["headers"] = dict(headers)
        selected_transport = transport
        if selected_transport is None and transport_factory is not None:
            selected_transport = transport_factory()
        if selected_transport is not None:
            kwargs["transport"] = selected_transport

        client = httpx.AsyncClient(**kwargs)
        self._clients[client_name] = client
        return client

    async def request(
        self,
        profile: str,
        method: str,
        url: str,
        *,
        client_name: str | None = None,
        idempotent: bool | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Execute with bounded retries only when replay is safe."""
        policy = self.profile(profile)
        method_upper = method.upper()
        may_retry = (
            method_upper in _IDEMPOTENT_METHODS
            if idempotent is None
            else idempotent
        )
        attempts = policy.max_attempts if may_retry else 1
        client = self.get(profile, name=client_name)

        for attempt in range(1, attempts + 1):
            try:
                response = await client.request(method_upper, url, **kwargs)
                if (
                    attempt < attempts
                    and response.status_code in policy.retry_statuses
                ):
                    await asyncio.sleep(min(0.1 * (2 ** (attempt - 1)), 1.0))
                    continue
                return response
            except (
                httpx.ConnectError,
                httpx.RemoteProtocolError,
                httpx.TimeoutException,
            ):
                if attempt >= attempts:
                    raise
                await asyncio.sleep(min(0.1 * (2 ** (attempt - 1)), 1.0))

        raise RuntimeError("outbound request retry loop exhausted")

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        clients = list(self._clients.values())
        self._clients.clear()
        if clients:
            await asyncio.gather(
                *(client.aclose() for client in clients if not client.is_closed),
                return_exceptions=True,
            )


_PROCESS_REGISTRY = OutboundClientRegistry("process")


def process_outbound_clients() -> OutboundClientRegistry:
    return _PROCESS_REGISTRY


def install_outbound_clients(
    app: Any,
    service_name: str,
    *,
    profiles: Mapping[str, TransportProfile] | None = None,
) -> OutboundClientRegistry:
    """Attach a service-owned registry and make it the process default."""
    global _PROCESS_REGISTRY
    registry = OutboundClientRegistry(service_name, profiles=profiles)
    app.state.outbound_clients = registry
    _PROCESS_REGISTRY = registry
    return registry


def get_outbound_client(
    profile: str = "internal",
    *,
    registry: OutboundClientRegistry | None = None,
    **kwargs: Any,
) -> httpx.AsyncClient:
    return (registry or process_outbound_clients()).get(profile, **kwargs)
