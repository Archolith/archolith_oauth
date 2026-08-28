"""SSRF-safe OAuth Client ID Metadata Document resolution."""

from __future__ import annotations

import asyncio
import ipaddress
import json
from typing import Any, Awaitable, Callable
from urllib.parse import SplitResult, urlsplit

import httpx

from .registration import ClientMetadataError, _valid_redirect_uri

DEFAULT_TIMEOUT_CONNECT_S = 5.0
DEFAULT_TIMEOUT_READ_S = 10.0
DEFAULT_MAX_BODY_BYTES = 512 * 1024

DnsResolver = Callable[[str], Awaitable[list[str]]]
PeerInspector = Callable[[httpx.Response], tuple[str, int] | None]


async def _system_dns_resolver(hostname: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(hostname, 443, type=1)
    return [info[4][0] for info in infos]


def _normalize_ip(address: str) -> str:
    return address.split("%", 1)[0].strip("[]")


def _default_peer_inspector(response: httpx.Response) -> tuple[str, int] | None:
    """Read the actually connected peer address from the httpcore stream."""
    network_stream = response.extensions.get("network_stream")
    if network_stream is None:
        return None
    try:
        peer = network_stream.get_extra_info("server_addr")
    except Exception:
        return None
    if not isinstance(peer, tuple) or len(peer) != 2:
        return None
    host, port = peer
    if not isinstance(host, str) or not isinstance(port, int):
        return None
    return _normalize_ip(host), port


def _reject_address(ip_text: str) -> str | None:
    try:
        address = ipaddress.ip_address(ip_text)
    except ValueError:
        return f"unparseable resolved address {ip_text!r}"
    if (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or not address.is_global
    ):
        return f"resolved address {ip_text} is not a public IP"
    return None


async def resolve_client_metadata_document(
    url: str,
    *,
    dns_resolver: DnsResolver | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    peer_inspector: PeerInspector | None = None,
    timeout_connect_s: float = DEFAULT_TIMEOUT_CONNECT_S,
    timeout_read_s: float = DEFAULT_TIMEOUT_READ_S,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> dict[str, Any]:
    """Fetch and validate a client's metadata document for CIMD client ids.

    Requires HTTPS on a non-root path without credentials, query, or
    fragment. DNS is resolved first and every resolved address must be a
    public, globally routable IP. Redirects are not followed and the body is
    size-bounded. The document must be a JSON object whose ``client_id``
    exactly matches the URL, advertise ``none`` among supported token
    endpoint auth methods, and carry valid redirect URIs.

    Against DNS rebinding, the connected peer address is re-checked against
    the prevalidated DNS answers. When no custom ``transport`` is injected
    (production), the peer must be verifiable via the network stream; a
    custom transport (test seam) skips peer verification unless
    ``peer_inspector`` is provided.
    """
    resolver = dns_resolver or _system_dns_resolver
    inspector = peer_inspector or _default_peer_inspector
    parsed = _validate_document_url(url)

    addresses = await resolver(parsed.hostname)
    if not addresses:
        raise ClientMetadataError(
            "invalid_client_metadata", "client metadata host did not resolve"
        )
    for address in addresses:
        rejection = _reject_address(address)
        if rejection:
            raise ClientMetadataError("invalid_client_metadata", rejection)
    validated_addresses = {_normalize_ip(address) for address in addresses}
    verify_peer = transport is None or peer_inspector is not None

    timeout = httpx.Timeout(timeout_read_s, connect=timeout_connect_s)
    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            transport=transport,
        ) as client:
            async with client.stream("GET", url) as response:
                if response.history:
                    raise ClientMetadataError(
                        "invalid_client_metadata",
                        "client metadata must be fetched without redirects",
                    )
                if verify_peer:
                    peer = inspector(response)
                    if peer is None:
                        raise ClientMetadataError(
                            "invalid_client_metadata",
                            "could not verify the connected peer address",
                        )
                    peer_ip = peer[0]
                    rejection = _reject_address(peer_ip)
                    if rejection:
                        raise ClientMetadataError("invalid_client_metadata", rejection)
                    if peer_ip not in validated_addresses:
                        raise ClientMetadataError(
                            "invalid_client_metadata",
                            "connected peer does not match the resolved addresses",
                        )
                if response.status_code != 200:
                    raise ClientMetadataError(
                        "invalid_client_metadata",
                        "client metadata document returned a non-200 status",
                    )
                content_type = response.headers.get("content-type", "")
                media_type = content_type.split(";")[0].strip().lower()
                if media_type != "application/json":
                    raise ClientMetadataError(
                        "invalid_client_metadata",
                        "client metadata document must be application/json",
                    )
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > max_body_bytes:
                        raise ClientMetadataError(
                            "invalid_client_metadata",
                            "client metadata document exceeds the size limit",
                        )
    except httpx.HTTPError as exc:
        raise ClientMetadataError(
            "invalid_client_metadata",
            "client metadata document could not be fetched",
        ) from exc

    try:
        document = json.loads(bytes(body))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ClientMetadataError(
            "invalid_client_metadata",
            "client metadata document is not valid JSON",
        ) from exc
    if not isinstance(document, dict):
        raise ClientMetadataError(
            "invalid_client_metadata",
            "client metadata document must be a JSON object",
        )

    if document.get("client_id") != url:
        raise ClientMetadataError(
            "invalid_client_metadata",
            "client_id does not exactly match the metadata URL",
        )
    auth_methods = document.get("token_endpoint_auth_methods_supported")
    if (
        not isinstance(auth_methods, list)
        or not all(isinstance(method, str) for method in auth_methods)
        or "none" not in auth_methods
    ):
        raise ClientMetadataError(
            "invalid_client_metadata",
            "client metadata must support the none token endpoint auth method",
        )
    redirect_uris = document.get("redirect_uris")
    if (
        not isinstance(redirect_uris, list)
        or not redirect_uris
        or not all(isinstance(uri, str) for uri in redirect_uris)
        or not all(_valid_redirect_uri(uri) for uri in redirect_uris)
    ):
        raise ClientMetadataError(
            "invalid_client_metadata",
            "client metadata redirect_uris are missing or invalid",
        )
    return document


def _validate_document_url(url: str) -> SplitResult:
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise ClientMetadataError(
            "invalid_client_metadata", "client id is not a valid URL"
        ) from exc
    if parsed.scheme != "https":
        raise ClientMetadataError(
            "invalid_client_metadata", "client metadata URL must use HTTPS"
        )
    if not parsed.hostname:
        raise ClientMetadataError(
            "invalid_client_metadata", "client metadata URL has no host"
        )
    if parsed.path in ("", "/"):
        raise ClientMetadataError(
            "invalid_client_metadata",
            "client metadata URL must have a non-root path",
        )
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ClientMetadataError(
            "invalid_client_metadata",
            "client metadata URL must not contain credentials, query, or fragment",
        )
    return parsed
