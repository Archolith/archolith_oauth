from __future__ import annotations

import json

import httpx
import pytest

from archolith_oauth import ClientMetadataError, resolve_client_metadata_document

DOCUMENT_URL = "https://chat.example.com/.well-known/oauth-client/menhir-client"


def _document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "client_id": DOCUMENT_URL,
        "client_name": "Menhir client",
        "redirect_uris": ["https://chat.example.com/callback"],
        "token_endpoint_auth_methods_supported": ["none"],
    }
    document.update(overrides)
    return document


def _transport(
    payload: bytes | str,
    *,
    status_code: int = 200,
    content_type: str = "application/json",
    redirect_to: str | None = None,
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if redirect_to is not None and request.url.path != "/final":
            return httpx.Response(
                302, headers={"Location": redirect_to}, content=b""
            )
        return httpx.Response(
            status_code,
            headers={"Content-Type": content_type},
            content=payload if isinstance(payload, bytes) else payload.encode(),
        )

    return httpx.MockTransport(handler)


async def _allow_all_dns(hostname: str) -> list[str]:
    return ["93.184.216.34"]


async def test_valid_document_round_trips():
    transport = _transport(json.dumps(_document()))
    document = await resolve_client_metadata_document(
        DOCUMENT_URL,
        dns_resolver=_allow_all_dns,
        transport=transport,
    )
    assert document["client_id"] == DOCUMENT_URL
    assert document["client_name"] == "Menhir client"


async def test_matching_connected_peer_is_accepted():
    async def dns(hostname: str) -> list[str]:
        return ["93.184.216.34"]

    def inspector(response: httpx.Response) -> tuple[str, int] | None:
        return ("93.184.216.34", 443)

    document = await resolve_client_metadata_document(
        DOCUMENT_URL,
        dns_resolver=dns,
        transport=_transport(json.dumps(_document())),
        peer_inspector=inspector,
    )
    assert document["client_id"] == DOCUMENT_URL


@pytest.mark.parametrize("peer", [("10.1.2.3", 443), ("203.0.113.7", 443)])
async def test_private_or_mismatched_connected_peer_is_rejected(
    peer: tuple[str, int],
):
    # DNS pre-resolves to a public address, but the connection is rebound to
    # a private or unrelated address.
    def inspector(response: httpx.Response) -> tuple[str, int] | None:
        return peer

    with pytest.raises(ClientMetadataError):
        await resolve_client_metadata_document(
            DOCUMENT_URL,
            dns_resolver=_allow_all_dns,
            transport=_transport(json.dumps(_document())),
            peer_inspector=inspector,
        )


async def test_rejects_non_https_url():
    with pytest.raises(ClientMetadataError):
        await resolve_client_metadata_document(
            DOCUMENT_URL.replace("https://", "http://"),
            dns_resolver=_allow_all_dns,
            transport=_transport("{}"),
        )


@pytest.mark.parametrize(
    "url",
    [
        "https://user:secret@chat.example.com/client.json",
        DOCUMENT_URL + "?tracked=1",
        DOCUMENT_URL + "#fragment",
        "https://chat.example.com/",
        "https://chat.example.com",
    ],
)
async def test_rejects_credentials_query_fragment_and_root(url: str):
    with pytest.raises(ClientMetadataError):
        await resolve_client_metadata_document(
            url,
            dns_resolver=_allow_all_dns,
            transport=_transport("{}"),
        )


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.5", "169.254.1.1", "::1", "fe80::1", "0.0.0.0"],
)
async def test_rejects_private_loopback_link_local_and_unspecified(address: str):
    async def hostile_dns(hostname: str) -> list[str]:
        return [address]

    with pytest.raises(ClientMetadataError):
        await resolve_client_metadata_document(
            DOCUMENT_URL,
            dns_resolver=hostile_dns,
            transport=_transport(json.dumps(_document())),
        )


async def test_rejects_redirect_response():
    transport = _transport(
        json.dumps(_document()),
        redirect_to="https://evil.example.com/final",
    )
    with pytest.raises(ClientMetadataError):
        await resolve_client_metadata_document(
            DOCUMENT_URL,
            dns_resolver=_allow_all_dns,
            transport=transport,
        )


async def test_rejects_oversize_body():
    big = b'{"pad":"' + b"a" * (600 * 1024) + b'"}'
    with pytest.raises(ClientMetadataError):
        await resolve_client_metadata_document(
            DOCUMENT_URL,
            dns_resolver=_allow_all_dns,
            transport=_transport(big),
            max_body_bytes=512 * 1024,
        )


async def test_rejects_wrong_content_type():
    with pytest.raises(ClientMetadataError):
        await resolve_client_metadata_document(
            DOCUMENT_URL,
            dns_resolver=_allow_all_dns,
            transport=_transport(json.dumps(_document()), content_type="text/html"),
        )


@pytest.mark.parametrize("status_code", [201, 403, 404, 500])
async def test_rejects_non_200_status(status_code: int):
    with pytest.raises(ClientMetadataError):
        await resolve_client_metadata_document(
            DOCUMENT_URL,
            dns_resolver=_allow_all_dns,
            transport=_transport("{}", status_code=status_code),
        )


async def test_rejects_identity_mismatch():
    transport = _transport(json.dumps(_document(client_id="https://other/cid")))
    with pytest.raises(ClientMetadataError):
        await resolve_client_metadata_document(
            DOCUMENT_URL,
            dns_resolver=_allow_all_dns,
            transport=transport,
        )


async def test_rejects_missing_none_auth_method():
    transport = _transport(
        json.dumps(_document(token_endpoint_auth_methods_supported=["private_key_jwt"]))
    )
    with pytest.raises(ClientMetadataError):
        await resolve_client_metadata_document(
            DOCUMENT_URL,
            dns_resolver=_allow_all_dns,
            transport=transport,
        )


async def test_rejects_invalid_redirect_uri():
    transport = _transport(
        json.dumps(
            _document(redirect_uris=["https://user:pw@chat.example.com/callback"])
        )
    )
    with pytest.raises(ClientMetadataError):
        await resolve_client_metadata_document(
            DOCUMENT_URL,
            dns_resolver=_allow_all_dns,
            transport=transport,
        )


async def test_rejects_non_object_and_invalid_json():
    for payload in ('["array"]', "not json"):
        with pytest.raises(ClientMetadataError):
            await resolve_client_metadata_document(
                DOCUMENT_URL,
                dns_resolver=_allow_all_dns,
                transport=_transport(payload),
            )
