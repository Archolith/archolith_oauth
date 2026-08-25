"""RFC 8414 and OAuth protected-resource metadata builders."""

from __future__ import annotations

from typing import Any

from .config import AuthorizationServerConfig, ResourceServerConfig


def protected_resource_metadata(config: ResourceServerConfig) -> dict[str, Any]:
    return {
        "resource": config.resource,
        "authorization_servers": list(config.authorization_servers),
        "scopes_supported": list(config.scopes_supported),
        "bearer_methods_supported": ["header"],
        "resource_name": config.resource_name,
    }


def authorization_server_metadata(config: AuthorizationServerConfig) -> dict[str, Any]:
    return {
        "issuer": config.issuer,
        "authorization_endpoint": config.authorization_endpoint,
        "token_endpoint": config.token_endpoint,
        "registration_endpoint": config.registration_endpoint,
        "jwks_uri": config.jwks_uri,
        "response_types_supported": ["code"],
        "grant_types_supported": list(config.grant_types_supported),
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": list(config.effective_scopes_supported),
        "protected_resources": [config.resource],
        "authorization_response_iss_parameter_supported": (
            config.authorization_response_iss_parameter_supported
        ),
        "client_id_metadata_document_supported": (
            config.client_id_metadata_document_supported
        ),
    }
