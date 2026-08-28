# archolith-oauth

Reusable OAuth 2.1 building blocks extracted from Menhir for Archolith services and remote MCP protected resources.

## Included

- RFC 9728 protected-resource and RFC 8414 authorization-server metadata
- Path-aware `.well-known` discovery for issuers/resources with URL paths
- Dynamic client registration for public PKCE clients
- Exact redirect, scope, and RFC 8707 resource validation
- Menhir-compatible SQLite client and single-use authorization-code stores
- Persistent RS256 signing keys with minimal active/previous-key rotation
- Access-token issuance and JWT/JWKS verification
- Opt-in `offline_access` with rotating, replay-detecting refresh tokens and
  encrypted durable exact-retry receipts for lost responses
- Prefixed environment settings, redacted diagnostics, and deployment preflight
- One-call construction with `OAuthRuntime.from_settings()`
- Signed consent-state primitives plus durable, atomic single-use consent
  registration and authorization-code issuance without prescribing a UI
- Declarative scope policy for routes and MCP tool catalog filtering
- Optional FastAPI routes and ASGI bearer middleware
- Node.js resource-server example using `jose`
- Dependency-free operator CLI for config, preflight, and key rotation

## Install

```bash
pip install archolith-oauth
```

For FastAPI routes and middleware:

```bash
pip install 'archolith-oauth[fastapi]'
```

## New-project quickstart

```python
from archolith_oauth import OAuthRuntime, OAuthSettings

settings = OAuthSettings.from_env("MYAPP_OAUTH_")
settings.preflight(require_consent_secret=True).raise_for_errors()
runtime = OAuthRuntime.from_settings(settings)
```

```text
MYAPP_OAUTH_ISSUER=https://auth.example.com/myapp
MYAPP_OAUTH_RESOURCE=https://api.example.com/mcp
MYAPP_OAUTH_SCOPES=myapp:read myapp:write myapp:admin
MYAPP_OAUTH_DEFAULT_SCOPES=myapp:read myapp:write
MYAPP_OAUTH_DATA_DIR=/var/lib/myapp/oauth
MYAPP_OAUTH_REFRESH_TOKENS_ENABLED=true
MYAPP_OAUTH_CONSENT_SECRET=<at-least-32-random-bytes>
```

Validate a deployment without printing secrets:

```bash
archolith-oauth --prefix MYAPP_OAUTH_ show-config --json
archolith-oauth --prefix MYAPP_OAUTH_ preflight --require-consent-secret
```

The same CLI is available as `python -m archolith_oauth`.

FastAPI protocol routes:

```python
from fastapi import FastAPI
from archolith_oauth.fastapi import create_protocol_router

app = FastAPI()
app.include_router(create_protocol_router(runtime))
```

Your application still owns login and the consent page. After approval, call
`authorize_and_redirect(...)` to validate the exact redirect, scope, PKCE, and
resource parameters and issue the authorization code.

## Scope policy

```python
from archolith_oauth import ScopePolicy, ScopeRequirement

policy = ScopePolicy({
    "list_sessions": "harness:read",
    "start_session": ("harness:read", "harness:session"),
    "delete_worktree": "harness:admin",
    "operate": ScopeRequirement(
        frozenset({"harness:session", "harness:admin"}),
        "any",
    ),
})

visible_tools = policy.filter_items(
    tools,
    principal.scopes,
    name=lambda tool: tool.name,
)
policy.require("start_session", principal.scopes)
```

Use the same policy for `tools/list` filtering and invocation enforcement.

## Consent state

`ConsentTokenManager` signs the exact authorization parameters shown to the
user. `ConsentNonceStore` atomically consumes each approval transaction so a
consent form cannot be replayed. `create_session()` can remember explicitly
approved client IDs without coupling the package to any login or HTML system.

## Signing-key rotation

The active private-key file remains a single JWK compatible with Menhir. On
rotation, only the retired public key is retained in a sibling file and exposed
through JWKS, allowing existing one-hour access tokens to finish naturally.
The default keeps one previous key:

```bash
archolith-oauth --prefix MYAPP_OAUTH_ rotate-key
```

Use `--retain-previous 0` to retire the old key immediately or a larger value
only when the access-token lifetime genuinely requires it. A running
`OAuthRuntime` can call `rotate_signing_key()` directly.

## Node resource servers

`examples/node/oauth-middleware.mjs` shows issuer, audience, JWKS, expiry, and
scope validation for the existing Node harness. The inbound bearer token must
never be forwarded into OpenCode, provider configuration, logs, or child-process
environments; only the verified principal is trusted.

## Protocol notes

The client must send the same canonical `resource` value in both the
authorization request and token request. Access tokens are audience-bound to
that resource. `offline_access` is advertised when refresh tokens are enabled
but is granted only when the client requests it.

For an issuer at `https://auth.example.com/harness` and resource at
`https://harness.example.com/mcp`, discovery URLs are:

- Authorization server: `https://auth.example.com/.well-known/oauth-authorization-server/harness`
- Protected resource: `https://harness.example.com/.well-known/oauth-protected-resource/mcp`

## Menhir adoption

Menhir keeps its existing settings adapter, consent screen, rate limits,
singleton wiring, and `menhir:*` scope-to-tier mapping. The package preserves
Menhir's current client database columns, client-store operations, keyword-based
authorization-code issuance, and active private-key file shape, so migration can
retain existing OAuth state. Refresh tokens remain disabled unless Menhir
explicitly enables them.

Menhir's authorize and token routes must begin requiring the same canonical
`resource` value before switching to this package; this is stricter than its
current implementation and is required by remote MCP authorization.

## Harness adoption

`cth.harness` remains Node.js. A small Python authorization service uses this
package to perform registration, consent, token issuance, and refresh rotation.
The Node MCP server validates the resulting JWT against the service's JWKS,
issuer, audience, and `harness:*` scopes.

Recommended scopes:

- `harness:read` — inspect sessions, output, status, and diffs
- `harness:session` — create and continue isolated sessions
- `harness:admin` — destructive session/worktree administration

Menhir and Harness should use separate authorization-server configurations and
resource audiences. They may share a host, but should use distinct issuer paths
or separate authorization-server deployments.
