# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-05-29

Security-hardening release. Closes four OAuth correctness bugs and adds the
resource-server half of the MCP authorization spec.

### Security (breaking where noted)
- **Authorization endpoint now validates `redirect_uri`** against the client's
  registered URIs (RFC 6749 §3.1.2.3) and rejects unknown `client_id`s. An
  unregistered/mismatched `redirect_uri` is answered with an error and is never
  redirected to. **Breaking:** flows that relied on unvalidated redirect URIs
  will now be rejected — register every redirect URI.
- **Access-token revocation now takes effect.** `validate_access_token` checks
  that the stored token row still exists, so `POST /oauth/revoke` and an
  expired/destroyed row immediately invalidate the JWT instead of it remaining
  valid until natural expiry. Introspection reflects this too.
- **Token endpoint binds the authorization code to the client** (RFC 6749
  §4.1.3): the requesting `client_id` (Basic auth or body) must match the code.
- **Audience binding honors `mcp_server_path`.** The default token `aud` is now
  `base_url + mcp_server_path`, matching the published protected-resource
  metadata (previously hard-coded to `/mcp`, breaking RFC 8707 on custom paths).
- **Audience matching is exact**, no longer a string prefix (which let
  `https://api.example.com.evil.com` match `https://api.example.com`).
- HTTPS is now enforced on `register`, `revoke`, `introspect`, and `userinfo`
  (in addition to `authorize`/`token`), except in dev/test/local.

### Added
- **`Mcp::Auth::ProtectedResource`** controller concern — validates the incoming
  Bearer token on your MCP endpoint, exposes the principal via
  `Mcp::Auth::ControllerHelpers` (`mcp_user_id`, `mcp_scope`, …), and answers
  401 with the RFC 9728 `WWW-Authenticate: Bearer … resource_metadata="…"`
  header the MCP spec requires. Includes `require_mcp_scope!` for per-action
  scope enforcement.
- **OpenID Connect id_token issuance** — when the `openid` scope is granted, the
  token response includes an `id_token` (with `email`/`profile` claims gated by
  scope), making the advertised OIDC discovery real.
- **Signing-key rotation** — `token_signing_additional_public_keys` accepts extra
  public keys that are honored for verification and published in JWKS, so a key
  roll doesn't invalidate outstanding tokens. `TokenService.reset_signing_keys!`
  clears the in-process key cache.
- Refresh grant supports **scope narrowing** (RFC 6749 §6) and the wired-up
  `current_user_method` config option.
- Dynamic client registration now validates redirect URIs (RFC 7591/8252),
  rejecting empty sets and dangerous schemes (`javascript:`/`data:`).

### Changed
- Refresh-token rotation and authorization-code consumption now happen *before*
  new tokens are minted, so a replayed code/refresh token can't double-issue.
- `store_access_token` failures now propagate instead of silently handing the
  client an unrevocable token.
- `none` removed from advertised revocation/introspection auth methods (those
  endpoints require client authentication).
- Migration template for `mcp_auth_oauth_clients` uses a portable `string`
  primary key instead of Postgres-only `uuid`/`gen_random_uuid()`.

### Migration

Mostly drop-in. Two things to check:
1. Ensure all OAuth clients have their `redirect_uris` registered — the
   authorization endpoint now enforces them.
2. To protect your MCP endpoint, include the new concern:
   ```ruby
   class McpController < ApplicationController
     include Mcp::Auth::ProtectedResource
     before_action :authenticate_mcp_token!
   end
   ```

## [0.3.0] - 2026-05-25

### Added
- **Asymmetric JWT signing** — `Mcp::Auth.configure` now accepts
  `token_signing_algorithm` (`HS256` / `RS256` / `ES256`),
  `token_signing_private_key` (PEM string or `OpenSSL::PKey`),
  `token_signing_public_key` (optional — derived from the private key when
  omitted), and `token_signing_kid` (optional explicit JWK key id;
  auto-derived via JWT::JWK thumbprint when omitted).
- **JWKS publication** — `/.well-known/jwks.json` now returns the active
  public key as a JWK when an asymmetric algorithm is configured. HMAC
  keys are never exposed; HS256 keeps returning an empty key set.
- JWT headers now include `kid` for asymmetric algorithms, letting clients
  pick the right verification key across rotations.
- `id_token_signing_alg_values_supported` in OIDC discovery metadata now
  reflects the configured algorithm instead of being hard-coded to HS256.
- 18 new examples covering signing under each algorithm, JWKS shape, kid
  override, and configuration validation.

### Changed
- Default signing algorithm remains `HS256` — existing setups using
  `oauth_secret` keep working without code changes.
- `TokenService` internals refactored so encode/decode pick the right key
  for the configured algorithm; HMAC and asymmetric flows share one path.

### Migration

To switch to asymmetric signing in your host app:

```ruby
# config/initializers/mcp_auth.rb
Mcp::Auth.configure do |c|
  c.token_signing_algorithm  = 'RS256'                                # or 'ES256'
  c.token_signing_private_key = ENV.fetch('MCP_TOKEN_PRIVATE_KEY')    # PEM
  # c.token_signing_public_key  = ENV['MCP_TOKEN_PUBLIC_KEY']         # optional
  # c.token_signing_kid          = 'main-2026-05'                     # optional
end
```

Generate the key once (RSA 2048 or EC P-256), store the private half in
your secrets manager / Rails credentials, and let the JWKS endpoint
serve the public half to resource servers.

Existing access tokens issued under `HS256` will no longer validate
after the switch — plan a brief re-auth window for active clients, or
keep `HS256` until refresh tokens cycle out.

## [0.2.0] - 2026-05-25

### Added
- **RFC 9207** — `iss` parameter on authorization-error redirects (success
  redirects already included it). Becomes a MUST in the MCP 2026-07-28
  spec release candidate.
- **RFC 7009** — `POST /oauth/revoke` now requires client authentication
  (HTTP Basic or form body) and only revokes tokens owned by the
  authenticated client. Honors the optional `token_type_hint` parameter.
- **RFC 7662** — `POST /oauth/introspect` now requires client
  authentication. Tokens not owned by the authenticated client are
  reported as `{active: false}` to prevent token-scanning attacks.
- Spec coverage for `revoke` + `introspect` endpoints (13 examples).

### Changed
- `revoke` and `introspect` now return HTTP 401 with
  `{error: "invalid_client"}` when client authentication fails. Previously
  they accepted unauthenticated requests. **This is a breaking change for
  callers that did not authenticate** — update clients to send credentials
  via HTTP Basic auth (preferred) or `client_id` + `client_secret` form
  params.
- `render_error` now accepts a `status:` keyword argument
  (default `:bad_request`).

## [0.1.0] - 2025-01-10

### Added
- Initial release of MCP Auth gem
- OAuth 2.1 authorization flow implementation
- PKCE support (RFC 7636) with S256 method requirement
- Dynamic Client Registration (RFC 7591)
- Token Revocation (RFC 7009)
- Token Introspection (RFC 7662)
- Authorization Server Metadata (RFC 8414)
- Protected Resource Metadata (RFC 9728)
- Resource Indicators support (RFC 8707) for token audience binding
- OpenID Connect Discovery support
- Automatic middleware for protecting `/mcp/*` routes
- JWT access tokens with proper audience validation
- Refresh token rotation for enhanced security
- Database-backed token storage for revocation support
- Customizable user data fetching
- Rake tasks for token cleanup and management
- Beautiful consent screen UI
- Comprehensive test suite
- Full documentation and examples

### Security
- HTTPS enforcement for production environments
- Secure token generation using SecureRandom
- Constant-time string comparison for PKCE validation
- Short-lived access tokens (1 hour default)
- Automatic refresh token rotation
- Token audience validation to prevent confused deputy attacks
- WWW-Authenticate header with resource metadata on 401 responses

[Unreleased]: https://github.com/SerhiiBorozenets/mcp-auth/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/SerhiiBorozenets/mcp-auth/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/SerhiiBorozenets/mcp-auth/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/SerhiiBorozenets/mcp-auth/releases/tag/v0.1.0