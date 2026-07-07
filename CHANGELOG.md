# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-07-03

Second security-hardening round (audit follow-ups), delivered in two phases.
Phase 1 — code-level fixes, no migration:

### Security (breaking where noted)
- **Authorization-code TTL was 30 HOURS, not 30 minutes.** The lifetime (a value
  in seconds, e.g. `1800`) was applied with `.minutes`. Now applied as seconds,
  and read from the single canonical config source so configured and default
  deployments agree. **Breaking:** codes now expire in ~30 min as intended.
- **Issuer / audience / discovery URLs are pinned to the configured origin.**
  `iss`, `aud`, the canonical resource, and all discovery/JWKS URLs derive from
  `authorization_server_url` when set, instead of the raw request Host — closing
  a Host/`X-Forwarded-Host` header-injection vector. **When unset**, the value
  still falls back to the request origin, so the host app MUST restrict permitted
  hosts via Rails `config.hosts`.
- **JWT validation hardened.** Access tokens now carry a `token_use` claim and an
  id_token can no longer be replayed as an access token; decode enforces
  `required_claims` (`iss`/`aud`/`sub`/`exp`) with a bounded clock-skew leeway;
  a missing audience is no longer silently accepted.
- **Confidential-client auth at the token endpoint.** A `client_secret` presented
  on a code/refresh request is now verified (constant-time); an invalid secret is
  rejected. (Full *requirement* of a secret for confidential clients lands with
  the `token_endpoint_auth_method` column in Phase 2.)
- **Refresh-token rotation is atomic.** Rotation is gated on a conditional delete,
  so two concurrent redemptions of one refresh token can no longer each mint a
  new token family.
- **Consent enforces least privilege.** A client can no longer be granted a scope
  it never requested; approved scopes are intersected with the requested set.
- **`oauth_secret` must be set in production.** The gem no longer silently signs
  tokens with `Rails.application.secret_key_base` in production (key separation);
  a missing secret now raises. Dev/test still fall back.

Phase 2 — secrets hashed at rest (adds a migration) + medium fixes:

### Security
- **All persisted secrets are now hashed at rest.** Access-token JWTs, refresh
  tokens, authorization codes, and client secrets are stored as SHA-256 digests
  (prefixed `sha256$`); a database leak no longer yields usable credentials. The
  plaintext client secret is returned exactly once at registration; tokens/codes
  are returned once to the client and matched by digest thereafter.
- **Dynamic Client Registration rejects unsupported grant/response types**
  (RFC 7591 §2) instead of storing arbitrary metadata.
- **Refresh-token reuse detection** (OAuth 2.1 §4.14.2). Rotation now marks the
  presented token revoked (grouped by a `family_id`) instead of deleting it, so
  an authenticated client replaying an already-rotated token is detected as theft
  and the **entire family is revoked — both the refresh tokens and the access
  tokens already issued to that principal** (immediate cut-off, not left valid
  until expiry). Client authentication is checked *before* this reaction, so an
  unauthenticated replay can't trigger family revocation. Rotation is atomic
  (only the request that flips `revoked_at` wins), superseding the delete-based
  race fix. The migration backfills a `family_id` for pre-existing tokens so
  reuse detection covers them too. A configurable **rotation grace period**
  (`refresh_token_reuse_grace_period`, default 10s) treats a rotated token
  replayed moments later as a benign concurrent-refresh race (rejected softly,
  family kept) rather than theft, so well-behaved MCP clients that fire several
  refreshes when the access token expires aren't logged out.
- **Access tokens carry a unique `jti`** (RFC 7519) so two tokens issued in the
  same second for the same principal/scope don't collide on the unique token
  index (which previously raised on rapid/concurrent refreshes).
- **Confidential-client authentication is now enforced.** Clients carry a
  `token_endpoint_auth_method`; a confidential client (`client_secret_basic` /
  `client_secret_post`) MUST present a valid secret at the token endpoint, while
  a public client (`none`, the default) relies on PKCE. **Existing clients
  default to `none`, so nothing that worked before starts requiring a secret** —
  a client opts into confidential auth explicitly at registration.

### Fixed
- Re-enabled a dead spec file (`spec/services/authorization_service.rb` →
  `…_spec.rb`) that RSpec never ran, restoring ~130 lines of coverage.
- `mcp_auth:revoke_*` rake tasks now delete across the three tables inside a
  transaction (no partial revocation on mid-way failure).

### Added
- **Pending-migration guard.** If the gem is upgraded but its migrations haven't
  run, mcp-auth now says so instead of failing with a cryptic `unknown attribute`:
  a clear warning is logged at boot, the OAuth endpoints return an actionable
  `server_error` ("run a pending migration"), and `rake mcp_auth:doctor` reports
  schema drift and exits non-zero. Fully guarded — never breaks boot, CI, or
  `db:*` tasks when the database is absent or unmigrated.
- **`rails generate mcp:auth:upgrade`** — copies only pending migrations for an
  existing install (no initializer/view overwrite prompts, unlike re-running the
  full install generator).
- **`config.secret_dual_read`** (default `true`) — transitional dual-read: a
  presented secret/token/code is matched against both its digest and any legacy
  plaintext row not yet backfilled, so the upgrade is safe under rolling deploys
  and safe to roll back. Set to `false` once every row is hashed to harden.

### Upgrade

Two migrations: a data backfill that hashes existing secrets **in place** (no
schema change), and an additive column migration (`token_endpoint_auth_method`
on clients; `family_id` + `revoked_at` on refresh tokens):

```bash
bundle update mcp-auth
rails generate mcp:auth:upgrade   # copies both pending migrations
rails db:migrate
```

The backfill hashes the plaintext already present in each column, so **existing
clients and tokens keep working without re-registration** — the client still
presents its original value and the gem re-hashes it to match. Existing clients
get `token_endpoint_auth_method = 'none'` (public), so none of them suddenly
requires a secret. With `secret_dual_read` on (default) the deploy is safe for
rolling releases and rollback; once every row is hashed and old code is gone,
set `config.secret_dual_read = false` to reject plaintext-form matches. The
hashing backfill is idempotent and irreversible.

## [0.5.0] - 2026-06-15

Security-hardening release. Closes five OAuth 2.1 / MCP authorization
vulnerabilities found in an adversarial audit of the authorization server and
protected-resource layer. Each fix ships with an RSpec test that fails before
and passes after.

### Security (breaking where noted)
- **Consent can no longer be bypassed.** `GET /oauth/authorize` previously issued
  an authorization code immediately when `approved=true` was present on the
  request URL — a GET, so not even CSRF-protected — skipping the consent screen
  entirely. The authorization endpoint now always renders consent; a code is
  granted only via the CSRF-protected `POST /oauth/approve`. **Breaking:** clients
  that appended `approved=true` to the authorize URL to auto-approve must go
  through the consent/approve step.
- **Refresh tokens are bound to the issuing client** (OAuth 2.1 §4.3.1). The
  refresh grant now rejects redemption unless the requesting `client_id` (Basic
  auth or body) matches the client the token was issued to, and does not rotate
  the token on a failed check. **Breaking:** a refresh request must include the
  matching `client_id` — the documented flow already does.
- **Authorization codes are consumed atomically** (OAuth 2.1 §4.1.2). Consumption
  now deletes the code in a single atomic operation and the token grant aborts
  unless it won that deletion, eliminating a race that could mint two token sets
  from one code.
- **Resource indicators are validated** (RFC 8707 / MCP authorization spec).
  `authorize` and both token grants reject any `resource` that does not identify
  this server (`invalid_target`), so the server can no longer mint a token whose
  audience is some other — possibly attacker-controlled — resource. **Breaking:**
  requests carrying a `resource` for a different host/path are rejected.
- **`api_key_secret` is no longer embedded in access tokens.** A bearer JWT is
  decodable by anyone holding it and is stored at rest, so only the non-sensitive
  `api_key_id` is now included; resolve the matching secret server-side from that
  id. Any `api_key_secret` returned by `fetch_user_data` is ignored.

### Changed
- README and the generated initializer document that `fetch_user_data` must not
  return secrets (they are ignored and never written into the token).

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
- Opt-in resource-server protection for MCP routes via the
  `Mcp::Auth::ProtectedResource` concern
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

[Unreleased]: https://github.com/SerhiiBorozenets/mcp-auth/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/SerhiiBorozenets/mcp-auth/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/SerhiiBorozenets/mcp-auth/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/SerhiiBorozenets/mcp-auth/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/SerhiiBorozenets/mcp-auth/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/SerhiiBorozenets/mcp-auth/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/SerhiiBorozenets/mcp-auth/releases/tag/v0.1.0